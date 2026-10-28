'use strict';
const router = require('express').Router();
const db = require('../db');
const audit = require('../audit');
const svc = require('../services/students');
const config = require('../config');
const { sha256 } = require('../crypto');
const { auth, requireRole } = require('../middleware');

router.use(auth, requireRole('verifier'));

const SCOPES = ['identity', 'program', 'marks'];
const MESSAGES = {
  ok: 'The institution attested this record and the integrity check passed.',
  tampered: 'The record was changed after the institution attested it. No data is released.',
  flagged: 'The institution found a mismatch with the APAAR registry. No data is released.',
  pending: 'The institution has not attested this record. No data is released.'
};
const who = req => (req.user.org || req.user.email);

// POST /api/verify/requests  { apaarId, purpose, scopes: ["identity","program","marks"] }
router.post('/requests', (req, res) => {
  const { apaarId, purpose, scopes } = req.body || {};
  const id = svc.digits(apaarId);
  if (!svc.isApaar(id)) return res.status(400).json({ error: 'An APAAR ID has 12 digits.' });
  if (!purpose || !Array.isArray(scopes) || !scopes.length || !scopes.every(s => SCOPES.includes(s)))
    return res.status(400).json({ error: 'Give a purpose and at least one scope: identity, program or marks.' });
  const s = svc.byApaar(id);
  if (!s) return res.status(404).json({ error: 'No record at an AICTE-approved institution is linked to this ID.' });
  const r = db.prepare("INSERT INTO consents (student_id, verifier_id, purpose, scopes, status, created_at) VALUES (?,?,?,?, 'pending', ?)")
    .run(s.id, req.user.id, String(purpose).slice(0, 120), JSON.stringify(scopes), new Date().toISOString());
  audit.log(who(req), 'Verification requested', s.id, purpose);
  res.status(201).json({ requestId: r.lastInsertRowid, status: 'pending', note: 'Waiting for the student to approve and share a code.' });
});

// GET /api/verify/requests
router.get('/requests', (req, res) => {
  db.prepare("UPDATE consents SET status = 'expired' WHERE status = 'approved' AND expires_at < ?").run(new Date().toISOString());
  const rows = db.prepare('SELECT id, purpose, scopes, status, created_at, expires_at FROM consents WHERE verifier_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ requests: rows.map(r => ({ id: r.id, purpose: r.purpose, scopes: JSON.parse(r.scopes), status: r.status, createdAt: r.created_at, expiresAt: r.expires_at })) });
});

// POST /api/verify/requests/:id/redeem  { code }
router.post('/requests/:id/redeem', (req, res) => {
  const c = db.prepare('SELECT * FROM consents WHERE id = ? AND verifier_id = ?').get(Number(req.params.id), req.user.id);
  if (!c) return res.status(404).json({ error: 'Request not found.' });
  if (c.status !== 'approved') return res.status(409).json({ error: 'This request is ' + c.status + '. A code works only once, after the student approves.' });
  if (new Date(c.expires_at) < new Date()) {
    db.prepare("UPDATE consents SET status = 'expired' WHERE id = ?").run(c.id);
    return res.status(410).json({ error: 'This code has expired. Send a new request.' });
  }
  const code = String((req.body || {}).code || '').replace(/\D/g, '');
  if (sha256(code + ':' + c.id) !== c.code_hash) {
    const attempts = c.attempts + 1;
    const locked = attempts >= config.maxCodeAttempts;
    db.prepare('UPDATE consents SET attempts = ?, status = ? WHERE id = ?').run(attempts, locked ? 'locked' : 'approved', c.id);
    audit.log(who(req), locked ? 'Code locked' : 'Wrong code', c.student_id, 'request ' + c.id);
    return res.status(locked ? 423 : 403).json({ error: locked ? 'Too many wrong codes. This request is locked.' : `Wrong code. ${config.maxCodeAttempts - attempts} attempt(s) left.` });
  }
  const s = svc.byId(c.student_id);
  const ev = svc.evaluate(s);
  db.prepare("UPDATE consents SET status = 'used', code_hash = NULL WHERE id = ?").run(c.id);
  audit.log(who(req), 'Verification completed', s.id, ev.verdict);
  const body = { verdict: ev.verdict, message: MESSAGES[ev.verdict], checkedAt: new Date().toISOString() };
  if (ev.verdict === 'ok') {
    body.data = svc.scopedData(s, JSON.parse(c.scopes));
    body.attestation = { version: ev.attestation.version, hash: ev.attestation.hash, signedAt: ev.attestation.created_at, institution: ev.institution.name, aicteId: ev.institution.aicte_id };
  } else if (ev.verdict === 'tampered') {
    body.attestation = { hashSealed: ev.attestation.hash, hashNow: ev.hashNow };
  }
  res.json(body);
});

module.exports = router;
