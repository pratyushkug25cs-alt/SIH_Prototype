'use strict';
const router = require('express').Router();
const db = require('../db');
const audit = require('../audit');
const svc = require('../services/students');
const { sha256, randomCode } = require('../crypto');
const config = require('../config');
const { auth, requireRole } = require('../middleware');

router.use(auth, requireRole('student'));

function expireOld() {
  db.prepare("UPDATE consents SET status = 'expired' WHERE status = 'approved' AND expires_at < ?").run(new Date().toISOString());
}
function present(c) {
  const v = db.prepare('SELECT org, email FROM users WHERE id = ?').get(c.verifier_id);
  return { id: c.id, requester: v.org || v.email, purpose: c.purpose, scopes: JSON.parse(c.scopes), status: c.status, createdAt: c.created_at, expiresAt: c.expires_at };
}
function mine(req, res) {
  const c = db.prepare('SELECT * FROM consents WHERE id = ? AND student_id = ?').get(Number(req.params.id), req.user.student_id);
  if (!c) { res.status(404).json({ error: 'Request not found.' }); return null; }
  return c;
}

// GET /api/me
router.get('/', (req, res) => {
  const s = svc.byId(req.user.student_id);
  const inst = svc.institution(s.institution_id);
  res.json({ student: svc.present(s), institution: { name: inst.name, aicteId: inst.aicte_id } });
});

// GET /api/me/consents
router.get('/consents', (req, res) => {
  expireOld();
  const rows = db.prepare('SELECT * FROM consents WHERE student_id = ? ORDER BY id DESC').all(req.user.student_id);
  res.json({ consents: rows.map(present) });
});

// POST /api/me/consents/:id/approve  -> returns the one-time code, shown only once
router.post('/consents/:id/approve', (req, res) => {
  expireOld();
  const c = mine(req, res); if (!c) return;
  if (c.status !== 'pending') return res.status(409).json({ error: 'This request is no longer waiting.' });
  const code = randomCode();
  const expires = new Date(Date.now() + config.codeTtlMin * 60000).toISOString();
  db.prepare("UPDATE consents SET status = 'approved', code_hash = ?, expires_at = ?, attempts = 0 WHERE id = ?").run(sha256(code + ':' + c.id), expires, c.id);
  audit.log('Student ' + req.user.email, 'Consent approved', c.student_id, 'request ' + c.id);
  res.json({ code, expiresAt: expires, note: 'Share this code only with the verifier. It is not stored in readable form.' });
});

for (const [name, status, label] of [['deny', 'denied', 'Consent declined'], ['revoke', 'revoked', 'Consent revoked']]) {
  router.post(`/consents/:id/${name}`, (req, res) => {
    const c = mine(req, res); if (!c) return;
    const allowed = name === 'deny' ? ['pending'] : ['approved'];
    if (!allowed.includes(c.status)) return res.status(409).json({ error: 'This request cannot be changed now.' });
    db.prepare('UPDATE consents SET status = ?, code_hash = NULL WHERE id = ?').run(status, c.id);
    audit.log('Student ' + req.user.email, label, c.student_id, 'request ' + c.id);
    res.json({ status });
  });
}

// GET /api/me/access-history
router.get('/access-history', (req, res) => {
  const rows = db.prepare('SELECT ts, actor, action, detail FROM audit_log WHERE student_id = ? ORDER BY id DESC LIMIT 100').all(req.user.student_id);
  res.json({ entries: rows });
});

module.exports = router;
