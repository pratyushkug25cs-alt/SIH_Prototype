'use strict';
const db = require('../db');
const { canonical, sha256, sign, verifySignature, encryptId, decryptId, blindIndex } = require('../crypto');
const registry = require('./Registry');

const DURATION = { 'B.Tech': 4, MBA: 2 };
const BRANCHES = { CSE: 'Computer Science and Engineering', ECE: 'Electronics and Communication Engineering', ME: 'Mechanical Engineering', CE: 'Civil Engineering', EE: 'Electrical Engineering', FIN: 'Finance' };
const isApaar = v => /^\d{12}$/.test(String(v || ''));
const digits = v => String(v || '').replace(/\D/g, '');

const institution = id => db.prepare('SELECT * FROM institutions WHERE id = ?').get(id);
const byId = id => db.prepare('SELECT * FROM students WHERE id = ?').get(id);
const byApaar = id => db.prepare('SELECT * FROM students WHERE apaar_idx = ?').get(blindIndex(id));

/** Public view of a record for staff and the student themself. */
function present(s) {
  const sgpa = JSON.parse(s.sgpa);
  const filled = sgpa.filter(x => x != null);
  return {
    id: s.id, enrolNo: s.enrol_no, name: s.name, dob: s.dob, program: s.program, branch: s.branch,
    admYear: s.adm_year, status: s.status, state: s.state, apaarId: s.apaar_enc ? decryptId(s.apaar_enc) : null,
    sgpa, credits: s.credits,
    cgpa: filled.length ? Math.round(filled.reduce((a, b) => a + b, 0) / filled.length * 100) / 100 : null,
    creditsRequired: (DURATION[s.program] || 4) * 40
  };
}

/** The exact data that gets hashed and signed. */
function attestationPayload(s) {
  const inst = institution(s.institution_id);
  return {
    apaar: s.apaar_enc ? decryptId(s.apaar_enc) : null, name: s.name, dob: s.dob, aicte: inst.aicte_id,
    program: s.program, branch: s.branch, adm: s.adm_year, status: s.status,
    sgpa: JSON.parse(s.sgpa), credits: s.credits
  };
}

function create(institutionId, v) {
  const n = db.prepare('SELECT COUNT(*) c FROM students WHERE institution_id = ? AND branch = ?').get(institutionId, v.branch).c + 1;
  const inst = institution(institutionId);
  const prefix = inst.short_name.split(' ')[0].toUpperCase();
  const enrol = v.enrolNo || `${prefix}/${String(v.admYear).slice(2)}/${v.branch}/${String(n).padStart(3, '0')}`;
  const r = db.prepare('INSERT INTO students (institution_id, enrol_no, name, dob, program, branch, adm_year) VALUES (?,?,?,?,?,?,?)')
    .run(institutionId, enrol, v.name, v.dob, v.program, v.branch, v.admYear);
  return byId(r.lastInsertRowid);
}

/** Link an APAAR ID. Returns { ok, error?, state }. */
function link(student, rawId) {
  const id = digits(rawId);
  if (!isApaar(id)) return { ok: false, error: 'An APAAR ID has 12 digits.' };
  const reg = registry.lookup(id);
  if (!reg) return { ok: false, error: 'This ID is not in the APAAR registry.' };
  const other = byApaar(id);
  if (other && other.id !== student.id) return { ok: false, error: 'This ID is already linked to another record.' };
  const cmp = registry.compare(student, reg);
  const state = cmp.name && cmp.dob ? 'pending' : 'flagged';
  db.prepare('UPDATE students SET apaar_enc = ?, apaar_idx = ?, state = ?, status = status WHERE id = ?')
    .run(encryptId(id), blindIndex(id), state, student.id);
  return { ok: true, state, match: cmp };
}

/** Seal the current record: canonical payload, SHA-256 hash, Ed25519 signature, new version. */
const attest = db.transaction((student, userId) => {
  if (!student.apaar_enc) throw new Error('Link an APAAR ID before attesting.');
  const inst = institution(student.institution_id);
  const payload = canonical(attestationPayload(student));
  const hash = sha256(payload);
  const signature = sign(inst.private_key, hash);
  const version = (db.prepare('SELECT MAX(version) v FROM attestations WHERE student_id = ?').get(student.id).v || 0) + 1;
  db.prepare('INSERT INTO attestations (student_id, version, payload, hash, signature, created_at, created_by) VALUES (?,?,?,?,?,?,?)')
    .run(student.id, version, payload, hash, signature, new Date().toISOString(), userId);
  db.prepare("UPDATE students SET state = 'verified' WHERE id = ?").run(student.id);
  return { version, hash };
});

/**
 * Check a student's record before releasing anything.
 * verdict: ok | tampered | flagged | pending
 */
function evaluate(student) {
  if (student.state === 'flagged') return { verdict: 'flagged' };
  if (student.state !== 'verified') return { verdict: 'pending' };
  const att = db.prepare('SELECT * FROM attestations WHERE student_id = ? ORDER BY version DESC LIMIT 1').get(student.id);
  if (!att) return { verdict: 'pending' };
  const inst = institution(student.institution_id);
  const nowHash = sha256(canonical(attestationPayload(student)));
  const intact = nowHash === att.hash && verifySignature(inst.public_key, att.hash, att.signature);
  return { verdict: intact ? 'ok' : 'tampered', attestation: att, hashNow: nowHash, institution: inst };
}

/** Only the fields the student agreed to share. */
function scopedData(student, scopes) {
  const p = present(student), inst = institution(student.institution_id), out = {};
  if (scopes.includes('identity')) out.identity = { name: p.name, dob: p.dob };
  if (scopes.includes('program')) out.program = { institution: inst.name, aicteId: inst.aicte_id, program: p.program, branch: BRANCHES[p.branch] || p.branch, batch: p.admYear, status: p.status };
  if (scopes.includes('marks')) out.marks = { cgpa: p.cgpa, credits: p.credits, creditsRequired: p.creditsRequired, sgpa: p.sgpa };
  return out;
}

module.exports = { DURATION, BRANCHES, isApaar, digits, institution, byId, byApaar, present, create, link, attest, evaluate, scopedData };
