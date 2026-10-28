'use strict';
const router = require('express').Router();
const db = require('../db');
const audit = require('../audit');
const svc = require('../services/students');
const { auth, requireRole } = require('../middleware');

router.use(auth, requireRole('registrar'));

/** Load a student and make sure it belongs to the registrar's own institution. */
function own(req, res) {
  const s = svc.byId(Number(req.params.id));
  if (!s || s.institution_id !== req.user.institution_id) {
    res.status(404).json({ error: 'Student not found.' });
    return null;
  }
  return s;
}
const actor = req => 'Registrar ' + req.user.email;

// GET /api/students?state=pending&q=ananya
router.get('/', (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  let rows = db.prepare('SELECT * FROM students WHERE institution_id = ? ORDER BY id').all(req.user.institution_id).map(svc.present);
  if (req.query.state) rows = rows.filter(s => s.state === req.query.state);
  if (q) rows = rows.filter(s => (s.name + ' ' + s.enrolNo + ' ' + (s.apaarId || '')).toLowerCase().includes(q));
  res.json({ count: rows.length, students: rows });
});

// POST /api/students  { name, dob, program, branch, admYear, apaarId? }
router.post('/', (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.dob || '')) return res.status(400).json({ error: 'dob must be YYYY-MM-DD.' });
  if (!svc.DURATION[b.program]) return res.status(400).json({ error: 'program must be B.Tech or MBA.' });
  if (!svc.BRANCHES[b.branch] || (b.program === 'MBA') !== (b.branch === 'FIN')) return res.status(400).json({ error: 'branch does not fit the program.' });
  const adm = Number(b.admYear);
  if (!(adm >= 2022 && adm <= 2026)) return res.status(400).json({ error: 'admYear must be between 2022 and 2026.' });
  const s = svc.create(req.user.institution_id, { name, dob: b.dob, program: b.program, branch: b.branch, admYear: adm });
  audit.log(actor(req), 'Student added', s.id, s.enrol_no);
  let linked = null;
  if (b.apaarId) {
    linked = svc.link(s, b.apaarId);
    if (!linked.ok) return res.status(422).json({ error: linked.error, student: svc.present(svc.byId(s.id)) });
    audit.log(actor(req), 'APAAR ID linked', s.id, linked.state);
  }
  res.status(201).json({ student: svc.present(svc.byId(s.id)) });
});

// POST /api/students/:id/link  { apaarId }
router.post('/:id/link', (req, res) => {
  const s = own(req, res); if (!s) return;
  const r = svc.link(s, (req.body || {}).apaarId);
  if (!r.ok) return res.status(422).json({ error: r.error });
  audit.log(actor(req), 'APAAR ID linked', s.id, r.state);
  res.json({ state: r.state, match: r.match, student: svc.present(svc.byId(s.id)) });
});

// POST /api/students/:id/attest
router.post('/:id/attest', (req, res) => {
  const s = own(req, res); if (!s) return;
  if (s.state === 'flagged') return res.status(409).json({ error: 'Resolve the identity mismatch before attesting.' });
  if (s.state === 'unlinked') return res.status(409).json({ error: 'Link an APAAR ID first.' });
  const r = svc.attest(s, req.user.id);
  audit.log(actor(req), 'Record attested', s.id, 'version ' + r.version);
  res.json({ version: r.version, hash: r.hash });
});

// POST /api/students/:id/results  { semester, sgpa }  (changes the record; attest again afterwards)
router.post('/:id/results', (req, res) => {
  const s = own(req, res); if (!s) return;
  const { semester, sgpa } = req.body || {};
  const sem = Number(semester), v = Number(sgpa);
  if (!(sem >= 1 && sem <= svc.DURATION[s.program] * 2) || !(v >= 0 && v <= 10)) return res.status(400).json({ error: 'Invalid semester or SGPA.' });
  const list = JSON.parse(s.sgpa);
  const before = list[sem - 1];
  list[sem - 1] = Math.round(v * 100) / 100;
  db.prepare('UPDATE students SET sgpa = ?, credits = ? WHERE id = ?').run(JSON.stringify(list), list.filter(x => x != null).length * 20, s.id);
  audit.log(actor(req), 'Result changed', s.id, `semester ${sem}: ${before == null ? 'none' : before} to ${list[sem - 1]}`);
  res.json({ student: svc.present(svc.byId(s.id)), note: 'Attest again so verifiers see the new result.' });
});

// GET /api/students/audit/log  (this institution's students only)
router.get('/audit/log', (req, res) => {
  const rows = db.prepare(`SELECT a.* FROM audit_log a LEFT JOIN students s ON s.id = a.student_id
    WHERE s.institution_id = ? OR a.actor LIKE ? ORDER BY a.id DESC LIMIT 200`).all(req.user.institution_id, '%' + req.user.email + '%');
  res.json({ entries: rows.map(r => ({ id: r.id, ts: r.ts, actor: r.actor, action: r.action, studentId: r.student_id, detail: r.detail })) });
});

// GET /api/students/audit/verify  (is the hash chain intact?)
router.get('/audit/verify', (req, res) => res.json(audit.verifyChain()));

module.exports = router;
