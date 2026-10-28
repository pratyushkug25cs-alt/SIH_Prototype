'use strict';
const router = require('express').Router();
const db = require('../db');
const { checkPassword } = require('../crypto');
const { issueToken } = require('../middleware');
const audit = require('../audit');

// POST /api/auth/login  { email, password }
router.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase());
  if (!user || !checkPassword(String(password || ''), user.pass_hash)) {
    audit.log(String(email || 'unknown'), 'Failed login', null, '');
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  audit.log(user.email, 'Signed in', user.student_id, user.role);
  res.json({ token: issueToken(user), role: user.role, org: user.org || null });
});

module.exports = router;
