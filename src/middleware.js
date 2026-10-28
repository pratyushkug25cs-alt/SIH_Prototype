'use strict';
const jwt = require('jsonwebtoken');
const config = require('./config');
const db = require('./db');

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, { expiresIn: '8h' });
}

/** Reads the bearer token and loads the user. */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Sign in first.' });
  try {
    const t = jwt.verify(h.slice(7), config.jwtSecret);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(t.sub);
    if (!user) return res.status(401).json({ error: 'Unknown user.' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Sign in again.' });
  }
}

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Your role cannot do this.' });

/** Wrap async handlers so errors reach the error middleware. */
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { issueToken, auth, requireRole, wrap };
