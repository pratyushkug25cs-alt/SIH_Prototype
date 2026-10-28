'use strict';
const db = require('./db');
const { sha256, canonical } = require('./crypto');

const GENESIS = 'GENESIS';

/**
 * Append-only, hash-chained audit trail. Each row's hash covers the previous row's hash,
 * so editing or deleting an old row breaks every row after it.
 */
const insert = db.prepare(
  'INSERT INTO audit_log (ts, actor, action, student_id, detail, prev_hash, row_hash) VALUES (?,?,?,?,?,?,?)'
);
const lastRow = db.prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1');

const write = db.transaction((actor, action, studentId, detail) => {
  const prev = (lastRow.get() || {}).row_hash || GENESIS;
  const ts = new Date().toISOString();
  const rowHash = sha256(prev + canonical({ ts, actor, action, studentId: studentId || null, detail: detail || '' }));
  insert.run(ts, actor, action, studentId || null, detail || '', prev, rowHash);
});

function log(actor, action, studentId, detail) {
  write(actor, action, studentId, detail);
}

/** Recompute the whole chain. Returns { ok, brokenAt }. */
function verifyChain() {
  let prev = GENESIS;
  for (const r of db.prepare('SELECT * FROM audit_log ORDER BY id').iterate()) {
    const expect = sha256(prev + canonical({ ts: r.ts, actor: r.actor, action: r.action, studentId: r.student_id || null, detail: r.detail }));
    if (r.prev_hash !== prev || r.row_hash !== expect) return { ok: false, brokenAt: r.id };
    prev = r.row_hash;
  }
  return { ok: true, brokenAt: null };
}

module.exports = { log, verifyChain };
