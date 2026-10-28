'use strict';
const Database = require('better-sqlite3');
const config = require('./config');

const db = new Database(config.dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS institutions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    short_name  TEXT    NOT NULL,
    aicte_id    TEXT    NOT NULL UNIQUE,
    public_key  TEXT    NOT NULL,
    private_key TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,
    pass_hash       TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK(role IN ('registrar','student','verifier')),
    institution_id  INTEGER REFERENCES institutions(id),
    student_id      INTEGER,
    org             TEXT
  );

  CREATE TABLE IF NOT EXISTS students (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    institution_id  INTEGER NOT NULL REFERENCES institutions(id),
    enrol_no        TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    dob             TEXT    NOT NULL,
    program         TEXT    NOT NULL,
    branch          TEXT    NOT NULL,
    adm_year        INTEGER NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active',
    state           TEXT    NOT NULL DEFAULT 'unlinked',
    apaar_enc       TEXT,
    apaar_idx       TEXT,
    sgpa            TEXT    NOT NULL DEFAULT '[]',
    credits         INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS attestations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id  INTEGER NOT NULL REFERENCES students(id),
    version     INTEGER NOT NULL,
    payload     TEXT    NOT NULL,
    hash        TEXT    NOT NULL,
    signature   TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    created_by  INTEGER NOT NULL REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS consents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id  INTEGER NOT NULL REFERENCES students(id),
    verifier_id INTEGER NOT NULL REFERENCES users(id),
    purpose     TEXT    NOT NULL,
    scopes      TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending',
    code_hash   TEXT,
    expires_at  TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,
    actor     TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    student_id INTEGER,
    detail    TEXT,
    prev_hash TEXT    NOT NULL,
    row_hash  TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS registry_mock (
    apaar_id TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    dob      TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_students_apaar   ON students(apaar_idx);
  CREATE INDEX IF NOT EXISTS idx_students_inst    ON students(institution_id);
  CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
  CREATE INDEX IF NOT EXISTS idx_consents_student ON consents(student_id);
  CREATE INDEX IF NOT EXISTS idx_consents_verifier ON consents(verifier_id);
  CREATE INDEX IF NOT EXISTS idx_audit_student    ON audit_log(student_id);
`);

module.exports = db;
