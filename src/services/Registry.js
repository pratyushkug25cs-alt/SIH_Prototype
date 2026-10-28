'use strict';
const db = require('../db');

/**
 * Adapter for the APAAR registry / DigiLocker identity lookup.
 * This MVP reads a local table. A real build replaces lookup() with the official API client
 * (obtained through partner onboarding) and keeps the same return shape, so nothing else changes.
 */
const find = db.prepare('SELECT name, dob FROM registry_mock WHERE apaar_id = ?');

function lookup(apaarId) {
  return find.get(apaarId) || null;
}

const norm = s => String(s || '').toLowerCase().replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();

/** Compare a student record with the registry identity. */
function compare(student, reg) {
  return { name: norm(student.name) === norm(reg.name), dob: student.dob === reg.dob };
}

module.exports = { lookup, compare };
