'use strict';
// Creates sample institutions, users, students and registry entries. Safe to run on an empty database.
const db = require('../src/db');
const { generateKeypair, hashPassword, encryptId, blindIndex } = require('../src/crypto');
const svc = require('../src/services/students');
const audit = require('../src/audit');

if (db.prepare('SELECT COUNT(*) c FROM institutions').get().c > 0) {
  console.log('Database already has data. Delete the .db file to reseed.');
  process.exit(0);
}

const PW = 'Passw0rd!demo';
const addInst = (name, short, aicte) => {
  const k = generateKeypair();
  return db.prepare('INSERT INTO institutions (name, short_name, aicte_id, public_key, private_key) VALUES (?,?,?,?,?)')
    .run(name, short, aicte, k.publicKey, k.privateKey).lastInsertRowid;
};
const addUser = (email, role, extra = {}) =>
  db.prepare('INSERT INTO users (email, pass_hash, role, institution_id, student_id, org) VALUES (?,?,?,?,?,?)')
    .run(email, hashPassword(PW), role, extra.institutionId || null, extra.studentId || null, extra.org || null).lastInsertRowid;

const dit = addInst('Demo Institute of Technology', 'DIT Patna', '1-9000011');
const adminId = addUser('registrar@dit.example', 'registrar', { institutionId: dit });
addUser('hiring@meridian.example', 'verifier', { org: 'Meridian Hiring Desk' });

// Registry entries (fictional). The third one has a different name format on purpose.
const registry = [
  ['482177305516', 'Ananya Kumari', '2005-08-12'],
  ['731905224081', 'Rohan Prasad', '2005-02-27'],
  ['905513380247', 'Mohd. Faiz', '2005-11-03'],
  ['316640192875', 'Ishita Rani', '2008-03-14']
];
const addReg = db.prepare('INSERT INTO registry_mock (apaar_id, name, dob) VALUES (?,?,?)');
registry.forEach(r => addReg.run(...r));

function student(name, dob, program, branch, admYear, apaar, sgpa) {
  const s = svc.create(dit, { name, dob, program, branch, admYear });
  if (sgpa) db.prepare('UPDATE students SET sgpa = ?, credits = ? WHERE id = ?').run(JSON.stringify(sgpa), sgpa.length * 20, s.id);
  if (apaar) svc.link(svc.byId(s.id), apaar);
  return svc.byId(s.id);
}

const ananya = student('Ananya Kumari', '2005-08-12', 'B.Tech', 'CSE', 2023, '482177305516', [8.1, 8.4, 7.9, 8.6, 8.8, 9.0]);
const rohan = student('Rohan Prasad', '2005-02-27', 'B.Tech', 'CSE', 2023, '731905224081', [7.2, 7.5, 7.1, 7.8, 8.0, 7.7]);
student('Mohammad Faiz', '2005-11-03', 'B.Tech', 'ME', 2023, '905513380247', [6.9, 7.0, 7.3, 7.1, 7.4, 7.6]); // flagged
student('Shreya Das', '2008-02-21', 'B.Tech', 'EE', 2026, null, null);                                          // unlinked

svc.attest(svc.byId(ananya.id), adminId);
svc.attest(svc.byId(rohan.id), adminId);

addUser('ananya@student.example', 'student', { studentId: ananya.id });
addUser('rohan@student.example', 'student', { studentId: rohan.id });

audit.log('system', 'Database seeded', null, '');
console.log('Seeded. Demo logins (password for all: ' + PW + ')');
console.log('  registrar@dit.example   registrar');
console.log('  ananya@student.example  student');
console.log('  hiring@meridian.example verifier');
console.log('Sample registry ID to try in the verifier flow: 482177305516 (Ananya, attested)');
