'use strict';
// End-to-end check on a throwaway database: login, link, attest, consent, verify, tamper, audit chain.
const fs = require('fs');
const os = require('os');
const path = require('path');

const dbFile = path.join(os.tmpdir(), 'apaar-smoke-' + process.pid + '.db');
process.env.DB_FILE = dbFile;
require('./seed');

const { createApp } = require('../src/server');
const audit = require('../src/audit');

let failed = 0;
const check = (label, cond, extra) => {
  console.log((cond ? 'PASS ' : 'FAIL ') + label + (cond ? '' : '  -> ' + JSON.stringify(extra)));
  if (!cond) failed++;
};

(async () => {
  const server = createApp().listen(0);
  const base = 'http://127.0.0.1:' + server.address().port + '/api';
  const call = async (method, url, body, token) => {
    const r = await fetch(base + url, {
      method, headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
    return { status: r.status, body: await r.json() };
  };
  const login = async email => (await call('POST', '/auth/login', { email, password: 'Passw0rd!demo' })).body.token;
  const PW_BAD = await call('POST', '/auth/login', { email: 'registrar@dit.example', password: 'wrong' });
  check('bad password is rejected', PW_BAD.status === 401, PW_BAD);

  const reg = await login('registrar@dit.example');
  const stu = await login('ananya@student.example');
  const ver = await login('hiring@meridian.example');

  const forbidden = await call('GET', '/students', null, stu);
  check('student cannot list the registrar roster', forbidden.status === 403, forbidden);

  const list = await call('GET', '/students', null, reg);
  check('registrar sees 4 students', list.body.count === 4, list.body.count);
  const faiz = list.body.students.find(s => s.name === 'Mohammad Faiz');
  check('name mismatch is flagged', faiz.state === 'flagged', faiz.state);
  const att = await call('POST', `/students/${faiz.id}/attest`, null, reg);
  check('flagged record cannot be attested', att.status === 409, att.body);

  // Link and attest a new student against the registry
  const add = await call('POST', '/students', { name: 'Ishita Rani', dob: '2008-03-14', program: 'B.Tech', branch: 'CSE', admYear: 2026, apaarId: '316640192875' }, reg);
  check('new student links and is pending', add.status === 201 && add.body.student.state === 'pending', add.body);
  const bad = await call('POST', '/students', { name: 'X', dob: '2008-01-01', program: 'B.Tech', branch: 'CSE', admYear: 2026, apaarId: '12345' }, reg);
  check('short APAAR ID is refused', bad.status === 422, bad.body);
  const at2 = await call('POST', `/students/${add.body.student.id}/attest`, null, reg);
  check('pending record can be attested', at2.status === 200 && at2.body.hash, at2.body);

  // Consent flow
  const apaar = '482177305516';
  const rq = await call('POST', '/verify/requests', { apaarId: apaar, purpose: 'Employment check', scopes: ['identity', 'program'] }, ver);
  check('verifier request created', rq.status === 201, rq.body);
  const early = await call('POST', `/verify/requests/${rq.body.requestId}/redeem`, { code: '123456' }, ver);
  check('code cannot be used before approval', early.status === 409, early.body);
  const ap = await call('POST', `/me/consents/${rq.body.requestId}/approve`, null, stu);
  check('student approves and gets a 6-digit code', /^\d{6}$/.test(ap.body.code || ''), ap.body);
  const wrong = await call('POST', `/verify/requests/${rq.body.requestId}/redeem`, { code: '000000' }, ver);
  check('wrong code is refused', wrong.status === 403, wrong.body);
  const ok = await call('POST', `/verify/requests/${rq.body.requestId}/redeem`, { code: ap.body.code }, ver);
  check('right code returns verified record', ok.body.verdict === 'ok' && ok.body.data.identity.name === 'Ananya Kumari', ok.body);
  check('marks are not released without consent', ok.body.data && !ok.body.data.marks, ok.body.data);
  const again = await call('POST', `/verify/requests/${rq.body.requestId}/redeem`, { code: ap.body.code }, ver);
  check('code works only once', again.status === 409, again.body);

  // Tamper: change a result without re-attesting, then verify again
  const ana = (await call('GET', '/students?q=ananya', null, reg)).body.students[0];
  await call('POST', `/students/${ana.id}/results`, { semester: 6, sgpa: 9.9 }, reg);
  const rq2 = await call('POST', '/verify/requests', { apaarId: apaar, purpose: 'Second check', scopes: ['marks'] }, ver);
  const ap2 = await call('POST', `/me/consents/${rq2.body.requestId}/approve`, null, stu);
  const bad2 = await call('POST', `/verify/requests/${rq2.body.requestId}/redeem`, { code: ap2.body.code }, ver);
  check('edited record fails the integrity check', bad2.body.verdict === 'tampered' && !bad2.body.data, bad2.body);
  await call('POST', `/students/${ana.id}/attest`, null, reg);
  const rq3 = await call('POST', '/verify/requests', { apaarId: apaar, purpose: 'Third check', scopes: ['marks'] }, ver);
  const ap3 = await call('POST', `/me/consents/${rq3.body.requestId}/approve`, null, stu);
  const ok3 = await call('POST', `/verify/requests/${rq3.body.requestId}/redeem`, { code: ap3.body.code }, ver);
  check('re-attested record verifies again', ok3.body.verdict === 'ok' && ok3.body.data.marks.sgpa[5] === 9.9, ok3.body);

  // Lockout after three wrong codes
  const rq4 = await call('POST', '/verify/requests', { apaarId: apaar, purpose: 'Lock test', scopes: ['identity'] }, ver);
  await call('POST', `/me/consents/${rq4.body.requestId}/approve`, null, stu);
  let last;
  for (let i = 0; i < 3; i++) last = await call('POST', `/verify/requests/${rq4.body.requestId}/redeem`, { code: '111111' }, ver);
  check('three wrong codes lock the request', last.status === 423, last);

  const hist = await call('GET', '/me/access-history', null, stu);
  check('student sees access history', hist.body.entries.length > 5, hist.body.entries.length);
  check('audit hash chain is intact', audit.verifyChain().ok === true, audit.verifyChain());

  // Tamper with the audit log itself
  const db = require('../src/db');
  db.prepare("UPDATE audit_log SET detail = 'edited' WHERE id = 3").run();
  check('edited audit row is detected', audit.verifyChain().ok === false, audit.verifyChain());

  server.close();
  // Close the database before deleting its files (avoids EPERM on Windows).
  db.close();
  for (const ext of ['', '-wal', '-shm']) fs.rmSync(dbFile + ext, { force: true });
  console.log(failed ? `\n${failed} check(s) failed` : '\nAll checks passed');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
