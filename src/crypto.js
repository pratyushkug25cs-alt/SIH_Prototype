'use strict';
const crypto = require('crypto');
const config = require('./config');

/** Deterministic JSON: keys sorted at every level, so the same record always hashes the same. */
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

const sha256 = text => crypto.createHash('sha256').update(text).digest('hex');

/* ---- Ed25519 institution signing ---- */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}
const sign = (privatePem, text) => crypto.sign(null, Buffer.from(text), privatePem).toString('base64');
function verifySignature(publicPem, text, signatureB64) {
  try { return crypto.verify(null, Buffer.from(text), publicPem, Buffer.from(signatureB64, 'base64')); }
  catch { return false; }
}

/* ---- APAAR ID protection: AES-256-GCM at rest, HMAC blind index for lookup ---- */
function encryptId(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', config.idEncKey, iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.');
}
function decryptId(stored) {
  const [iv, tag, enc] = stored.split('.').map(s => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', config.idEncKey, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}
const blindIndex = plain => crypto.createHmac('sha256', config.idIndexKey).update(plain).digest('hex');

/* ---- passwords ---- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}

const randomCode = () => String(crypto.randomInt(100000, 1000000));

module.exports = { canonical, sha256, generateKeypair, sign, verifySignature, encryptId, decryptId, blindIndex, hashPassword, checkPassword, randomCode };
