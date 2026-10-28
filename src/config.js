'use strict';
// Central configuration. In production every secret must come from the environment or a KMS.
const env = process.env;

const config = {
  port: Number(env.PORT || 3000),
  dbFile: env.DB_FILE || 'data.db',
  jwtSecret: env.JWT_SECRET || 'dev-only-secret-change-me',
  idEncKey: Buffer.from(env.ID_ENC_KEY || '00'.repeat(32), 'hex'),
  idIndexKey: Buffer.from(env.ID_INDEX_KEY || '11'.repeat(32), 'hex'),
  codeTtlMin: Number(env.CODE_TTL_MIN || 10),
  maxCodeAttempts: 3,
  isDevKeys: !env.JWT_SECRET || !env.ID_ENC_KEY
};

if (config.idEncKey.length !== 32 || config.idIndexKey.length !== 32) {
  throw new Error('ID_ENC_KEY and ID_INDEX_KEY must each be 64 hex characters (32 bytes).');
}
if (config.isDevKeys) {
  console.warn('[warn] Using development keys. Set JWT_SECRET, ID_ENC_KEY and ID_INDEX_KEY in .env.');
}

module.exports = config;
