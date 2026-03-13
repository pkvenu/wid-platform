// =============================================================================
// Token Crypto Module — ES256 (ECDSA P-256) with HS256 Legacy Fallback
// =============================================================================
// Key loading priority:
//   1. JWT_PRIVATE_KEY env var (base64-encoded PEM)
//   2. JWT_PRIVATE_KEY_FILE env var (path to PEM file)
//   3. ./keys/dev/ec-private.pem (dev fallback)
//   4. JWT_SECRET with HS256 (legacy fallback, logs warning)
// =============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

let _privateKey = null;
let _publicKey = null;
let _algorithm = null;
let _kid = null;
let _jwks = null;

function init() {
  // Already initialized
  if (_algorithm) return;

  // Priority 1: JWT_PRIVATE_KEY env var (base64-encoded PEM)
  if (process.env.JWT_PRIVATE_KEY) {
    try {
      _privateKey = Buffer.from(process.env.JWT_PRIVATE_KEY, 'base64').toString('utf8');
      _publicKey = derivePublicKey(_privateKey);
      _algorithm = 'ES256';
      _kid = computeKid(_publicKey);
      _jwks = buildJWKS(_publicKey, _kid);
      console.log(`Token crypto: ES256 loaded from JWT_PRIVATE_KEY env var (kid=${_kid})`);
      return;
    } catch (err) {
      console.error('Failed to load JWT_PRIVATE_KEY env var:', err.message);
    }
  }

  // Priority 2: JWT_PRIVATE_KEY_FILE env var (path to PEM file)
  if (process.env.JWT_PRIVATE_KEY_FILE) {
    try {
      _privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE, 'utf8');
      _publicKey = derivePublicKey(_privateKey);
      _algorithm = 'ES256';
      _kid = computeKid(_publicKey);
      _jwks = buildJWKS(_publicKey, _kid);
      console.log(`Token crypto: ES256 loaded from ${process.env.JWT_PRIVATE_KEY_FILE} (kid=${_kid})`);
      return;
    } catch (err) {
      console.error('Failed to load JWT_PRIVATE_KEY_FILE:', err.message);
    }
  }

  // Priority 3: Dev keys in ./keys/dev/
  const devKeyPath = path.join(__dirname, '..', 'keys', 'dev', 'ec-private.pem');
  if (fs.existsSync(devKeyPath)) {
    try {
      _privateKey = fs.readFileSync(devKeyPath, 'utf8');
      _publicKey = derivePublicKey(_privateKey);
      _algorithm = 'ES256';
      _kid = computeKid(_publicKey);
      _jwks = buildJWKS(_publicKey, _kid);
      console.log(`Token crypto: ES256 loaded from dev keys (kid=${_kid})`);
      console.warn('WARNING: Using dev keys. Set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE for production.');
      return;
    } catch (err) {
      console.error('Failed to load dev keys:', err.message);
    }
  }

  // Priority 4: Legacy HS256 fallback
  const secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
  _privateKey = secret;
  _publicKey = secret;
  _algorithm = 'HS256';
  _kid = null;
  _jwks = null;
  console.warn('WARNING: Falling back to HS256 (symmetric). Upgrade to ES256 by providing EC keys.');
  if (secret === 'dev-secret-change-in-production') {
    console.warn('WARNING: Using default JWT_SECRET. Set JWT_SECRET env var for production.');
  }
}

function derivePublicKey(privatePem) {
  const keyObject = crypto.createPrivateKey(privatePem);
  const publicKeyObject = crypto.createPublicKey(keyObject);
  return publicKeyObject.export({ type: 'spki', format: 'pem' });
}

function computeKid(publicKeyPem) {
  const keyObject = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObject.export({ format: 'jwk' });
  // RFC 7638: canonical JSON with lexicographic key order for EC
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function buildJWKS(publicKeyPem, kid) {
  const keyObject = crypto.createPublicKey(publicKeyPem);
  const jwk = keyObject.export({ format: 'jwk' });
  return {
    keys: [
      {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        kid,
        use: 'sig',
        alg: 'ES256',
      },
    ],
  };
}

/**
 * Sign a JWT payload.
 * @param {object} payload - JWT claims
 * @returns {string} Signed JWT
 */
function signToken(payload) {
  init();
  const options = { algorithm: _algorithm };
  if (_kid) {
    options.keyid = _kid;
  }
  return jwt.sign(payload, _privateKey, options);
}

/**
 * Verify a JWT. Supports dual verification during migration:
 * tries ES256 first, falls back to HS256 for tokens issued before upgrade.
 * @param {string} token - JWT string
 * @returns {object|null} Decoded claims or null if invalid
 */
function verifyToken(token) {
  init();

  // If running ES256, try ES256 first, then fall back to HS256 for migration
  if (_algorithm === 'ES256') {
    try {
      return jwt.verify(token, _publicKey, { algorithms: ['ES256'] });
    } catch {
      // Fall back to HS256 for tokens issued before the upgrade
      const legacySecret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
      try {
        return jwt.verify(token, legacySecret, { algorithms: ['HS256'] });
      } catch {
        return null;
      }
    }
  }

  // HS256 mode
  try {
    return jwt.verify(token, _privateKey, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

/**
 * Get the JWKS document (public key only). Returns null if HS256 mode.
 * @returns {object|null}
 */
function getJWKS() {
  init();
  return _jwks;
}

/**
 * Get the current signing algorithm.
 * @returns {string} 'ES256' or 'HS256'
 */
function getAlgorithm() {
  init();
  return _algorithm;
}

/**
 * Get the current key ID. Returns null for HS256.
 * @returns {string|null}
 */
function getKid() {
  init();
  return _kid;
}

/**
 * Reset internal state. For testing only.
 */
function _reset() {
  _privateKey = null;
  _publicKey = null;
  _algorithm = null;
  _kid = null;
  _jwks = null;
}

module.exports = {
  signToken,
  verifyToken,
  getJWKS,
  getAlgorithm,
  getKid,
  _reset,
};
