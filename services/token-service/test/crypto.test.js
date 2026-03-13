const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// =============================================================================
// Token Crypto Module Tests
// =============================================================================

describe('crypto module', () => {
  let tokenCrypto;

  beforeEach(() => {
    // Clear cached module + env vars before each test
    delete require.cache[require.resolve('../src/crypto')];
    delete process.env.JWT_PRIVATE_KEY;
    delete process.env.JWT_PRIVATE_KEY_FILE;
    delete process.env.JWT_SECRET;
    tokenCrypto = require('../src/crypto');
  });

  afterEach(() => {
    tokenCrypto._reset();
    delete process.env.JWT_PRIVATE_KEY;
    delete process.env.JWT_PRIVATE_KEY_FILE;
    delete process.env.JWT_SECRET;
  });

  // ===========================================================================
  // ES256 signing and verification
  // ===========================================================================

  describe('ES256 sign/verify (dev keys)', () => {
    it('should sign tokens with ES256 using dev keys', () => {
      const payload = { sub: 'spiffe://wid/workload/test', aud: 'stripe' };
      const token = tokenCrypto.signToken(payload);
      assert.ok(token);

      // Decode header to check algorithm
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
      assert.equal(header.alg, 'ES256');
    });

    it('should include kid in JWT header', () => {
      const payload = { sub: 'test-workload' };
      const token = tokenCrypto.signToken(payload);
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
      assert.ok(header.kid, 'JWT header should have kid');
      assert.equal(header.kid, tokenCrypto.getKid());
    });

    it('should verify ES256-signed tokens', () => {
      const payload = { sub: 'test-workload', aud: 'api', iat: Math.floor(Date.now() / 1000) };
      const token = tokenCrypto.signToken(payload);
      const decoded = tokenCrypto.verifyToken(token);
      assert.ok(decoded);
      assert.equal(decoded.sub, 'test-workload');
      assert.equal(decoded.aud, 'api');
    });

    it('should reject forged tokens', () => {
      // Sign with a different key
      const { privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      const forgedToken = jwt.sign({ sub: 'attacker' }, privateKey, { algorithm: 'ES256' });
      const result = tokenCrypto.verifyToken(forgedToken);
      assert.equal(result, null, 'Forged token should not verify');
    });

    it('should reject expired tokens', () => {
      const payload = {
        sub: 'test-workload',
        iat: Math.floor(Date.now() / 1000) - 7200,
        exp: Math.floor(Date.now() / 1000) - 3600,
      };
      const token = tokenCrypto.signToken(payload);
      const result = tokenCrypto.verifyToken(token);
      assert.equal(result, null, 'Expired token should not verify');
    });

    it('should reject tokens with algorithm confusion (HS256 on ES256 key)', () => {
      // Try to create an HS256 token using the public key as secret (alg confusion attack)
      const jwks = tokenCrypto.getJWKS();
      const pubKeyStr = JSON.stringify(jwks);
      const malicious = jwt.sign({ sub: 'attacker' }, pubKeyStr, { algorithm: 'HS256' });
      const result = tokenCrypto.verifyToken(malicious);
      assert.equal(result, null, 'Algorithm confusion attack should fail');
    });
  });

  // ===========================================================================
  // JWKS
  // ===========================================================================

  describe('JWKS', () => {
    it('should return JWKS with correct shape', () => {
      const jwks = tokenCrypto.getJWKS();
      assert.ok(jwks);
      assert.ok(Array.isArray(jwks.keys));
      assert.equal(jwks.keys.length, 1);

      const key = jwks.keys[0];
      assert.equal(key.kty, 'EC');
      assert.equal(key.crv, 'P-256');
      assert.equal(key.alg, 'ES256');
      assert.equal(key.use, 'sig');
      assert.ok(key.x, 'JWKS key should have x coordinate');
      assert.ok(key.y, 'JWKS key should have y coordinate');
      assert.ok(key.kid, 'JWKS key should have kid');
    });

    it('should not contain private key material in JWKS', () => {
      const jwks = tokenCrypto.getJWKS();
      const key = jwks.keys[0];
      assert.equal(key.d, undefined, 'JWKS must NOT contain private key (d parameter)');
    });

    it('should have kid matching the signing key', () => {
      const jwks = tokenCrypto.getJWKS();
      assert.equal(jwks.keys[0].kid, tokenCrypto.getKid());
    });
  });

  // ===========================================================================
  // Algorithm and kid accessors
  // ===========================================================================

  describe('getAlgorithm / getKid', () => {
    it('should report ES256 with dev keys', () => {
      assert.equal(tokenCrypto.getAlgorithm(), 'ES256');
    });

    it('should return non-null kid with ES256', () => {
      assert.ok(tokenCrypto.getKid());
      assert.equal(typeof tokenCrypto.getKid(), 'string');
    });
  });

  // ===========================================================================
  // HS256 legacy fallback
  // ===========================================================================

  describe('HS256 fallback', () => {
    it('should accept legacy HS256 tokens during ES256 migration', () => {
      // In ES256 mode (dev keys loaded), HS256 tokens signed with the default
      // secret should still verify — this is the dual-verification migration path
      const payload = { sub: 'legacy-workload', iat: Math.floor(Date.now() / 1000) };
      const legacyToken = jwt.sign(payload, 'dev-secret-change-in-production', { algorithm: 'HS256' });

      const result = tokenCrypto.verifyToken(legacyToken);
      assert.ok(result, 'HS256 tokens should verify during migration period');
      assert.equal(result.sub, 'legacy-workload');
    });

    it('should reject HS256 tokens with wrong secret during migration', () => {
      const payload = { sub: 'attacker', iat: Math.floor(Date.now() / 1000) };
      const badToken = jwt.sign(payload, 'totally-wrong-secret', { algorithm: 'HS256' });

      const result = tokenCrypto.verifyToken(badToken);
      assert.equal(result, null, 'Wrong HS256 secret should be rejected even in migration');
    });
  });

  // ===========================================================================
  // Dual verification (migration support)
  // ===========================================================================

  describe('dual verification during migration', () => {
    it('should verify ES256 tokens', () => {
      const payload = { sub: 'new-workload', iat: Math.floor(Date.now() / 1000) };
      const token = tokenCrypto.signToken(payload);
      const result = tokenCrypto.verifyToken(token);
      assert.ok(result);
      assert.equal(result.sub, 'new-workload');
    });

    it('should verify legacy HS256 tokens (migration fallback)', () => {
      const payload = { sub: 'old-workload', iat: Math.floor(Date.now() / 1000) };
      const legacyToken = jwt.sign(payload, 'dev-secret-change-in-production', { algorithm: 'HS256' });
      const result = tokenCrypto.verifyToken(legacyToken);
      assert.ok(result, 'Legacy HS256 tokens should verify during migration');
      assert.equal(result.sub, 'old-workload');
    });

    it('should reject tokens signed with wrong HS256 secret', () => {
      const payload = { sub: 'attacker', iat: Math.floor(Date.now() / 1000) };
      const badToken = jwt.sign(payload, 'wrong-secret', { algorithm: 'HS256' });
      const result = tokenCrypto.verifyToken(badToken);
      assert.equal(result, null, 'Wrong HS256 secret should be rejected');
    });
  });

  // ===========================================================================
  // JWT_PRIVATE_KEY env var loading
  // ===========================================================================

  describe('JWT_PRIVATE_KEY env var', () => {
    it('should load key from base64-encoded env var', () => {
      tokenCrypto._reset();
      delete require.cache[require.resolve('../src/crypto')];

      // Generate a fresh key pair
      const { privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      process.env.JWT_PRIVATE_KEY = Buffer.from(privateKey).toString('base64');
      const freshCrypto = require('../src/crypto');
      assert.equal(freshCrypto.getAlgorithm(), 'ES256');
      assert.ok(freshCrypto.getKid());

      // Sign and verify round-trip
      const token = freshCrypto.signToken({ sub: 'env-workload' });
      const decoded = freshCrypto.verifyToken(token);
      assert.ok(decoded);
      assert.equal(decoded.sub, 'env-workload');

      freshCrypto._reset();
    });
  });
});
