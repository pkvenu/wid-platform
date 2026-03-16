// =============================================================================
// Agent Card JWS Signer — Test Suite
// =============================================================================

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { signAgentCard, verifyAgentCard } = require('../agent-card-signer');

// ── Generate test ES256 key pair ─────────────────────────────────────────────

function generateTestKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

const testKeys = generateTestKeys();
const altKeys = generateTestKeys(); // different key pair for negative tests

const sampleCard = {
  name: 'test-agent',
  version: '1.0.0',
  description: 'A test A2A agent',
  skills: [{ name: 'analyze', description: 'Data analysis' }],
};


// =============================================================================
// signAgentCard
// =============================================================================

describe('signAgentCard', () => {
  it('produces valid JWS compact serialization (3 base64url parts)', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey);
    const parts = jws.split('.');
    assert.equal(parts.length, 3);
    // Each part should be valid base64url
    for (const part of parts) {
      assert.ok(part.length > 0, 'JWS part should not be empty');
      assert.ok(/^[A-Za-z0-9_-]+$/.test(part), `JWS part should be base64url: ${part.slice(0, 20)}`);
    }
  });

  it('includes kid in header when provided', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { kid: 'test-kid-123' });
    const headerJson = Buffer.from(jws.split('.')[0], 'base64url').toString('utf8');
    const header = JSON.parse(headerJson);
    assert.equal(header.kid, 'test-kid-123');
    assert.equal(header.alg, 'ES256');
    assert.equal(header.typ, 'agent-card+jwt');
  });

  it('includes iss claim when provided', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { iss: 'workload-identity-platform' });
    const payloadJson = Buffer.from(jws.split('.')[1], 'base64url').toString('utf8');
    const payload = JSON.parse(payloadJson);
    assert.equal(payload.iss, 'workload-identity-platform');
  });

  it('includes iat and exp claims', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { expiresInSeconds: 3600 });
    const payloadJson = Buffer.from(jws.split('.')[1], 'base64url').toString('utf8');
    const payload = JSON.parse(payloadJson);
    assert.ok(payload.iat, 'should have iat');
    assert.ok(payload.exp, 'should have exp');
    assert.equal(payload.exp - payload.iat, 3600);
  });
});


// =============================================================================
// verifyAgentCard
// =============================================================================

describe('verifyAgentCard', () => {
  it('verifies with matching key', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey);
    const result = verifyAgentCard(jws, testKeys.publicKey);
    assert.equal(result.valid, true);
    assert.equal(result.error, null);
    assert.ok(result.payload);
    assert.equal(result.payload.name, 'test-agent');
  });

  it('fails with wrong key', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey);
    const result = verifyAgentCard(jws, altKeys.publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.error);
  });

  it('rejects tampered payload', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey);
    const parts = jws.split('.');
    // Tamper with payload
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    payload.name = 'evil-agent';
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const tampered = parts.join('.');

    const result = verifyAgentCard(tampered, testKeys.publicKey);
    assert.equal(result.valid, false);
  });

  it('rejects expired signature', () => {
    // Sign with -1 second expiry (already expired)
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { expiresInSeconds: -10 });
    const result = verifyAgentCard(jws, testKeys.publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.error?.includes('expired'));
  });

  it('rejects invalid JWS format (wrong part count)', () => {
    const result = verifyAgentCard('only-one-part', testKeys.publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.error?.includes('3 parts'));
  });

  it('rejects null input', () => {
    const result = verifyAgentCard(null, testKeys.publicKey);
    assert.equal(result.valid, false);
  });

  it('rejects empty string', () => {
    const result = verifyAgentCard('', testKeys.publicKey);
    assert.equal(result.valid, false);
  });

  it('round-trip preserves all card fields', () => {
    const card = {
      name: 'finance-agent',
      version: '2.1.0',
      skills: [{ name: 'billing' }, { name: 'reporting' }],
      security: { trust_level: 'high' },
    };
    const jws = signAgentCard(card, testKeys.privateKey, { kid: 'k1', iss: 'platform' });
    const result = verifyAgentCard(jws, testKeys.publicKey);

    assert.equal(result.valid, true);
    assert.equal(result.payload.name, 'finance-agent');
    assert.equal(result.payload.version, '2.1.0');
    assert.deepEqual(result.payload.skills, [{ name: 'billing' }, { name: 'reporting' }]);
    assert.deepEqual(result.payload.security, { trust_level: 'high' });
    assert.equal(result.payload.iss, 'platform');
    assert.equal(result.header.kid, 'k1');
    assert.equal(result.header.alg, 'ES256');
  });

  it('succeeds without exp when expiresInSeconds is 0', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { expiresInSeconds: 0 });
    const result = verifyAgentCard(jws, testKeys.publicKey);
    assert.equal(result.valid, true);
  });

  it('returns header info even on verification failure', () => {
    const jws = signAgentCard(sampleCard, testKeys.privateKey, { kid: 'my-kid' });
    // Use wrong key
    const result = verifyAgentCard(jws, altKeys.publicKey);
    assert.equal(result.valid, false);
    assert.equal(result.header?.kid, 'my-kid');
  });
});
