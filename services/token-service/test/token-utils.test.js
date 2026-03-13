const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  determineAuthMethod,
  generateRequestId,
  generateJTI,
  extractSpiffeIdFromCert,
} = require('../src/utils');

// =============================================================================
// determineAuthMethod()
// =============================================================================

describe('determineAuthMethod', () => {
  it('should return mtls when client certificate is present', () => {
    const req = {
      socket: {
        getPeerCertificate: () => ({ subject: { CN: 'billing-agent' } }),
      },
      headers: {},
    };
    assert.equal(determineAuthMethod(req), 'mtls');
  });

  it('should return oidc when Bearer token is present', () => {
    const req = {
      socket: {},
      headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.test' },
    };
    assert.equal(determineAuthMethod(req), 'oidc');
  });

  it('should return api_key as default', () => {
    const req = {
      socket: {},
      headers: {},
    };
    assert.equal(determineAuthMethod(req), 'api_key');
  });

  it('should prefer mtls over Bearer token', () => {
    const req = {
      socket: {
        getPeerCertificate: () => ({ subject: { CN: 'agent' } }),
      },
      headers: { authorization: 'Bearer token' },
    };
    assert.equal(determineAuthMethod(req), 'mtls');
  });
});

// =============================================================================
// generateRequestId()
// =============================================================================

describe('generateRequestId', () => {
  it('should start with req- prefix', () => {
    const id = generateRequestId();
    assert.ok(id.startsWith('req-'), `Expected req- prefix, got: ${id}`);
  });

  it('should contain timestamp and random parts', () => {
    const id = generateRequestId();
    const parts = id.split('-');
    assert.ok(parts.length >= 3, 'Expected at least 3 parts');
  });

  it('should generate unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateRequestId()));
    assert.equal(ids.size, 100, 'Generated duplicate IDs');
  });
});

// =============================================================================
// generateJTI()
// =============================================================================

describe('generateJTI', () => {
  it('should start with jti- prefix', () => {
    const id = generateJTI();
    assert.ok(id.startsWith('jti-'), `Expected jti- prefix, got: ${id}`);
  });

  it('should generate unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateJTI()));
    assert.equal(ids.size, 100, 'Generated duplicate JTIs');
  });
});

// =============================================================================
// extractSpiffeIdFromCert()
// =============================================================================

describe('extractSpiffeIdFromCert', () => {
  it('should extract SPIFFE ID from SAN URI', () => {
    const cert = {
      subjectaltname: 'URI:spiffe://company.com/workload/billing-agent, DNS:billing.local',
    };
    assert.equal(extractSpiffeIdFromCert(cert), 'spiffe://company.com/workload/billing-agent');
  });

  it('should return null when no SAN present', () => {
    const cert = {};
    assert.equal(extractSpiffeIdFromCert(cert), null);
  });

  it('should return null when SAN has no SPIFFE URI', () => {
    const cert = {
      subjectaltname: 'DNS:billing.local, IP:10.0.0.1',
    };
    assert.equal(extractSpiffeIdFromCert(cert), null);
  });

  it('should return null for null cert', () => {
    assert.equal(extractSpiffeIdFromCert(null), null);
  });

  it('should handle SPIFFE URI with deep path', () => {
    const cert = {
      subjectaltname: 'URI:spiffe://wid.dev/gcp/cloud-run/prod/billing',
    };
    assert.equal(extractSpiffeIdFromCert(cert), 'spiffe://wid.dev/gcp/cloud-run/prod/billing');
  });
});
