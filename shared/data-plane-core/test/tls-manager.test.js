// =============================================================================
// TLS Manager & Trace Context Test Suite
// =============================================================================
// Tests TLSManager certificate handling and cross-environment trace propagation.
// =============================================================================

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { TLSManager } = require('../src/tls-manager.js');
const {
  injectCrossEnvTrace,
  extractCrossEnvTrace,
  enrichAuditWithTraceContext,
  HEADER_ORIGIN_RELAY,
  HEADER_ORIGIN_ENV,
  HEADER_RELAY_SPIFFE,
  HEADER_TRACE_ID,
} = require('../src/trace-context.js');

// ── TLSManager ───────────────────────────────────────────────────────────────

describe('TLSManager', () => {

  describe('constructor', () => {
    it('does not throw with no cert paths', () => {
      assert.doesNotThrow(() => new TLSManager());
    });

    it('initializes with null state when no paths provided', () => {
      const tls = new TLSManager();
      assert.equal(tls.isLoaded, false);
      assert.equal(tls.spiffeId, null);
      assert.equal(tls.fingerprint, null);
      assert.equal(tls.certificate, null);
      assert.equal(tls.certInfo, null);
    });

    it('accepts custom log function', () => {
      let logged = false;
      const tls = new TLSManager({ log: () => { logged = true; } });
      assert.equal(tls.isLoaded, false);
    });
  });

  describe('_computeFingerprint', () => {
    it('computes SHA-256 fingerprint from PEM', () => {
      const tls = new TLSManager();
      // Minimal valid base64 content between PEM markers
      const fakePem = [
        '-----BEGIN CERTIFICATE-----',
        'AAAAAAAAAAAAAAAAAAAAAA==',
        '-----END CERTIFICATE-----',
      ].join('\n');
      const fp = tls._computeFingerprint(fakePem);
      assert.ok(fp, 'fingerprint should not be null');
      assert.equal(typeof fp, 'string');
      assert.equal(fp.length, 64, 'SHA-256 hex is 64 chars');
      assert.match(fp, /^[0-9a-f]{64}$/, 'fingerprint should be lowercase hex');
    });

    it('returns consistent fingerprint for same input', () => {
      const tls = new TLSManager();
      const pem = [
        '-----BEGIN CERTIFICATE-----',
        'dGVzdGNlcnQ=',
        '-----END CERTIFICATE-----',
      ].join('\n');
      const fp1 = tls._computeFingerprint(pem);
      const fp2 = tls._computeFingerprint(pem);
      assert.equal(fp1, fp2);
    });

    it('returns null for completely invalid input', () => {
      const tls = new TLSManager();
      // Null/undefined triggers catch block
      const fp = tls._computeFingerprint(null);
      assert.equal(fp, null);
    });
  });

  describe('_extractSpiffeId', () => {
    it('extracts SPIFFE ID from X.509 SAN', () => {
      const tls = new TLSManager();
      // Mock an x509 object with subjectAltName
      const mockX509 = {
        subjectAltName: 'URI:spiffe://cluster.local/ns/prod/sa/relay-aws, DNS:relay.wid.internal',
      };
      const spiffeId = tls._extractSpiffeId(mockX509);
      assert.equal(spiffeId, 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    });

    it('returns null when no SAN present', () => {
      const tls = new TLSManager();
      const mockX509 = { subjectAltName: null };
      assert.equal(tls._extractSpiffeId(mockX509), null);
    });

    it('returns null when SAN has no SPIFFE URI', () => {
      const tls = new TLSManager();
      const mockX509 = { subjectAltName: 'DNS:relay.wid.internal, IP:10.0.0.1' };
      assert.equal(tls._extractSpiffeId(mockX509), null);
    });

    it('returns null for null x509', () => {
      const tls = new TLSManager();
      assert.equal(tls._extractSpiffeId(null), null);
    });

    it('picks first SPIFFE URI when multiple present', () => {
      const tls = new TLSManager();
      const mockX509 = {
        subjectAltName: 'URI:spiffe://domain-a/workload-1, URI:spiffe://domain-b/workload-2',
      };
      assert.equal(tls._extractSpiffeId(mockX509), 'spiffe://domain-a/workload-1');
    });
  });

  describe('isExpiringSoon', () => {
    it('returns true when no cert loaded', () => {
      const tls = new TLSManager();
      assert.equal(tls.isExpiringSoon(), true);
    });

    it('returns true when no cert loaded with custom threshold', () => {
      const tls = new TLSManager();
      assert.equal(tls.isExpiringSoon(60000), true);
    });
  });

  describe('getRemainingValiditySec', () => {
    it('returns 0 when no cert loaded', () => {
      const tls = new TLSManager();
      assert.equal(tls.getRemainingValiditySec(), 0);
    });
  });

  describe('createMTLSAgent', () => {
    it('throws when no certs loaded', () => {
      const tls = new TLSManager();
      assert.throws(
        () => tls.createMTLSAgent(),
        { message: 'Cannot create mTLS agent: certificates not loaded' }
      );
    });
  });

  describe('validatePeerCert', () => {
    it('returns valid: false with invalid PEM', () => {
      const tls = new TLSManager();
      const result = tls.validatePeerCert('not-a-real-certificate');
      assert.equal(result.valid, false);
      assert.equal(result.spiffeId, null);
      assert.equal(result.fingerprint, null);
      assert.ok(result.error, 'should contain an error message');
    });

    it('returns valid: false with empty string', () => {
      const tls = new TLSManager();
      const result = tls.validatePeerCert('');
      assert.equal(result.valid, false);
      assert.ok(result.error);
    });

    it('returns valid: false with null input', () => {
      const tls = new TLSManager();
      const result = tls.validatePeerCert(null);
      assert.equal(result.valid, false);
      assert.ok(result.error);
    });
  });

  describe('destroy', () => {
    it('does not throw when no watchers or agent exist', () => {
      const tls = new TLSManager();
      assert.doesNotThrow(() => tls.destroy());
    });

    it('can be called multiple times safely', () => {
      const tls = new TLSManager();
      assert.doesNotThrow(() => {
        tls.destroy();
        tls.destroy();
      });
    });
  });
});

// ── Trace Context ────────────────────────────────────────────────────────────

describe('injectCrossEnvTrace', () => {
  it('sets origin headers when not present', () => {
    const headers = injectCrossEnvTrace(
      {},
      'spiffe://cluster.local/ns/prod/sa/relay-aws',
      'aws-us-east-1'
    );
    assert.equal(headers[HEADER_RELAY_SPIFFE], 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    assert.equal(headers[HEADER_ORIGIN_RELAY], 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    assert.equal(headers[HEADER_ORIGIN_ENV], 'aws-us-east-1');
  });

  it('preserves existing origin headers', () => {
    const existing = {
      [HEADER_ORIGIN_RELAY]: 'spiffe://cluster.local/ns/prod/sa/relay-gcp',
      [HEADER_ORIGIN_ENV]: 'gcp-us-central1',
    };
    const headers = injectCrossEnvTrace(
      existing,
      'spiffe://cluster.local/ns/prod/sa/relay-aws',
      'aws-us-east-1'
    );
    // Should set the current relay but NOT overwrite origin
    assert.equal(headers[HEADER_RELAY_SPIFFE], 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    assert.equal(headers[HEADER_ORIGIN_RELAY], undefined, 'should not overwrite origin relay');
    assert.equal(headers[HEADER_ORIGIN_ENV], undefined, 'should not overwrite origin env');
  });

  it('defaults environment to unknown when not provided', () => {
    const headers = injectCrossEnvTrace(
      {},
      'spiffe://cluster.local/ns/prod/sa/relay',
      undefined
    );
    assert.equal(headers[HEADER_ORIGIN_ENV], 'unknown');
  });

  it('does not set relay header when spiffeId is null', () => {
    const headers = injectCrossEnvTrace({}, null, 'some-env');
    assert.equal(headers[HEADER_RELAY_SPIFFE], undefined);
    assert.equal(headers[HEADER_ORIGIN_RELAY], undefined);
  });

  it('handles undefined existingHeaders', () => {
    const headers = injectCrossEnvTrace(
      undefined,
      'spiffe://domain/workload',
      'env-1'
    );
    assert.equal(headers[HEADER_RELAY_SPIFFE], 'spiffe://domain/workload');
    assert.equal(headers[HEADER_ORIGIN_RELAY], 'spiffe://domain/workload');
    assert.equal(headers[HEADER_ORIGIN_ENV], 'env-1');
  });
});

describe('extractCrossEnvTrace', () => {
  it('extracts all header fields', () => {
    const headers = {
      [HEADER_TRACE_ID]: 'trace-abc-123',
      [HEADER_ORIGIN_RELAY]: 'spiffe://cluster.local/ns/prod/sa/relay-gcp',
      [HEADER_ORIGIN_ENV]: 'gcp-us-central1',
      [HEADER_RELAY_SPIFFE]: 'spiffe://cluster.local/ns/prod/sa/relay-aws',
    };
    const ctx = extractCrossEnvTrace(headers);
    assert.equal(ctx.traceId, 'trace-abc-123');
    assert.equal(ctx.originRelaySpiffeId, 'spiffe://cluster.local/ns/prod/sa/relay-gcp');
    assert.equal(ctx.originEnvironment, 'gcp-us-central1');
    assert.equal(ctx.currentRelaySpiffeId, 'spiffe://cluster.local/ns/prod/sa/relay-aws');
  });

  it('returns nulls for missing headers', () => {
    const ctx = extractCrossEnvTrace({});
    assert.equal(ctx.traceId, null);
    assert.equal(ctx.originRelaySpiffeId, null);
    assert.equal(ctx.originEnvironment, null);
    assert.equal(ctx.currentRelaySpiffeId, null);
  });

  it('handles undefined input', () => {
    const ctx = extractCrossEnvTrace(undefined);
    assert.equal(ctx.traceId, null);
    assert.equal(ctx.originRelaySpiffeId, null);
  });

  it('extracts partial headers', () => {
    const ctx = extractCrossEnvTrace({
      [HEADER_TRACE_ID]: 'trace-xyz',
    });
    assert.equal(ctx.traceId, 'trace-xyz');
    assert.equal(ctx.originRelaySpiffeId, null);
    assert.equal(ctx.originEnvironment, null);
    assert.equal(ctx.currentRelaySpiffeId, null);
  });
});

describe('enrichAuditWithTraceContext', () => {
  it('adds relay identity fields to audit entry', () => {
    const entry = { decision_id: 'dec-1', verdict: 'allowed' };
    const enriched = enrichAuditWithTraceContext(
      entry,
      'spiffe://cluster.local/ns/prod/sa/relay-aws',
      'aws-us-east-1'
    );
    assert.equal(enriched.decision_id, 'dec-1');
    assert.equal(enriched.verdict, 'allowed');
    assert.equal(enriched.relay_spiffe_id, 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    assert.equal(enriched.relay_environment, 'aws-us-east-1');
    assert.equal(enriched.origin_relay_spiffe_id, null);
    assert.equal(enriched.origin_environment, null);
  });

  it('preserves existing origin fields from entry', () => {
    const entry = {
      decision_id: 'dec-2',
      origin_relay_spiffe_id: 'spiffe://cluster.local/ns/prod/sa/relay-gcp',
      origin_environment: 'gcp-us-central1',
    };
    const enriched = enrichAuditWithTraceContext(
      entry,
      'spiffe://cluster.local/ns/prod/sa/relay-aws',
      'aws-us-east-1'
    );
    assert.equal(enriched.origin_relay_spiffe_id, 'spiffe://cluster.local/ns/prod/sa/relay-gcp');
    assert.equal(enriched.origin_environment, 'gcp-us-central1');
    assert.equal(enriched.relay_spiffe_id, 'spiffe://cluster.local/ns/prod/sa/relay-aws');
    assert.equal(enriched.relay_environment, 'aws-us-east-1');
  });

  it('handles null relaySpiffeId and environmentName', () => {
    const entry = { decision_id: 'dec-3' };
    const enriched = enrichAuditWithTraceContext(entry, null, null);
    assert.equal(enriched.relay_spiffe_id, null);
    assert.equal(enriched.relay_environment, null);
  });

  it('does not mutate the original entry', () => {
    const entry = { decision_id: 'dec-4' };
    const enriched = enrichAuditWithTraceContext(entry, 'spiffe://x', 'env');
    assert.equal(entry.relay_spiffe_id, undefined);
    assert.equal(enriched.relay_spiffe_id, 'spiffe://x');
  });
});

// ── Trace Context Header Constants ───────────────────────────────────────────

describe('trace context header constants', () => {
  it('exports correct header names', () => {
    assert.equal(HEADER_ORIGIN_RELAY, 'x-wid-origin-relay');
    assert.equal(HEADER_ORIGIN_ENV, 'x-wid-origin-environment');
    assert.equal(HEADER_RELAY_SPIFFE, 'x-wid-relay-spiffe-id');
    assert.equal(HEADER_TRACE_ID, 'x-wid-trace-id');
  });
});
