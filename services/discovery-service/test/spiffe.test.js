const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  generateSpiffeId,
  parseSpiffeId,
  EFFECTIVE_DOMAIN,
} = require('../src/utils/spiffe');

// =============================================================================
// generateSpiffeId()
// =============================================================================

describe('generateSpiffeId', () => {
  it('should produce valid SPIFFE URI format', () => {
    const id = generateSpiffeId('production', 'billing-agent', 'cloud-run');
    assert.ok(id.startsWith('spiffe://'), `Expected spiffe:// prefix, got: ${id}`);
    assert.ok(id.includes(EFFECTIVE_DOMAIN), `Expected domain ${EFFECTIVE_DOMAIN}`);
  });

  it('should clean special characters from name', () => {
    const id = generateSpiffeId('prod', 'My Agent (v2)!', 'cloud-run');
    assert.ok(!id.includes('('), 'Should not contain parentheses');
    assert.ok(!id.includes('!'), 'Should not contain exclamation');
    assert.ok(id.includes('my-agent-v2'), 'Should be cleaned and lowercased');
  });

  it('should map known type to correct path', () => {
    assert.ok(generateSpiffeId('ns', 'svc', 'cloud-run').includes('/gcp/cloud-run/'));
    assert.ok(generateSpiffeId('ns', 'svc', 'lambda').includes('/aws/lambda/'));
    assert.ok(generateSpiffeId('ns', 'svc', 'a2a-agent').includes('/agent/a2a/'));
    assert.ok(generateSpiffeId('ns', 'svc', 'mcp-server').includes('/agent/mcp/'));
  });

  it('should use workload as default type path for unknown types', () => {
    const id = generateSpiffeId('ns', 'svc', 'unknown-type');
    assert.ok(id.includes('/workload/'), `Expected /workload/ path, got: ${id}`);
  });

  it('should handle missing type gracefully', () => {
    const id = generateSpiffeId('ns', 'svc');
    assert.ok(id.includes('/workload/'), `Expected /workload/ path for undefined type`);
  });

  it('should clean namespace too', () => {
    const id = generateSpiffeId('My Project!', 'svc', 'cloud-run');
    assert.ok(id.includes('/my-project/'), 'Namespace should be cleaned');
  });
});

// =============================================================================
// parseSpiffeId()
// =============================================================================

describe('parseSpiffeId', () => {
  it('should parse valid SPIFFE ID', () => {
    const result = parseSpiffeId('spiffe://company.com/gcp/cloud-run/prod/billing');
    assert.deepEqual(result, {
      domain: 'company.com',
      type: 'gcp/cloud-run',
      namespace: 'prod',
      name: 'billing',
    });
  });

  it('should return null for invalid input', () => {
    assert.equal(parseSpiffeId('not-a-spiffe-id'), null);
  });

  it('should return null for null input', () => {
    assert.equal(parseSpiffeId(null), null);
  });

  it('should return null for undefined input', () => {
    assert.equal(parseSpiffeId(undefined), null);
  });

  it('should parse single-segment type path', () => {
    const result = parseSpiffeId('spiffe://wid.dev/workload/default/my-svc');
    assert.deepEqual(result, {
      domain: 'wid.dev',
      type: 'workload',
      namespace: 'default',
      name: 'my-svc',
    });
  });

  it('should handle deep type paths', () => {
    const result = parseSpiffeId('spiffe://wid.dev/identity/sa/prod/vault-agent');
    assert.deepEqual(result, {
      domain: 'wid.dev',
      type: 'identity/sa',
      namespace: 'prod',
      name: 'vault-agent',
    });
  });
});
