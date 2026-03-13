const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  NHI_TYPES,
  ACTIONS,
  CAPABILITIES,
  AUTH_METHODS,
  buildNHIContext,
  validateCapability,
  resolveActionFromCapability,
  determineNHIType,
  extractTrustDomain,
} = require('../src/canonical-nhi-context');

// =============================================================================
// NHI_TYPES Enum
// =============================================================================

describe('NHI_TYPES', () => {
  it('should have exactly 5 types', () => {
    assert.equal(Object.keys(NHI_TYPES).length, 5);
  });

  it('should contain workload, agent, ai_agent, integration, infra_identity', () => {
    assert.equal(NHI_TYPES.WORKLOAD, 'workload');
    assert.equal(NHI_TYPES.AGENT, 'agent');
    assert.equal(NHI_TYPES.AI_AGENT, 'ai_agent');
    assert.equal(NHI_TYPES.INTEGRATION, 'integration');
    assert.equal(NHI_TYPES.INFRA_IDENTITY, 'infra_identity');
  });
});

// =============================================================================
// CAPABILITIES Schema
// =============================================================================

describe('CAPABILITIES', () => {
  it('should have 14 capabilities', () => {
    assert.equal(Object.keys(CAPABILITIES).length, 14);
  });

  it('should have risk_level on every capability', () => {
    for (const [key, cap] of Object.entries(CAPABILITIES)) {
      assert.ok(cap.risk_level, `${key} missing risk_level`);
    }
  });

  it('should have actions array on every capability', () => {
    for (const [key, cap] of Object.entries(CAPABILITIES)) {
      assert.ok(Array.isArray(cap.actions), `${key} missing actions array`);
      assert.ok(cap.actions.length > 0, `${key} has empty actions array`);
    }
  });
});

// =============================================================================
// determineNHIType()
// =============================================================================

describe('determineNHIType', () => {
  it('should return ai_agent when is_ai_agent is true', () => {
    assert.equal(determineNHIType({ is_ai_agent: true }), 'ai_agent');
  });

  it('should return agent when is_mcp_server is true', () => {
    assert.equal(determineNHIType({ is_mcp_server: true }), 'agent');
  });

  it('should return integration when category is integration', () => {
    assert.equal(determineNHIType({ category: 'integration' }), 'integration');
  });

  it('should return infra_identity when type includes infra', () => {
    assert.equal(determineNHIType({ type: 'infra-node' }), 'infra_identity');
  });

  it('should return infra_identity when category is infrastructure', () => {
    assert.equal(determineNHIType({ category: 'infrastructure' }), 'infra_identity');
  });

  it('should return workload as default', () => {
    assert.equal(determineNHIType({ name: 'billing-service' }), 'workload');
  });

  it('should prioritize ai_agent over mcp_server', () => {
    assert.equal(determineNHIType({ is_ai_agent: true, is_mcp_server: true }), 'ai_agent');
  });
});

// =============================================================================
// extractTrustDomain()
// =============================================================================

describe('extractTrustDomain', () => {
  it('should extract domain from valid SPIFFE ID', () => {
    assert.equal(extractTrustDomain('spiffe://company.com/workload/ns/svc'), 'company.com');
  });

  it('should return null for non-SPIFFE string', () => {
    assert.equal(extractTrustDomain('not-a-spiffe-id'), null);
  });

  it('should return null for null input', () => {
    assert.equal(extractTrustDomain(null), null);
  });

  it('should return null for undefined input', () => {
    assert.equal(extractTrustDomain(undefined), null);
  });

  it('should handle SPIFFE ID with deep path', () => {
    assert.equal(extractTrustDomain('spiffe://wid.dev/gcp/cloud-run/prod/billing'), 'wid.dev');
  });
});

// =============================================================================
// buildNHIContext()
// =============================================================================

describe('buildNHIContext', () => {
  const workload = {
    id: 'w-123',
    name: 'billing-agent',
    namespace: 'production',
    environment: 'prod',
    spiffe_id: 'spiffe://company.com/workload/prod/billing-agent',
    labels: { team: 'billing' },
    verified: true,
    security_score: 85,
    is_ai_agent: true,
  };

  const request = {
    action: 'token_exchange',
    capability: 'token:exchange',
    audience: 'stripe-api',
    auth_method: 'mtls',
  };

  it('should build complete OPA input structure', () => {
    const ctx = buildNHIContext(workload, request);
    assert.ok(ctx.nhi, 'missing nhi');
    assert.ok(ctx.request, 'missing request');
    assert.equal(ctx.nhi.id, 'w-123');
    assert.equal(ctx.nhi.type, 'ai_agent');
    assert.equal(ctx.request.action, 'token_exchange');
  });

  it('should throw when workload is null', () => {
    assert.throws(() => buildNHIContext(null, request), /Workload is required/);
  });

  it('should throw when request action is missing', () => {
    assert.throws(() => buildNHIContext(workload, {}), /Request action is required/);
  });

  it('should extract trust domain from SPIFFE ID', () => {
    const ctx = buildNHIContext(workload, request);
    assert.equal(ctx.nhi.trust_domain, 'company.com');
  });

  it('should default optional fields to null or empty', () => {
    const minimal = { id: 'w-min', name: 'test' };
    const ctx = buildNHIContext(minimal, { action: 'api_invoke' });
    assert.equal(ctx.nhi.spiffe_id, null);
    assert.equal(ctx.nhi.cloud_provider, null);
    assert.deepEqual(ctx.nhi.labels, {});
  });
});

// =============================================================================
// validateCapability()
// =============================================================================

describe('validateCapability', () => {
  it('should throw for unknown capability', () => {
    assert.throws(() => validateCapability('bogus:cap', {}), /Unknown capability/);
  });

  it('should throw when AI capability used by non-AI agent', () => {
    assert.throws(
      () => validateCapability('model:invoke', { is_ai_agent: false }),
      /requires AI agent/
    );
  });

  it('should throw when MCP capability used by non-MCP server', () => {
    assert.throws(
      () => validateCapability('mcp:execute', { is_mcp_server: false }),
      /requires MCP server/
    );
  });

  it('should throw when elevated capability used with low score', () => {
    assert.throws(
      () => validateCapability('token:issue', { security_score: 50 }),
      /requires security score/
    );
  });

  it('should return capability object for valid capability', () => {
    const cap = validateCapability('token:exchange', { security_score: 50 });
    assert.equal(cap.risk_level, 'medium');
  });

  it('should allow AI capability for AI agent', () => {
    const cap = validateCapability('model:invoke', { is_ai_agent: true });
    assert.equal(cap.risk_level, 'medium');
  });
});

// =============================================================================
// resolveActionFromCapability()
// =============================================================================

describe('resolveActionFromCapability', () => {
  it('should return first action from capability', () => {
    assert.equal(resolveActionFromCapability('token:exchange'), 'token_exchange');
  });

  it('should throw for unknown capability', () => {
    assert.throws(() => resolveActionFromCapability('bogus'), /Unknown capability/);
  });

  it('should resolve credential:issue:aws to credential_issue', () => {
    assert.equal(resolveActionFromCapability('credential:issue:aws'), 'credential_issue');
  });
});
