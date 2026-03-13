const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  calculateSecurityScore,
  determineTrustLevel,
  applyFindingPenalties,
  TRUST_HIERARCHY,
} = require('../src/utils/security-scorer');

// =============================================================================
// calculateSecurityScore()
// =============================================================================

describe('calculateSecurityScore', () => {
  it('should return base score of 50 for bare-minimum workload', () => {
    assert.equal(calculateSecurityScore({}), 50);
  });

  it('should add 15 for owner', () => {
    assert.equal(calculateSecurityScore({ owner: 'alice' }), 65);
  });

  it('should add 10 for team', () => {
    assert.equal(calculateSecurityScore({ team: 'platform' }), 60);
  });

  it('should add 10 for cost_center', () => {
    assert.equal(calculateSecurityScore({ cost_center: 'CC-001' }), 60);
  });

  it('should add 10 for known environment, 20 for production', () => {
    assert.equal(calculateSecurityScore({ environment: 'staging' }), 60);
    assert.equal(calculateSecurityScore({ environment: 'production' }), 70);
  });

  it('should add trust level bonuses based on TRUST_HIERARCHY index', () => {
    // cryptographic (idx 5) = +15
    const crypto = calculateSecurityScore({ verified: true, trust_level: 'cryptographic' });
    // base(50) + verified(20) + crypto(15) = 85
    assert.equal(crypto, 85);
  });

  it('should apply shadow penalty of -25', () => {
    const score = calculateSecurityScore({ is_shadow: true });
    assert.equal(score, 25);
  });

  it('should apply dormant penalty of -25', () => {
    const score = calculateSecurityScore({ is_dormant: true });
    assert.equal(score, 25);
  });

  it('should clamp to 0 for worst case', () => {
    const score = calculateSecurityScore({ is_shadow: true, is_dormant: true });
    assert.equal(score, 0);
  });

  it('should clamp to 100 for full attribution', () => {
    const full = {
      owner: 'alice',
      team: 'platform',
      cost_center: 'CC-001',
      environment: 'production',
      verified: true,
      trust_level: 'cryptographic',
    };
    assert.equal(calculateSecurityScore(full), 100);
  });
});

// =============================================================================
// determineTrustLevel()
// =============================================================================

describe('determineTrustLevel', () => {
  it('should return cryptographic for gcp-metadata-jwt', () => {
    assert.equal(determineTrustLevel('gcp-metadata-jwt'), 'cryptographic');
  });

  it('should return cryptographic for spiffe-svid', () => {
    assert.equal(determineTrustLevel('spiffe-svid'), 'cryptographic');
  });

  it('should return very-high for aws-imdsv2', () => {
    assert.equal(determineTrustLevel('aws-imdsv2'), 'very-high');
  });

  it('should return high for aws-lambda-context', () => {
    assert.equal(determineTrustLevel('aws-lambda-context'), 'high');
  });

  it('should return medium for k8s-service-account', () => {
    assert.equal(determineTrustLevel('k8s-service-account'), 'medium');
  });

  it('should return low for api', () => {
    assert.equal(determineTrustLevel('api'), 'low');
  });

  it('should return none for unknown method', () => {
    assert.equal(determineTrustLevel('unknown-method'), 'none');
  });
});

// =============================================================================
// applyFindingPenalties()
// =============================================================================

describe('applyFindingPenalties', () => {
  it('should return base score when no findings', () => {
    assert.equal(applyFindingPenalties(80, []), 80);
    assert.equal(applyFindingPenalties(80, null), 80);
  });

  it('should apply critical penalty of -40', () => {
    assert.equal(applyFindingPenalties(80, [{ severity: 'critical' }]), 40);
  });

  it('should apply high penalty of -25', () => {
    assert.equal(applyFindingPenalties(80, [{ severity: 'high' }]), 55);
  });

  it('should apply volume penalty for multiple findings', () => {
    // 3 findings: worst=25(high), volume=(3-1)*3=6, total penalty=31
    const findings = [
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'low' },
    ];
    assert.equal(applyFindingPenalties(80, findings), 49);
  });

  it('should cap volume penalty at 15', () => {
    // 10 findings: worst=5(low), volume=min(15, 9*3)=15, total=20
    const findings = Array.from({ length: 10 }, () => ({ severity: 'low' }));
    assert.equal(applyFindingPenalties(80, findings), 60);
  });

  it('should clamp result to 0', () => {
    assert.equal(applyFindingPenalties(10, [{ severity: 'critical' }]), 0);
  });
});

// =============================================================================
// TRUST_HIERARCHY
// =============================================================================

describe('TRUST_HIERARCHY', () => {
  it('should have 6 levels in order', () => {
    assert.deepEqual(TRUST_HIERARCHY, ['none', 'low', 'medium', 'high', 'very-high', 'cryptographic']);
  });
});
