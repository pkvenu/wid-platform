// =============================================================================
// Security Scorer - Calculate security scores for workloads
// =============================================================================

// Trust level hierarchy (lowest → highest)
const TRUST_HIERARCHY = ['none', 'low', 'medium', 'high', 'very-high', 'cryptographic'];

/**
 * Calculate security score for a workload
 * @param {Object} workload - Workload object
 * @returns {number} Security score (0-100)
 */
function calculateSecurityScore(workload) {
  let score = 50; // Base score

  // Ownership factors (+35 max)
  if (workload.owner) score += 15;
  if (workload.team) score += 10;
  if (workload.cost_center) score += 10;

  // Environment factors (+20 max)
  if (workload.environment && workload.environment !== 'unknown') score += 10;
  if (workload.environment === 'production') score += 10;

  // Identity trust factors (+35 max — scale by trust level)
  if (workload.verified) score += 20;
  const trustIdx = TRUST_HIERARCHY.indexOf(workload.trust_level || 'none');
  if (trustIdx >= 5) score += 15;        // cryptographic
  else if (trustIdx >= 3) score += 10;   // high or very-high
  else if (trustIdx >= 2) score += 5;    // medium

  // Shadow/Dormant penalties (-50 max)
  if (workload.is_shadow) score -= 25;
  if (workload.is_dormant) score -= 25;

  // Ensure score is between 0-100
  return Math.max(0, Math.min(100, score));
}

/**
 * Determine trust level based on verification method.
 * 'cryptographic' = hardware-backed or SPIFFE SVID verified identity.
 * Aligns with UI TRUST_COLORS which includes the cryptographic tier.
 * @param {string} verificationMethod - Verification method
 * @returns {string} Trust level
 */
function determineTrustLevel(verificationMethod) {
  const trustLevels = {
    // Cryptographic — hardware attestation or SPIFFE-verified
    'gcp-metadata-jwt': 'cryptographic',   // GCP signed instance identity JWT
    'aws-imdsv2-tpm': 'cryptographic',      // IMDSv2 with TPM attestation
    'spiffe-svid': 'cryptographic',         // SPIFFE X.509 SVID
    // Very-high — platform-managed identity with strong verification
    'aws-imdsv2': 'very-high',
    'aws-ecs-task-role': 'very-high',
    'aws-lambda-context': 'high',
    'gcp-metadata': 'high',
    'azure-msi': 'high',
    'k8s-service-account': 'medium',
    'catalog-match': 'medium',
    'manual-approval': 'low',
    'api': 'low',
  };

  return trustLevels[verificationMethod] || 'none';
}

// ── Finding-based score penalties ──────────────────────────────────────────
const FINDING_PENALTIES = {
  critical: 40, high: 25, medium: 15, low: 5, info: 0,
};

/**
 * Adjust a governance-based score downward based on security findings.
 * Takes the worst single-finding penalty plus a volume penalty for multiple findings.
 * @param {number} baseScore - Governance score (0-100)
 * @param {Array} findings - Array of { severity: 'critical'|'high'|'medium'|'low'|'info' }
 * @returns {number} Adjusted score (0-100)
 */
function applyFindingPenalties(baseScore, findings) {
  if (!findings || findings.length === 0) return baseScore;
  const worstPenalty = findings.reduce((worst, f) => {
    const p = FINDING_PENALTIES[f.severity] || 0;
    return p > worst ? p : worst;
  }, 0);
  const volumePenalty = Math.min(15, (findings.length - 1) * 3);
  return Math.max(0, Math.min(100, baseScore - worstPenalty - volumePenalty));
}

module.exports = {
  calculateSecurityScore,
  determineTrustLevel,
  applyFindingPenalties,
  TRUST_HIERARCHY,
};
