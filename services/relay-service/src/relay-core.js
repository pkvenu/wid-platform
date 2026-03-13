// =============================================================================
// Relay Core — Extracted pure functions for testability
// =============================================================================

/**
 * Match a workload against a pattern (used in policy evaluation).
 * Returns true if pattern is wildcard, or if principal/name contains the pattern.
 */
function matchWorkload(principal, name, pattern) {
  if (pattern === '*') return true;
  if (principal && principal.includes(pattern)) return true;
  if (name && name.includes(pattern)) return true;
  return false;
}

/**
 * Evaluate a request against cached policies.
 * Returns the first matching enabled policy, or null.
 */
function evaluateCachedPolicies(request, policies) {
  for (const policy of policies) {
    if (!policy.enabled) continue;

    const srcMatch = !policy.source_match || matchWorkload(request.source_principal, request.source_name, policy.source_match);
    const dstMatch = !policy.destination_match || matchWorkload(request.destination_principal, request.destination_name, policy.destination_match);

    if (srcMatch && dstMatch) {
      return policy;
    }
  }
  return null;
}

/**
 * Create an audit buffer with max size, enrichment, and flush.
 * @param {number} maxSize - Maximum buffer size before dropping events
 * @param {string} relayId - Relay identifier for enrichment
 * @returns {{ append, flush, stats }} Audit buffer interface
 */
function createAuditBuffer(maxSize, relayId) {
  const buffer = [];
  let dropped = 0;
  let flushed = 0;

  return {
    append(event) {
      if (buffer.length >= maxSize) {
        dropped++;
        return false;
      }
      buffer.push({
        ...event,
        relay_id: relayId,
        buffered_at: new Date().toISOString(),
      });
      return true;
    },

    flush() {
      const events = buffer.splice(0);
      flushed += events.length;
      return events;
    },

    stats() {
      return {
        buffered: buffer.length,
        flushed,
        dropped,
      };
    },

    get length() {
      return buffer.length;
    },
  };
}

/**
 * Parse relay CONFIG from environment variables.
 * Extracted for testability.
 */
function parseConfig(env = {}) {
  return {
    port:              parseInt(env.PORT || '3005'),
    envName:           env.ENVIRONMENT_NAME || 'local',
    envType:           env.ENVIRONMENT_TYPE || 'docker',
    region:            env.REGION || 'local',
    clusterId:         env.CLUSTER_ID || 'local-docker',
    centralUrl:        env.CENTRAL_CONTROL_PLANE_URL || '',
    centralApiKey:     env.CENTRAL_API_KEY || '',
    policySyncIntervalMs:  parseInt(env.POLICY_SYNC_INTERVAL_MS || '30000'),
    auditFlushIntervalMs:  parseInt(env.AUDIT_FLUSH_INTERVAL_MS || '10000'),
    auditBatchSize:        parseInt(env.AUDIT_BATCH_SIZE || '100'),
    maxAuditBufferSize:    parseInt(env.MAX_AUDIT_BUFFER_SIZE || '10000'),
    syncTimeoutMs:         parseInt(env.SYNC_TIMEOUT_MS || '5000'),
    localAdapters:         (env.LOCAL_ADAPTERS || '').split(',').filter(Boolean),
  };
}

module.exports = {
  matchWorkload,
  evaluateCachedPolicies,
  createAuditBuffer,
  parseConfig,
};
