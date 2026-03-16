// =============================================================================
// Cross-Environment Trace Context — Hub-Spoke Federation
// =============================================================================
//
// When requests traverse multiple spoke environments (e.g., AWS → GCP),
// trace context must propagate the origin relay's identity so audit trails
// show the full cross-environment path.
//
// Headers:
//   X-WID-Trace-Id           — existing trace correlation ID
//   X-WID-Origin-Relay       — SPIFFE ID of the relay where the trace started
//   X-WID-Origin-Environment — environment name of the trace origin
//   X-WID-Relay-SPIFFE-ID    — SPIFFE ID of the current relay
//
// =============================================================================

const HEADER_ORIGIN_RELAY = 'x-wid-origin-relay';
const HEADER_ORIGIN_ENV = 'x-wid-origin-environment';
const HEADER_RELAY_SPIFFE = 'x-wid-relay-spiffe-id';
const HEADER_TRACE_ID = 'x-wid-trace-id';

/**
 * Inject cross-environment trace headers into outbound requests.
 * Called by the edge gateway when proxying requests.
 *
 * @param {Object} existingHeaders - Current request headers
 * @param {string} relaySpiffeId   - This relay's SPIFFE ID
 * @param {string} environmentName - This relay's environment name
 * @returns {Object} Headers to inject
 */
function injectCrossEnvTrace(existingHeaders = {}, relaySpiffeId, environmentName) {
  const headers = {};

  // Always include this relay's identity
  if (relaySpiffeId) {
    headers[HEADER_RELAY_SPIFFE] = relaySpiffeId;
  }

  // If no origin relay is set, this is the originating environment
  if (!existingHeaders[HEADER_ORIGIN_RELAY] && relaySpiffeId) {
    headers[HEADER_ORIGIN_RELAY] = relaySpiffeId;
    headers[HEADER_ORIGIN_ENV] = environmentName || 'unknown';
  }

  return headers;
}

/**
 * Extract cross-environment trace context from incoming request headers.
 * Called by the relay when receiving requests or audit events.
 *
 * @param {Object} headers - Request headers
 * @returns {{ traceId: string|null, originRelaySpiffeId: string|null, originEnvironment: string|null, currentRelaySpiffeId: string|null }}
 */
function extractCrossEnvTrace(headers = {}) {
  return {
    traceId: headers[HEADER_TRACE_ID] || null,
    originRelaySpiffeId: headers[HEADER_ORIGIN_RELAY] || null,
    originEnvironment: headers[HEADER_ORIGIN_ENV] || null,
    currentRelaySpiffeId: headers[HEADER_RELAY_SPIFFE] || null,
  };
}

/**
 * Build audit event metadata for cross-environment traces.
 * Merges trace context into an audit event entry.
 *
 * @param {Object} entry       - Base audit entry
 * @param {string} relaySpiffeId - This relay's SPIFFE ID
 * @param {string} environmentName - This relay's environment name
 * @returns {Object} Enriched audit entry
 */
function enrichAuditWithTraceContext(entry, relaySpiffeId, environmentName) {
  return {
    ...entry,
    relay_spiffe_id: relaySpiffeId || null,
    relay_environment: environmentName || null,
    origin_relay_spiffe_id: entry.origin_relay_spiffe_id || null,
    origin_environment: entry.origin_environment || null,
  };
}

module.exports = {
  injectCrossEnvTrace,
  extractCrossEnvTrace,
  enrichAuditWithTraceContext,
  HEADER_ORIGIN_RELAY,
  HEADER_ORIGIN_ENV,
  HEADER_RELAY_SPIFFE,
  HEADER_TRACE_ID,
};
