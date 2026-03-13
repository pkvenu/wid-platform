// =============================================================================
// Token Service Utilities — Extracted for testability
// =============================================================================

const { AUTH_METHODS } = require('./canonical-nhi-context');

/**
 * Determine authentication method from request.
 * Priority: mTLS > Bearer token > API key (default)
 */
function determineAuthMethod(req) {
  const clientCert = req.socket?.getPeerCertificate?.();
  if (clientCert && clientCert.subject) {
    return AUTH_METHODS.MTLS;
  }

  if (req.headers?.authorization?.startsWith('Bearer ')) {
    return AUTH_METHODS.OIDC;
  }

  return AUTH_METHODS.API_KEY;
}

/**
 * Generate a unique request ID.
 * Format: req-{timestamp}-{random}
 */
function generateRequestId() {
  return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Generate a unique JWT ID (jti).
 * Format: jti-{timestamp}-{random}
 */
function generateJTI() {
  return `jti-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Extract SPIFFE ID from a client certificate's Subject Alternative Names.
 * Looks for URI SAN matching spiffe:// prefix.
 */
function extractSpiffeIdFromCert(cert) {
  if (cert?.subjectaltname) {
    const match = cert.subjectaltname.match(/URI:spiffe:\/\/[^,]+/);
    if (match) {
      return match[0].replace('URI:', '');
    }
  }
  return null;
}

module.exports = {
  determineAuthMethod,
  generateRequestId,
  generateJTI,
  extractSpiffeIdFromCert,
};
