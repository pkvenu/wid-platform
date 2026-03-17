// =============================================================================
// Security Headers Middleware — Shared across all Express services
// =============================================================================
// Production hardening (P2.6): standard security headers with zero dependencies.
// Mount BEFORE cors middleware so headers are set on every response including
// preflight and error responses.
// =============================================================================

'use strict';

const DEFAULTS = {
  hsts: true,
  csp: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' *",
};

/**
 * Returns Express middleware that sets security response headers.
 *
 * @param {Object} [opts]
 * @param {string} [opts.csp]  - Custom Content-Security-Policy value
 * @param {boolean} [opts.hsts] - Whether to set Strict-Transport-Security (default true)
 * @returns {Function} Express middleware
 */
function securityHeaders(opts = {}) {
  const csp = opts.csp || DEFAULTS.csp;
  const hsts = opts.hsts !== undefined ? opts.hsts : DEFAULTS.hsts;

  return function securityHeadersMiddleware(req, res, next) {
    // HSTS — only meaningful over HTTPS but safe to set unconditionally
    if (hsts) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    // Prevent MIME-type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Prevent framing (clickjacking protection)
    res.setHeader('X-Frame-Options', 'DENY');

    // Disable legacy XSS filter (can cause more harm than good in modern browsers)
    res.setHeader('X-XSS-Protection', '0');

    // Content Security Policy
    res.setHeader('Content-Security-Policy', csp);

    // Referrer policy — send origin only on cross-origin, full on same-origin
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions policy — disable sensitive browser APIs
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    next();
  };
}

module.exports = securityHeaders;
module.exports.securityHeaders = securityHeaders;
