// =============================================================================
// Rate Limiting Middleware — Shared across all Express services
// =============================================================================
// Production hardening (P2.6): sliding window counter with in-memory Map.
// No external dependencies. Mount AFTER cors but BEFORE routes.
//
// Exports:
//   rateLimiter(opts)   — generic rate limiter factory
//   authRateLimiter()   — strict 10 req/min per IP (login/register)
//   apiRateLimiter()    — 300 req/min per tenant (general API)
// =============================================================================

'use strict';

/**
 * Creates a rate limiter Express middleware.
 *
 * @param {Object} [opts]
 * @param {number} [opts.windowMs=60000]     - Sliding window duration in ms
 * @param {number} [opts.maxRequests=100]     - Max requests per window per key
 * @param {Function} [opts.keyExtractor]      - (req) => string — key for grouping
 * @returns {Function} Express middleware
 */
function rateLimiter(opts = {}) {
  const windowMs = opts.windowMs || 60000;
  const maxRequests = opts.maxRequests || 100;
  const keyExtractor = opts.keyExtractor || defaultKeyExtractor;

  // Sliding window counters: key -> { count, resetAt }
  const windows = new Map();

  // Periodic cleanup of expired windows (every 60s)
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of windows) {
      if (now > entry.resetAt) {
        windows.delete(key);
      }
    }
  }, 60000);
  // Allow process to exit without waiting for cleanup
  if (cleanupInterval.unref) cleanupInterval.unref();

  return function rateLimitMiddleware(req, res, next) {
    const key = keyExtractor(req);
    const now = Date.now();

    let entry = windows.get(key);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      windows.set(key, entry);
    }

    entry.count++;

    const remaining = Math.max(0, maxRequests - entry.count);
    const resetEpochSeconds = Math.ceil(entry.resetAt / 1000);

    // Always set rate limit headers
    res.setHeader('X-RateLimit-Limit', String(maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(resetEpochSeconds));

    if (entry.count > maxRequests) {
      const retryAfterSeconds = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Try again in ${retryAfterSeconds}s.`,
        retry_after: retryAfterSeconds,
      });
    }

    next();
  };
}

/**
 * Default key extractor: uses client IP address.
 */
function defaultKeyExtractor(req) {
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

/**
 * Extract tenant ID from JWT in cookie or Authorization header.
 * Falls back to IP if no tenant can be determined.
 */
function tenantKeyExtractor(req) {
  // Try wid_token cookie (used by policy-sync-service auth)
  try {
    const cookie = req.cookies?.wid_token;
    if (cookie) {
      // Decode without verifying (rate limiter only needs the claim for grouping)
      const parts = cookie.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.tenantId) return `tenant:${payload.tenantId}`;
      }
    }
  } catch { /* fall through */ }

  // Try Authorization header
  try {
    const auth = req.headers?.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      const token = auth.substring(7);
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.tenantId) return `tenant:${payload.tenantId}`;
      }
    }
  } catch { /* fall through */ }

  // Fallback to IP
  return `ip:${req.ip || req.connection?.remoteAddress || 'unknown'}`;
}

/**
 * Strict rate limiter for auth endpoints: 10 req/min per IP.
 */
function authRateLimiter() {
  return rateLimiter({
    windowMs: 60000,
    maxRequests: 10,
    keyExtractor: defaultKeyExtractor,
  });
}

/**
 * General API rate limiter: 300 req/min per tenant.
 */
function apiRateLimiter() {
  return rateLimiter({
    windowMs: 60000,
    maxRequests: 300,
    keyExtractor: tenantKeyExtractor,
  });
}

module.exports = {
  rateLimiter,
  authRateLimiter,
  apiRateLimiter,
};
