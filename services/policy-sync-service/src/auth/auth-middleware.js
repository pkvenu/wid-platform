// =============================================================================
// Auth Middleware — JWT cookie verification with tenant context
// =============================================================================

const jwt = require('jsonwebtoken');
const { JWT_SECRET, COOKIE_NAME } = require('./auth-routes');
const { tenantDb: { tenantQuery, systemQuery } } = require('../shared-loader');

// Paths that do NOT require authentication
const PUBLIC_PATHS = [
  '/health',
  '/api/v1/auth/',
  '/api/v1/relay/',          // Internal spoke-to-hub traffic
  '/api/v1/gateway/evaluate', // Edge gateway calls (authenticated via mTLS/tokens)
];

// Default tenant for backwards compatibility during migration
const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

function requireAuth(req, res, next) {
  // Skip auth for public paths
  const path = req.path;
  if (PUBLIC_PATHS.some(p => path === p || path.startsWith(p))) {
    return next();
  }

  // Also skip OPTIONS (CORS preflight)
  if (req.method === 'OPTIONS') {
    return next();
  }

  const token = req.cookies?.[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    // Set tenantId — fall back to default for pre-migration JWTs
    req.tenantId = decoded.tenantId || DEFAULT_TENANT_ID;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      res.clearCookie(COOKIE_NAME, { path: '/' });
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/**
 * Creates a tenant-scoped database proxy that wraps a pool.
 * Attaches `req.db` with a `.query()` method that automatically
 * scopes all queries to the request's tenant via RLS.
 *
 * Usage in routes: `const result = await req.db.query('SELECT ...', [params])`
 *
 * For system-level queries (no tenant scope): use pool directly.
 */
function attachTenantDb(pool) {
  return (req, res, next) => {
    const tid = req.tenantId || DEFAULT_TENANT_ID;
    req.db = {
      query: (text, params) => tenantQuery(pool, tid, text, params),
    };
    // Also expose system-level query for relay/gateway endpoints
    req.systemDb = {
      query: (text, params) => systemQuery(pool, text, params),
    };
    next();
  };
}

module.exports = { requireAuth, attachTenantDb };
