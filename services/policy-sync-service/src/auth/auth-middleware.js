// =============================================================================
// Auth Middleware — JWT cookie verification for protected routes
// =============================================================================

const jwt = require('jsonwebtoken');
const { JWT_SECRET, COOKIE_NAME } = require('./auth-routes');

// Paths that do NOT require authentication
const PUBLIC_PATHS = [
  '/health',
  '/api/v1/auth/',
  '/api/v1/relay/',          // Internal spoke-to-hub traffic
  '/api/v1/gateway/evaluate', // Edge gateway calls (authenticated via mTLS/tokens)
];

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
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      res.clearCookie(COOKIE_NAME, { path: '/' });
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = { requireAuth };
