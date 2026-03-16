// =============================================================================
// Tenant Middleware — Extract & Enforce Tenant Context
// =============================================================================
//
// Sits after auth middleware. Extracts tenant_id from JWT, sets req.tenantId,
// and optionally enforces tenant plan limits.
//
// Usage:
//   app.use(requireAuth);       // sets req.user = { userId, email, role, tenantId }
//   app.use(requireTenant);     // sets req.tenantId, enforces tenant exists
// =============================================================================

const tenantDb = require('./tenant-db');

// In-memory tenant cache (TTL-based, per-process)
const tenantCache = new Map();
const TENANT_CACHE_TTL = 60_000; // 1 minute

/**
 * Middleware: require valid tenant context on every request.
 * Extracts tenantId from JWT (set by auth middleware).
 */
function requireTenant(pool) {
  return async (req, res, next) => {
    const tenantId = req.user?.tenantId;

    if (!tenantId) {
      return res.status(403).json({ error: 'No tenant context in token' });
    }

    // Validate tenant exists (cached)
    const tenant = await getCachedTenant(pool, tenantId);
    if (!tenant) {
      return res.status(403).json({ error: 'Tenant not found or disabled' });
    }

    req.tenantId = tenantId;
    req.tenant = tenant;
    next();
  };
}

/**
 * Get tenant with short-lived cache to avoid DB hit per request.
 */
async function getCachedTenant(pool, tenantId) {
  const cached = tenantCache.get(tenantId);
  if (cached && Date.now() - cached.ts < TENANT_CACHE_TTL) {
    return cached.data;
  }

  try {
    const { rows } = await tenantDb.systemQuery(pool, 'SELECT * FROM tenants WHERE id = $1', [tenantId]);
    if (rows.length === 0) return null;

    tenantCache.set(tenantId, { data: rows[0], ts: Date.now() });
    return rows[0];
  } catch {
    return null;
  }
}

/**
 * Middleware: enforce tenant plan limits before resource creation.
 * Usage: app.post('/api/v1/connectors', enforceTenantLimit('connector'), handler)
 */
function enforceTenantLimit(resourceType) {
  const limitMap = {
    user: 'max_users',
    workload: 'max_workloads',
    connector: 'max_connectors',
    policy: 'max_policies',
  };
  const usageMap = {
    user: 'user_count',
    workload: 'workload_count',
    connector: 'connector_count',
    policy: 'policy_count',
  };

  return async (req, res, next) => {
    const tenant = req.tenant;
    if (!tenant) return next(); // requireTenant should run first

    const limitCol = limitMap[resourceType];
    const usageCol = usageMap[resourceType];

    if (!limitCol || !usageCol) return next();

    try {
      const { rows } = await tenantDb.systemQuery(
        req.app.locals.pool,
        'SELECT ' + usageCol + ' FROM tenant_usage WHERE tenant_id = $1',
        [req.tenantId]
      );
      const current = rows[0]?.[usageCol] || 0;
      const limit = tenant[limitCol];

      if (current >= limit) {
        return res.status(429).json({
          error: `${resourceType} limit reached`,
          current,
          limit,
          plan: tenant.plan,
          upgrade: 'Contact sales to increase limits',
        });
      }
      next();
    } catch {
      next(); // Don't block on usage check failure
    }
  };
}

/**
 * Middleware: enforce data sovereignty — reject if request targets wrong region.
 */
function enforceDataResidency(pool) {
  return async (req, res, next) => {
    const tenant = req.tenant;
    if (!tenant || !tenant.data_residency_strict) return next();

    // Check if relay/spoke is in allowed region
    const requestRegion = req.headers['x-wid-region'] || req.headers['x-relay-region'];
    if (requestRegion && !tenant.allowed_regions.includes(requestRegion)) {
      console.warn(`[sovereignty] Blocked: tenant ${tenant.slug} restricted to ${tenant.allowed_regions}, got ${requestRegion}`);
      return res.status(403).json({
        error: 'Data residency violation',
        allowed_regions: tenant.allowed_regions,
        request_region: requestRegion,
      });
    }
    next();
  };
}

/**
 * Clear tenant cache entry (call after tenant settings change).
 */
function invalidateTenantCache(tenantId) {
  tenantCache.delete(tenantId);
}

module.exports = {
  requireTenant,
  enforceTenantLimit,
  enforceDataResidency,
  invalidateTenantCache,
  getCachedTenant,
};
