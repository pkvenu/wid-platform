// =============================================================================
// Tenant-Scoped Database Access — Defense Layer 1 (Application)
// =============================================================================
//
// Wraps every DB query in a transaction that sets the PostgreSQL session
// variable `app.tenant_id`. This enables RLS policies to filter rows
// automatically — routes never need manual WHERE tenant_id = $N.
//
// Usage:
//   const { createTenantPool, tenantQuery, systemQuery } = require('../../shared/tenant-db');
//   const pool = createTenantPool();
//
//   // Tenant-scoped (RLS filters automatically):
//   const rows = await tenantQuery(pool, req.tenantId, 'SELECT * FROM workloads');
//
//   // System-level (bypasses RLS, use sparingly):
//   const tenants = await systemQuery(pool, 'SELECT * FROM tenants');
// =============================================================================

const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wid_user:wip_password@postgres:5432/workload_identity';

/**
 * Create a connection pool. Call once per service at startup.
 * Pool handles connection reuse, queueing, and cleanup.
 */
function createTenantPool(opts = {}) {
  return new Pool({
    connectionString: DATABASE_URL,
    max: opts.max || 20,                 // max connections in pool
    idleTimeoutMillis: opts.idleTimeout || 30000,
    connectionTimeoutMillis: opts.connectionTimeout || 5000,
    ...opts,
  });
}

/**
 * Execute a query scoped to a specific tenant.
 * Sets `app.tenant_id` via SET LOCAL (transaction-scoped, safe for pooling).
 *
 * @param {Pool} pool - pg Pool instance
 * @param {string} tenantId - UUID of the tenant
 * @param {string} text - SQL query
 * @param {Array} params - Query parameters
 * @returns {import('pg').QueryResult}
 */
async function tenantQuery(pool, tenantId, text, params = []) {
  if (!tenantId) {
    throw new Error('tenantQuery requires a tenantId');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // SET LOCAL is transaction-scoped — automatically cleared on COMMIT/ROLLBACK.
    // Safe for connection pooling (no state leak between requests).
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [tenantId]);
    const result = await client.query(text, params);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Execute multiple queries in a single tenant-scoped transaction.
 * All queries see the same tenant context and share one transaction.
 *
 * @param {Pool} pool - pg Pool instance
 * @param {string} tenantId - UUID of the tenant
 * @param {Function} fn - async function receiving (client) to run queries
 * @returns {*} Whatever fn returns
 */
async function tenantTransaction(pool, tenantId, fn) {
  if (!tenantId) {
    throw new Error('tenantTransaction requires a tenantId');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [tenantId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Execute a system-level query (no tenant context).
 * Used for: tenant creation, cross-tenant admin operations, health checks.
 * RLS is bypassed IF the pool connects as the table owner (wid_user).
 *
 * @param {Pool} pool - pg Pool instance
 * @param {string} text - SQL query
 * @param {Array} params - Query parameters
 * @returns {import('pg').QueryResult}
 */
async function systemQuery(pool, text, params = []) {
  return pool.query(text, params);
}

module.exports = {
  createTenantPool,
  tenantQuery,
  tenantTransaction,
  systemQuery,
};
