// =============================================================================
// Tests: Tenant Middleware — requireTenant, enforceTenantLimit, data residency
// =============================================================================

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// We can test the middleware with mock pools since it uses systemQuery internally
const { requireTenant, enforceTenantLimit, enforceDataResidency, invalidateTenantCache } = require('../tenant-middleware');

function mockRes() {
  const res = {
    statusCode: 200,
    body: null,
    status(code) { res.statusCode = code; return res; },
    json(data) { res.body = data; },
  };
  return res;
}

describe('tenant-middleware', () => {
  beforeEach(() => {
    // Clear tenant cache between tests
    invalidateTenantCache('t1');
    invalidateTenantCache('t2');
  });

  describe('requireTenant', () => {
    it('should return 403 if no tenantId in user', async () => {
      const pool = {};
      const middleware = requireTenant(pool);
      const req = { user: { userId: 'u1' } };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });

      assert.equal(res.statusCode, 403);
      assert.ok(res.body.error.includes('No tenant context'));
      assert.equal(nextCalled, false);
    });

    it('should return 403 if tenant not found', async () => {
      const pool = {};
      const tenantDb = require('../tenant-db');
      const origSysQuery = tenantDb.systemQuery;
      tenantDb.systemQuery = async () => ({ rows: [] });

      const middleware = requireTenant(pool);
      const req = { user: { tenantId: 't2' } };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });

      assert.equal(res.statusCode, 403);
      assert.equal(nextCalled, false);

      tenantDb.systemQuery = origSysQuery;
    });

    it('should set req.tenant and call next if tenant exists', async () => {
      const tenant = { id: 't1', name: 'Test', slug: 'test', plan: 'trial' };
      const tenantDb = require('../tenant-db');
      tenantDb.systemQuery = async () => ({ rows: [tenant] });
      invalidateTenantCache('t1');

      const pool = {};
      const middleware = requireTenant(pool);
      const req = { user: { tenantId: 't1' } };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });

      assert.equal(nextCalled, true);
      assert.equal(req.tenantId, 't1');
      assert.deepEqual(req.tenant, tenant);
    });
  });

  describe('enforceDataResidency', () => {
    it('should pass through if no strict residency', async () => {
      const middleware = enforceDataResidency({});
      const req = { tenant: { data_residency_strict: false }, headers: {} };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, true);
    });

    it('should pass through if no tenant on request', async () => {
      const middleware = enforceDataResidency({});
      const req = { headers: {} };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, true);
    });

    it('should block wrong region', async () => {
      const middleware = enforceDataResidency({});
      const req = {
        tenant: { slug: 'eu-co', data_residency_strict: true, allowed_regions: ['eu'] },
        headers: { 'x-wid-region': 'us' },
      };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });

      assert.equal(res.statusCode, 403);
      assert.ok(res.body.error.includes('Data residency violation'));
      assert.equal(nextCalled, false);
    });

    it('should allow correct region', async () => {
      const middleware = enforceDataResidency({});
      const req = {
        tenant: { slug: 'eu-co', data_residency_strict: true, allowed_regions: ['eu'] },
        headers: { 'x-wid-region': 'eu' },
      };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, true);
    });

    it('should allow if no region header sent', async () => {
      const middleware = enforceDataResidency({});
      const req = {
        tenant: { slug: 'eu-co', data_residency_strict: true, allowed_regions: ['eu'] },
        headers: {},
      };
      const res = mockRes();
      let nextCalled = false;

      await middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, true);
    });
  });
});
