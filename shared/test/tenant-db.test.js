// =============================================================================
// Tests: Tenant DB Module — unit tests without DB connection
// =============================================================================

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

describe('tenant-db', () => {
  describe('tenantQuery', () => {
    it('should throw if no tenantId', async () => {
      // Import the real module (no DB connection needed for validation tests)
      const { tenantQuery } = require('../tenant-db');

      // Create a mock pool
      const mockPool = {
        connect: async () => ({
          query: async () => ({ rows: [] }),
          release: () => {},
        }),
      };

      await assert.rejects(
        () => tenantQuery(mockPool, null, 'SELECT 1'),
        /tenantQuery requires a tenantId/
      );
    });

    it('should throw if empty string tenantId', async () => {
      const { tenantQuery } = require('../tenant-db');
      const mockPool = {
        connect: async () => ({
          query: async () => ({ rows: [] }),
          release: () => {},
        }),
      };

      await assert.rejects(
        () => tenantQuery(mockPool, '', 'SELECT 1'),
        /tenantQuery requires a tenantId/
      );
    });

    it('should execute BEGIN, set_config, query, COMMIT sequence', async () => {
      const { tenantQuery } = require('../tenant-db');
      const queries = [];
      const mockClient = {
        query: async (text, params) => {
          queries.push({ text, params });
          return { rows: [{ id: 1 }], rowCount: 1 };
        },
        release: () => {},
      };
      const mockPool = { connect: async () => mockClient };

      const tenantId = '00000000-0000-0000-0000-000000000001';
      const result = await tenantQuery(mockPool, tenantId, 'SELECT * FROM workloads WHERE id = $1', ['abc']);

      assert.equal(queries.length, 4);
      assert.equal(queries[0].text, 'BEGIN');
      assert.ok(queries[1].text.includes('set_config'));
      assert.deepEqual(queries[1].params, [tenantId]);
      assert.equal(queries[2].text, 'SELECT * FROM workloads WHERE id = $1');
      assert.deepEqual(queries[2].params, ['abc']);
      assert.equal(queries[3].text, 'COMMIT');
      assert.equal(result.rows[0].id, 1);
    });

    it('should ROLLBACK on query error and release client', async () => {
      const { tenantQuery } = require('../tenant-db');
      const queries = [];
      let released = false;
      const mockClient = {
        query: async (text, params) => {
          queries.push({ text, params });
          if (text.startsWith('SELECT')) throw new Error('query failed');
          return { rows: [] };
        },
        release: () => { released = true; },
      };
      const mockPool = { connect: async () => mockClient };

      await assert.rejects(
        () => tenantQuery(mockPool, 'tid', 'SELECT 1'),
        /query failed/
      );

      assert.ok(queries.some(q => q.text === 'ROLLBACK'), 'Should ROLLBACK on error');
      assert.ok(released, 'Should release client on error');
    });
  });

  describe('tenantTransaction', () => {
    it('should throw if no tenantId', async () => {
      const { tenantTransaction } = require('../tenant-db');
      const mockPool = { connect: async () => ({ query: async () => ({}), release: () => {} }) };

      await assert.rejects(
        () => tenantTransaction(mockPool, null, async () => {}),
        /tenantTransaction requires a tenantId/
      );
    });

    it('should execute function within tenant context and return result', async () => {
      const { tenantTransaction } = require('../tenant-db');
      const queries = [];
      const mockClient = {
        query: async (text, params) => {
          queries.push({ text });
          return { rows: [{ count: 5 }] };
        },
        release: () => {},
      };
      const mockPool = { connect: async () => mockClient };

      const result = await tenantTransaction(mockPool, 'tid', async (client) => {
        const r = await client.query('INSERT INTO users (name) VALUES ($1)', ['test']);
        return 'inserted';
      });

      assert.equal(result, 'inserted');
      assert.equal(queries[0].text, 'BEGIN');
      assert.ok(queries[1].text.includes('set_config'));
      assert.equal(queries[queries.length - 1].text, 'COMMIT');
    });
  });

  describe('systemQuery', () => {
    it('should execute directly on pool', async () => {
      const { systemQuery } = require('../tenant-db');
      let called = false;
      const mockPool = {
        query: async (text, params) => {
          called = true;
          assert.equal(text, 'SELECT * FROM tenants');
          return { rows: [{ id: 't1' }] };
        },
      };

      const result = await systemQuery(mockPool, 'SELECT * FROM tenants');
      assert.ok(called);
      assert.equal(result.rows[0].id, 't1');
    });
  });
});
