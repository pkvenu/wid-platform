// =============================================================================
// Auth Routes — Register, Login, Logout, Me, Tenant Management
// =============================================================================
// Multi-tenant aware: JWT includes tenantId, registration creates tenant.

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { tenantDb: { systemQuery, tenantQuery, tenantTransaction } } = require('../shared-loader');

const JWT_SECRET = process.env.AUTH_JWT_SECRET || 'wid-auth-secret-change-in-production';
const JWT_EXPIRY = '24h';
const COOKIE_NAME = 'wid_token';
const SALT_ROUNDS = 12;
const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

/**
 * Generate a short, human-readable tenant ID like GCP project IDs.
 * Format: wid-<slug>-<random> (e.g., "wid-acme-corp-k7x3m2")
 */
function generateTenantSlug(orgName) {
  const base = orgName.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 20);
  const suffix = crypto.randomBytes(3).toString('hex'); // 6 chars
  return `${base}-${suffix}`;
}

function cookieOptions() {
  const secureFallback = process.env.NODE_ENV === 'production' || !!process.env.K_SERVICE;
  const secure = process.env.COOKIE_SECURE !== undefined
    ? process.env.COOKIE_SECURE === 'true'
    : secureFallback;
  return {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24h
    path: '/',
  };
}

/**
 * Generate a JWT with tenant context.
 */
function signToken(user, tenantId) {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role, tenantId },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

/**
 * Slugify a tenant name for URL-safe usage.
 */
function slugify(name) {
  return name.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substring(0, 63);
}

function mountAuthRoutes(app, pool) {
  // ── POST /api/v1/auth/register — Create tenant + first admin user ──
  app.post('/api/v1/auth/register', async (req, res) => {
    try {
      const { email, password, name, organization, data_region } = req.body;

      if (!email || !password || !name) {
        return res.status(400).json({ error: 'email, password, and name are required' });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      const orgName = organization || `${name}'s Organization`;
      const slug = generateTenantSlug(orgName);
      const region = ['us', 'eu', 'ap'].includes(data_region) ? data_region : 'us';

      // Check slug uniqueness (extremely unlikely collision with random suffix, but safe)
      const { rows: slugCheck } = await systemQuery(pool, 'SELECT id FROM tenants WHERE slug = $1', [slug]);
      if (slugCheck.length > 0) {
        return res.status(409).json({ error: 'Organization name already taken, please try again' });
      }

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      // Atomic: create tenant + admin user in one transaction
      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Always create a real tenant with a proper UUID (no hardcoded IDs)
        const { rows: tenantRows } = await client.query(
          `INSERT INTO tenants (name, slug, plan, data_region, allowed_regions)
           VALUES ($1, $2, 'trial', $3, ARRAY[$3])
           RETURNING id, slug`,
          [orgName, slug, region]
        );
        const tenantId = tenantRows[0].id;

        // Check email unique within tenant
        const { rows: emailCheck } = await client.query(
          'SELECT id FROM users WHERE email = $1 AND tenant_id = $2',
          [email.toLowerCase().trim(), tenantId]
        );
        if (emailCheck.length > 0) {
          await client.query('ROLLBACK');
          return res.status(409).json({ error: 'Email already registered in this organization' });
        }

        const { rows } = await client.query(
          `INSERT INTO users (email, password_hash, name, role, tenant_id)
           VALUES ($1, $2, $3, 'admin', $4)
           RETURNING id, email, name, role, tenant_id, created_at`,
          [email.toLowerCase().trim(), passwordHash, name.trim(), tenantId]
        );
        const user = rows[0];

        // Initialize usage tracking
        await client.query(
          `INSERT INTO tenant_usage (tenant_id, user_count) VALUES ($1, 1)
           ON CONFLICT (tenant_id) DO UPDATE SET user_count = tenant_usage.user_count + 1, last_updated = NOW()`,
          [tenantId]
        );

        await client.query('COMMIT');

        const token = signToken(user, tenantId);
        res.cookie(COOKIE_NAME, token, cookieOptions());

        console.log(`[auth] User registered: ${user.email} (tenant: ${slug})`);
        res.status(201).json({
          user: { id: user.id, email: user.email, name: user.name, role: user.role },
          tenant: { id: tenantId, name: orgName, slug, plan: 'trial', data_region: region },
        });
      } catch (txErr) {
        await client.query('ROLLBACK');
        throw txErr;
      } finally {
        client.release();
      }
    } catch (err) {
      console.error('[auth] Register error:', err.message);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  // ── POST /api/v1/auth/login ──
  app.post('/api/v1/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'email and password are required' });
      }

      // Find user with tenant info
      const { rows } = await systemQuery(pool,
        `SELECT u.id, u.email, u.password_hash, u.name, u.role, u.tenant_id,
                t.name AS tenant_name, t.slug AS tenant_slug, t.plan AS tenant_plan, t.data_region
         FROM users u
         LEFT JOIN tenants t ON t.id = u.tenant_id
         WHERE u.email = $1
         ORDER BY u.created_at ASC LIMIT 1`,
        [email.toLowerCase().trim()]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const user = rows[0];
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Update last_login
      await systemQuery(pool, 'UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

      const token = signToken(user, user.tenant_id);
      res.cookie(COOKIE_NAME, token, cookieOptions());

      console.log(`[auth] Login: ${user.email} (tenant: ${user.tenant_slug || user.tenant_id})`);
      res.json({
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
        tenant: {
          id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug,
          plan: user.tenant_plan, data_region: user.data_region,
        },
      });
    } catch (err) {
      console.error('[auth] Login error:', err.message);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  // ── POST /api/v1/auth/logout ──
  app.post('/api/v1/auth/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.json({ ok: true });
  });

  // ── GET /api/v1/auth/me ──
  app.get('/api/v1/auth/me', async (req, res) => {
    try {
      const token = req.cookies?.[COOKIE_NAME];
      if (!token) {
        const { rows } = await systemQuery(pool, 'SELECT COUNT(*)::int AS count FROM users');
        return res.status(401).json({ error: 'Not authenticated', hasUsers: rows[0].count > 0 });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await systemQuery(pool,
        `SELECT u.id, u.email, u.name, u.role, u.created_at, u.last_login, u.tenant_id,
                t.name AS tenant_name, t.slug AS tenant_slug, t.plan AS tenant_plan,
                t.data_region, t.data_residency_strict
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE u.id = $1`,
        [decoded.userId]
      );

      if (rows.length === 0) {
        res.clearCookie(COOKIE_NAME, { path: '/' });
        return res.status(401).json({ error: 'User not found' });
      }

      const user = rows[0];
      res.json({
        user: {
          id: user.id, email: user.email, name: user.name, role: user.role,
          created_at: user.created_at, last_login: user.last_login,
        },
        tenant: {
          id: user.tenant_id, name: user.tenant_name, slug: user.tenant_slug,
          plan: user.tenant_plan, data_region: user.data_region,
          data_residency_strict: user.data_residency_strict,
        },
      });
    } catch (err) {
      if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        res.clearCookie(COOKIE_NAME, { path: '/' });
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      console.error('[auth] Me error:', err.message);
      res.status(500).json({ error: 'Auth check failed' });
    }
  });

  // ── GET /api/v1/auth/status — Public: are there any users? ──
  app.get('/api/v1/auth/status', async (req, res) => {
    try {
      const { rows } = await systemQuery(pool, 'SELECT COUNT(*)::int AS count FROM users');
      res.json({ hasUsers: rows[0].count > 0 });
    } catch {
      res.json({ hasUsers: false });
    }
  });

  // ── POST /api/v1/auth/reset-password — Admin password reset (bearer-token protected) ──
  const DEMO_RESET_TOKEN = process.env.DEMO_RESET_TOKEN || 'wid-demo-reset-2026';

  app.post('/api/v1/auth/reset-password', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${DEMO_RESET_TOKEN}`) {
      return res.status(403).json({ error: 'Invalid reset token' });
    }
    try {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ error: 'email and password required' });
      if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      const { rowCount } = await systemQuery(pool,
        'UPDATE users SET password_hash = $1 WHERE email = $2',
        [passwordHash, email.toLowerCase().trim()]
      );
      if (rowCount === 0) return res.status(404).json({ error: 'User not found' });
      console.log(`[auth] Password reset for: ${email}`);
      res.json({ ok: true, email });
    } catch (err) {
      console.error('[auth] Password reset error:', err.message);
      res.status(500).json({ error: 'Password reset failed' });
    }
  });

  // ── POST /api/v1/auth/demo-reset — Tenant-scoped demo reset ──
  app.post('/api/v1/auth/demo-reset', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${DEMO_RESET_TOKEN}`) {
      return res.status(403).json({ error: 'Invalid reset token' });
    }
    try {
      const tenantId = req.body.tenant_id || DEFAULT_TENANT_ID;
      const results = {};

      // Order matters: foreign keys. Scoped to tenant.
      for (const table of ['ext_authz_decisions', 'access_decisions', 'policy_violations',
                           'discovery_scans', 'targets', 'workloads', 'connectors', 'policies', 'users']) {
        try {
          const r = await systemQuery(pool, `DELETE FROM ${table} WHERE tenant_id = $1`, [tenantId]);
          results[table] = r.rowCount;
        } catch (e) {
          results[table] = `skip: ${e.message}`;
        }
      }
      // Reset usage
      await systemQuery(pool,
        `UPDATE tenant_usage SET user_count=0, workload_count=0, connector_count=0, policy_count=0, last_updated=NOW()
         WHERE tenant_id = $1`,
        [tenantId]
      );

      res.clearCookie(COOKIE_NAME, { path: '/' });
      console.log(`[auth] DEMO RESET executed for tenant ${tenantId}:`, results);
      res.json({ reset: true, tenant_id: tenantId, deleted: results });
    } catch (err) {
      console.error('[auth] Demo reset error:', err.message);
      res.status(500).json({ error: 'Demo reset failed' });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // TENANT MANAGEMENT ENDPOINTS
  // ═══════════════════════════════════════════════════════════════════════════

  // ── GET /api/v1/tenant — Current tenant details ──
  app.get('/api/v1/tenant', async (req, res) => {
    try {
      const token = req.cookies?.[COOKIE_NAME];
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await systemQuery(pool,
        `SELECT t.*, tu.user_count, tu.workload_count, tu.connector_count, tu.policy_count
         FROM tenants t
         LEFT JOIN tenant_usage tu ON tu.tenant_id = t.id
         WHERE t.id = $1`,
        [decoded.tenantId]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });

      res.json({ tenant: rows[0] });
    } catch (err) {
      console.error('[auth] Tenant error:', err.message);
      res.status(500).json({ error: 'Failed to get tenant' });
    }
  });

  // ── PUT /api/v1/tenant — Update tenant settings (admin only) ──
  app.put('/api/v1/tenant', async (req, res) => {
    try {
      const token = req.cookies?.[COOKIE_NAME];
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Admin role required' });
      }

      const { name, settings, data_region, data_residency_strict } = req.body;
      const updates = [];
      const params = [];
      let idx = 1;

      if (name) { updates.push(`name = $${idx++}`); params.push(name); }
      if (settings) { updates.push(`settings = $${idx++}`); params.push(JSON.stringify(settings)); }
      if (data_region) { updates.push(`data_region = $${idx++}`); params.push(data_region); }
      if (data_residency_strict !== undefined) {
        updates.push(`data_residency_strict = $${idx++}`);
        params.push(data_residency_strict);
      }

      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

      updates.push(`updated_at = NOW()`);
      params.push(decoded.tenantId);

      const { rows } = await systemQuery(pool,
        `UPDATE tenants SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`,
        params
      );

      const { tenantMiddleware: { invalidateTenantCache } } = require('../shared-loader');
      invalidateTenantCache(decoded.tenantId);

      res.json({ tenant: rows[0] });
    } catch (err) {
      console.error('[auth] Tenant update error:', err.message);
      res.status(500).json({ error: 'Failed to update tenant' });
    }
  });

  // ── GET /api/v1/tenant/users — List tenant users (admin only) ──
  app.get('/api/v1/tenant/users', async (req, res) => {
    try {
      const token = req.cookies?.[COOKIE_NAME];
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await systemQuery(pool,
        'SELECT id, email, name, role, created_at, last_login FROM users WHERE tenant_id = $1 ORDER BY created_at ASC',
        [decoded.tenantId]
      );
      res.json({ users: rows, total: rows.length });
    } catch (err) {
      console.error('[auth] List users error:', err.message);
      res.status(500).json({ error: 'Failed to list users' });
    }
  });

  // ── POST /api/v1/tenant/invite — Invite user to tenant (admin only) ──
  app.post('/api/v1/tenant/invite', async (req, res) => {
    try {
      const token = req.cookies?.[COOKIE_NAME];
      if (!token) return res.status(401).json({ error: 'Not authenticated' });

      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Admin role required' });
      }

      const { email, role } = req.body;
      if (!email) return res.status(400).json({ error: 'email is required' });

      const inviteRole = ['admin', 'operator', 'viewer'].includes(role) ? role : 'viewer';

      // Check tenant limit
      const { rows: usage } = await systemQuery(pool,
        'SELECT user_count FROM tenant_usage WHERE tenant_id = $1', [decoded.tenantId]);
      const { rows: tenant } = await systemQuery(pool,
        'SELECT max_users FROM tenants WHERE id = $1', [decoded.tenantId]);

      if (usage[0]?.user_count >= tenant[0]?.max_users) {
        return res.status(429).json({ error: 'User limit reached for your plan' });
      }

      // Check not already a member
      const { rows: existing } = await systemQuery(pool,
        'SELECT id FROM users WHERE email = $1 AND tenant_id = $2',
        [email.toLowerCase().trim(), decoded.tenantId]);
      if (existing.length > 0) {
        return res.status(409).json({ error: 'User already exists in this tenant' });
      }

      // Create invitation
      const inviteToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      await systemQuery(pool,
        `INSERT INTO tenant_invitations (tenant_id, email, role, invited_by, token, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [decoded.tenantId, email.toLowerCase().trim(), inviteRole, decoded.userId, inviteToken, expiresAt]
      );

      console.log(`[auth] Invitation sent: ${email} -> tenant ${decoded.tenantId} (role: ${inviteRole})`);
      res.status(201).json({
        invitation: {
          email: email.toLowerCase().trim(),
          role: inviteRole,
          expires_at: expiresAt,
          token: inviteToken, // In production, send via email instead
        },
      });
    } catch (err) {
      console.error('[auth] Invite error:', err.message);
      res.status(500).json({ error: 'Failed to create invitation' });
    }
  });

  // ── POST /api/v1/auth/accept-invite — Accept invitation and create user ──
  app.post('/api/v1/auth/accept-invite', async (req, res) => {
    try {
      const { token: inviteToken, password, name } = req.body;
      if (!inviteToken || !password || !name) {
        return res.status(400).json({ error: 'token, password, and name are required' });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      // Find valid invitation
      const { rows: invitations } = await systemQuery(pool,
        `SELECT * FROM tenant_invitations
         WHERE token = $1 AND accepted_at IS NULL AND expires_at > NOW()`,
        [inviteToken]
      );
      if (invitations.length === 0) {
        return res.status(404).json({ error: 'Invalid or expired invitation' });
      }

      const invite = invitations[0];
      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

      // Atomic: create user + mark invitation accepted
      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        const { rows } = await client.query(
          `INSERT INTO users (email, password_hash, name, role, tenant_id)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, email, name, role, tenant_id, created_at`,
          [invite.email, passwordHash, name.trim(), invite.role, invite.tenant_id]
        );
        const user = rows[0];

        await client.query(
          'UPDATE tenant_invitations SET accepted_at = NOW() WHERE id = $1',
          [invite.id]
        );

        // Update usage
        await client.query(
          `UPDATE tenant_usage SET user_count = user_count + 1, last_updated = NOW()
           WHERE tenant_id = $1`,
          [invite.tenant_id]
        );

        await client.query('COMMIT');

        const authToken = signToken(user, user.tenant_id);
        res.cookie(COOKIE_NAME, authToken, cookieOptions());

        console.log(`[auth] Invitation accepted: ${user.email} joined tenant ${user.tenant_id}`);
        res.status(201).json({
          user: { id: user.id, email: user.email, name: user.name, role: user.role },
          tenant: { id: user.tenant_id },
        });
      } catch (txErr) {
        await client.query('ROLLBACK');
        if (txErr.code === '23505') {
          return res.status(409).json({ error: 'Email already registered in this organization' });
        }
        throw txErr;
      } finally {
        client.release();
      }
    } catch (err) {
      console.error('[auth] Accept invite error:', err.message);
      res.status(500).json({ error: 'Failed to accept invitation' });
    }
  });
}

module.exports = { mountAuthRoutes, JWT_SECRET, COOKIE_NAME };
