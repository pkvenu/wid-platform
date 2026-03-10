// =============================================================================
// Auth Routes — Register, Login, Logout, Me
// =============================================================================

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.AUTH_JWT_SECRET || 'wid-auth-secret-change-in-production';
const JWT_EXPIRY = '24h';
const COOKIE_NAME = 'wid_token';
const SALT_ROUNDS = 12;

function cookieOptions() {
  // COOKIE_SECURE=false allows HTTP-only LB (e.g., IP-based LB without TLS)
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

function mountAuthRoutes(app, dbClient) {
  // ── POST /api/v1/auth/register — First-user bootstrap ──
  app.post('/api/v1/auth/register', async (req, res) => {
    try {
      const { email, password, name } = req.body;

      if (!email || !password || !name) {
        return res.status(400).json({ error: 'email, password, and name are required' });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }

      // Only allow registration when no users exist (first-user bootstrap)
      const { rows: existing } = await dbClient.query('SELECT COUNT(*)::int AS count FROM users');
      if (existing[0].count > 0) {
        return res.status(403).json({ error: 'Registration disabled. Users already exist.' });
      }

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      const { rows } = await dbClient.query(
        `INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, 'admin') RETURNING id, email, name, role, created_at`,
        [email.toLowerCase().trim(), passwordHash, name.trim()]
      );
      const user = rows[0];

      const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
      res.cookie(COOKIE_NAME, token, cookieOptions());

      console.log(`[auth] First user registered: ${user.email}`);
      res.status(201).json({ user: { id: user.id, email: user.email, name: user.name, role: user.role } });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'Email already registered' });
      }
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

      const { rows } = await dbClient.query(
        'SELECT id, email, password_hash, name, role FROM users WHERE email = $1',
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
      await dbClient.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

      const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
      res.cookie(COOKIE_NAME, token, cookieOptions());

      console.log(`[auth] Login: ${user.email}`);
      res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role } });
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
        // Also check if any users exist (for showing register vs login)
        const { rows } = await dbClient.query('SELECT COUNT(*)::int AS count FROM users');
        return res.status(401).json({ error: 'Not authenticated', hasUsers: rows[0].count > 0 });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await dbClient.query(
        'SELECT id, email, name, role, created_at, last_login FROM users WHERE id = $1',
        [decoded.userId]
      );

      if (rows.length === 0) {
        res.clearCookie(COOKIE_NAME, { path: '/' });
        return res.status(401).json({ error: 'User not found' });
      }

      res.json({ user: rows[0] });
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
      const { rows } = await dbClient.query('SELECT COUNT(*)::int AS count FROM users');
      res.json({ hasUsers: rows[0].count > 0 });
    } catch (err) {
      // Table might not exist yet
      res.json({ hasUsers: false });
    }
  });

  // ── POST /api/v1/auth/reset-password — Admin password reset (bearer-token protected) ──
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
      const { rowCount } = await dbClient.query(
        'UPDATE users SET password_hash = $1 WHERE email = $2',
        [passwordHash, email.toLowerCase().trim()]
      );
      if (rowCount === 0) return res.status(404).json({ error: 'User not found' });
      console.log(`[auth] Password reset for: ${email}`);
      res.json({ ok: true, email });
    } catch (err) {
      console.error('[auth] Password reset error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/v1/auth/demo-reset — Nuclear demo reset ──
  // Wipes users, connectors, workloads — returns to first-user registration
  // Protected by a bearer token (not cookie auth) so it works from CLI
  const DEMO_RESET_TOKEN = process.env.DEMO_RESET_TOKEN || 'wid-demo-reset-2026';
  app.post('/api/v1/auth/demo-reset', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== `Bearer ${DEMO_RESET_TOKEN}`) {
      return res.status(403).json({ error: 'Invalid reset token' });
    }
    try {
      const results = {};
      // Order matters: foreign keys
      for (const table of ['ext_authz_decisions', 'access_decisions', 'policy_violations', 'discovery_scans', 'targets', 'workloads', 'connectors', 'policies', 'users']) {
        try {
          const r = await dbClient.query(`DELETE FROM ${table}`);
          results[table] = r.rowCount;
        } catch (e) {
          results[table] = `skip: ${e.message}`;
        }
      }
      res.clearCookie(COOKIE_NAME, { path: '/' });
      console.log('[auth] DEMO RESET executed:', results);
      res.json({ reset: true, deleted: results });
    } catch (err) {
      console.error('[auth] Demo reset error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });
}

module.exports = { mountAuthRoutes, JWT_SECRET, COOKIE_NAME };
