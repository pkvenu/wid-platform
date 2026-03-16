// =============================================================================
// Production Credential Broker - Plugin-Based Architecture
// Add new providers by creating *-provider.js files in src/providers/
// =============================================================================

const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const providerManager = require('./providers');
const cache = require('./utils/cache');
const { RotationScheduler } = require('./rotation/scheduler');
const { mountLifecycleRoutes } = require('./rotation/lifecycle-routes');
const { createTenantPool } = require('./shared-loader').tenantDb;
const securityHeaders = require('./shared-loader').securityHeaders;
const { apiRateLimiter } = require('./shared-loader').rateLimitMiddleware;

const app = express();

// Security headers (P2.6) — set on every response
app.use(securityHeaders());

app.use(express.json());

// Rate limiting (P2.6) — 300 req/min per tenant for API routes
app.use(apiRateLimiter());

// Configuration
const PORT = process.env.PORT || 3002;
const OPA_URL = process.env.OPA_URL || 'http://opa:8181';
const TOKEN_SERVICE_URL = process.env.TOKEN_SERVICE_URL || 'http://token-service:3000';

let pool = null;

// =============================================================================
// Initialize (pg.Pool via shared tenant-db module)
// =============================================================================
async function initDatabase() {
  try {
    pool = createTenantPool();
    await pool.query('SELECT 1');
    console.log('✅ Database: Connected (pool)');
  } catch (error) {
    console.error('❌ Database: Failed -', error.message);
  }
}

// =============================================================================
// Get Credential (uses provider manager with caching)
// =============================================================================
async function getCredential(targetApi, secretPath) {
  // Check cache first
  const cacheKey = `${targetApi}:${secretPath}`;
  const cached = cache.get(cacheKey);
  
  if (cached) {
    console.log(`    💾 Cache hit (TTL: ${cache.getTTL()}s)`);
    return cached;
  }

  console.log(`    🔍 Fetching: ${secretPath}`);

  // Get from provider manager (handles failover automatically)
  const result = await providerManager.getSecret(secretPath);

  if (!result) {
    throw new Error(`Failed to retrieve credential: ${secretPath}`);
  }

  console.log(`    ✅ Retrieved from ${result.provider}`);

  // Cache it
  cache.set(cacheKey, result.value);

  return result.value;
}

// =============================================================================
// Target API Configurations
// =============================================================================
function getTargetConfig(target) {
  const configs = {
    'stripe': {
      baseUrl: process.env.STRIPE_API_URL || 'https://api.stripe.com',
      secretPath: process.env.STRIPE_SECRET_PATH || 'credentials/stripe/api-key',
      authType: 'bearer',
      headers: { 'Stripe-Version': '2023-10-16' }
    },
    'github': {
      baseUrl: process.env.GITHUB_API_URL || 'https://api.github.com',
      secretPath: process.env.GITHUB_SECRET_PATH || 'credentials/github/token',
      authType: 'token',
      headers: { 'Accept': 'application/vnd.github.v3+json' }
    },
    'openai': {
      baseUrl: process.env.OPENAI_API_URL || 'https://api.openai.com',
      secretPath: process.env.OPENAI_SECRET_PATH || 'credentials/openai/api-key',
      authType: 'bearer'
    },
    'anthropic': {
      baseUrl: process.env.ANTHROPIC_API_URL || 'https://api.anthropic.com',
      secretPath: process.env.ANTHROPIC_SECRET_PATH || 'credentials/anthropic/api-key',
      authType: 'x-api-key',
      headers: { 'anthropic-version': '2023-06-01' }
    }
  };

  return configs[target];
}

// =============================================================================
// CREDENTIAL INJECTION PROXY
// =============================================================================
app.all('/v1/proxy/:target/*', async (req, res) => {
  const target = req.params.target;
  const path = req.params[0] || '';
  const method = req.method;

  console.log(`\n🔐 Proxy Request: ${method} ${target}/${path}`);

  const startTime = Date.now();

  try {
    // Extract workload identity
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const token = authHeader.replace('Bearer ', '');
    let workloadId, actor;

    try {
      // Decode token to extract jti, then validate via token-service
      const decoded = jwt.decode(token);
      if (!decoded || !decoded.jti) {
        return res.status(401).json({ error: 'invalid_token', reason: 'Missing jti claim' });
      }

      const validateResponse = await axios.post(
        `${TOKEN_SERVICE_URL}/v1/token/validate`,
        { token_jti: decoded.jti },
        { timeout: 5000 }
      );

      if (!validateResponse.data.valid) {
        return res.status(401).json({
          error: 'invalid_token',
          reason: validateResponse.data.reason || 'Token validation failed',
        });
      }

      workloadId = decoded.sub;
      actor = decoded.act?.sub || decoded.sub;
      console.log(`  Workload: ${workloadId}, Actor: ${actor}`);
    } catch (error) {
      console.error(`  Token validation error:`, error.message);
      return res.status(401).json({ error: 'invalid_token' });
    }

    // Check policy
    const allowed = await checkPolicy(workloadId, target);
    if (!allowed) {
      console.log(`  ❌ DENIED`);
      if (pool) {
        await logAccess(workloadId, actor, target, method, path, 'denied', null, Date.now() - startTime);
      }
      return res.status(403).json({ error: 'access_denied' });
    }

    console.log(`  ✅ ALLOWED`);

    // Get target config
    const targetConfig = getTargetConfig(target);
    if (!targetConfig) {
      return res.status(404).json({ error: 'target_not_configured' });
    }

    // Get credential (uses provider manager)
    const credential = await getCredential(target, targetConfig.secretPath);

    // Build request
    const targetUrl = `${targetConfig.baseUrl}/${path}`;
    const proxyHeaders = { ...req.headers };
    delete proxyHeaders['host'];
    delete proxyHeaders['authorization'];
    delete proxyHeaders['content-length'];

    if (targetConfig.headers) {
      Object.assign(proxyHeaders, targetConfig.headers);
    }

    // Inject credential
    switch (targetConfig.authType) {
      case 'bearer':
        proxyHeaders['Authorization'] = `Bearer ${credential}`;
        break;
      case 'token':
        proxyHeaders['Authorization'] = `token ${credential}`;
        break;
      case 'x-api-key':
        proxyHeaders['X-API-Key'] = credential;
        break;
      case 'basic':
        const encoded = Buffer.from(`user:${credential}`).toString('base64');
        proxyHeaders['Authorization'] = `Basic ${encoded}`;
        break;
    }

    console.log(`  💉 Credential injected (${targetConfig.authType})`);

    // Forward request
    const proxyResponse = await axios({
      method,
      url: targetUrl,
      headers: proxyHeaders,
      data: req.body,
      params: req.query,
      timeout: 30000,
      validateStatus: () => true
    });

    const duration = Date.now() - startTime;
    console.log(`  📥 ${proxyResponse.status} (${duration}ms)`);

    // Log access
    if (pool) {
      await logAccess(workloadId, actor, target, method, path, 'allowed', proxyResponse.status, duration);
    }

    // Return response
    res.status(proxyResponse.status).set(proxyResponse.headers).send(proxyResponse.data);

    console.log(`  ✅ Complete`);

  } catch (error) {
    console.error(`  ❌ Error:`, error.message);
    res.status(500).json({ error: 'proxy_error', message: error.message });
  }
});

// =============================================================================
// Helper Functions
// =============================================================================
async function checkPolicy(workloadId, target) {
  try {
    const response = await axios.post(`${OPA_URL}/v1/data/workload/allow`, {
      input: { subject: workloadId, audience: target }
    }, { timeout: 2000 });
    return response.data.result === true;
  } catch (error) {
    return false;
  }
}

async function logAccess(workloadId, actor, target, method, path, result, statusCode, duration) {
  if (!pool) return;
  try {
    await pool.query(`
      INSERT INTO credential_usage 
      (workload_id, target_api, method, path, result, status_code, accessed_at, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
    `, [workloadId, target, method, path, result, statusCode, JSON.stringify({ actor, duration_ms: duration })]);
  } catch (error) {
    console.error('Log failed:', error.message);
  }
}

// =============================================================================
// Admin Endpoints
// =============================================================================
app.post('/v1/admin/cache/clear', (req, res) => {
  cache.flush();
  res.json({ message: 'Cache cleared' });
});

app.get('/v1/admin/providers', (req, res) => {
  res.json({
    providers: providerManager.getProvidersMetadata()
  });
});

// =============================================================================
// Convenience API Endpoints (top-level paths for common operations)
// =============================================================================

// POST /api/v1/credentials/rotate — Trigger rotation for a specific credential path
app.post('/api/v1/credentials/rotate', async (req, res) => {
  try {
    const { credential_path, provider, new_value, workload_id } = req.body || {};
    if (!credential_path) {
      return res.status(400).json({ error: 'credential_path is required' });
    }

    if (!pool) {
      return res.status(503).json({ error: 'Database not connected' });
    }

    // Delegate to the scheduler (same logic as lifecycle route)
    const { RotationScheduler } = require('./rotation/scheduler');
    // Reuse the scheduler instance via the app — it's mounted during start()
    const scheduler = app.get('rotationScheduler');
    if (!scheduler) {
      return res.status(503).json({ error: 'Rotation scheduler not initialized' });
    }

    const rotation = await scheduler.scheduleRotation(credential_path, 'api', {
      provider,
      workloadId: workload_id,
    });

    // Execute immediately if new_value provided
    if (new_value) {
      try {
        const result = await scheduler.executeRotation(rotation.id, new_value);
        return res.json({
          message: `Credential "${credential_path}" rotated successfully`,
          rotation_id: rotation.id,
          status: 'completed',
          old_version: result.oldVersion,
          new_version: result.newVersion,
        });
      } catch (execErr) {
        return res.status(500).json({
          error: `Rotation failed: ${execErr.message}`,
          rotation_id: rotation.id,
          status: 'failed',
        });
      }
    }

    res.status(202).json({
      message: `Rotation scheduled for "${credential_path}"`,
      rotation_id: rotation.id,
      status: 'pending',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/credentials/rotation-status — Rotation schedule and last rotation times
app.get('/api/v1/credentials/rotation-status', async (req, res) => {
  try {
    const scheduler = app.get('rotationScheduler');
    if (!scheduler) {
      return res.status(503).json({ error: 'Rotation scheduler not initialized' });
    }

    const status = await scheduler.getRotationStatus();
    res.json({
      default_max_age_days: scheduler.defaultMaxAgeDays,
      evaluation_interval_ms: scheduler.evaluationInterval,
      ...status,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/providers — List active providers with health status
app.get('/api/v1/providers', async (req, res) => {
  try {
    const metadata = providerManager.getProvidersMetadata();
    const healthResults = await providerManager.healthCheckAll();

    const providers = metadata.map(p => {
      const provider = providerManager.getProvider(p.key);
      return {
        ...p,
        healthy: healthResults[p.key] || false,
        capabilities: {
          rotation: provider?.supportsRotation() || false,
          revocation: provider?.supportsRevocation() || false,
          dynamic_secrets: provider?.supportsDynamicSecrets() || false,
        },
      };
    });

    res.json({ providers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// Health Check
// =============================================================================
app.get('/health', async (req, res) => {
  try {
    const opaHealthy = await axios.get(`${OPA_URL}/health`, { timeout: 2000 }).then(() => true).catch(() => false);
    const dbHealthy = pool ? await pool.query('SELECT 1').then(() => true).catch(() => false) : false;
    const providerHealth = await providerManager.healthCheckAll();

    res.json({
      service: 'credential-broker',
      version: '2.0.0',
      status: 'healthy',
      providers: providerHealth,
      cache: cache.getStats(),
      opa_connected: opaHealthy,
      database_connected: dbHealthy
    });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: error.message });
  }
});

// =============================================================================
// Start Server
// =============================================================================
async function start() {
  await providerManager.loadProviders();
  await initDatabase();

  // Startup migration: ensure credential_rotations + rotation_policies tables exist
  if (pool) {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS credential_rotations (
          id              SERIAL PRIMARY KEY,
          credential_path VARCHAR(500) NOT NULL,
          provider        VARCHAR(50) NOT NULL,
          workload_id     UUID,
          status          VARCHAR(20) DEFAULT 'pending',
          triggered_by    VARCHAR(50),
          old_version     VARCHAR(100),
          new_version     VARCHAR(100),
          error_message   TEXT,
          scheduled_at    TIMESTAMPTZ,
          executed_at     TIMESTAMPTZ,
          created_at      TIMESTAMPTZ DEFAULT NOW()
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS rotation_policies (
          id                  SERIAL PRIMARY KEY,
          credential_path     VARCHAR(500) NOT NULL UNIQUE,
          provider            VARCHAR(50) NOT NULL,
          max_age_days        INTEGER NOT NULL DEFAULT 90,
          auto_rotate         BOOLEAN NOT NULL DEFAULT true,
          notify_before_days  INTEGER NOT NULL DEFAULT 7,
          enabled             BOOLEAN NOT NULL DEFAULT true,
          created_at          TIMESTAMPTZ DEFAULT NOW(),
          updated_at          TIMESTAMPTZ DEFAULT NOW()
        )
      `);
    } catch (e) {
      console.log('  startup migration:', e.message);
    }
  }

  // Mount lifecycle API routes
  const scheduler = new RotationScheduler(pool, providerManager, {
    defaultMaxAgeDays: parseInt(process.env.ROTATION_MAX_AGE_DAYS) || 90,
    evaluationInterval: parseInt(process.env.ROTATION_EVAL_INTERVAL_MS) || 3600000,
  });
  app.set('rotationScheduler', scheduler);
  mountLifecycleRoutes(app, pool, providerManager, scheduler);

  const server = app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  Credential Broker v2.2 - Plugin Architecture             ║
║  Port: ${PORT}                                                 ║
╚════════════════════════════════════════════════════════════╝

Plugin-Based Secret Providers
   Add new providers by creating *-provider.js files!

Lifecycle API:
   POST /v1/credentials/:id/rotate     -> trigger rotation
   GET  /v1/credentials/:id/history    -> rotation history
   POST /v1/credentials/:id/revoke     -> revoke credential
   GET  /v1/credentials/stale          -> list stale credentials
   POST /v1/credentials/migrate        -> cross-provider migration
   GET  /v1/credentials/providers      -> provider capabilities
   POST /v1/credentials/dynamic        -> generate dynamic secret

Rotation Policies:
   GET    /v1/credentials/policies         -> list policies
   PUT    /v1/credentials/policies/:path   -> set policy
   DELETE /v1/credentials/policies/:path   -> remove policy

Convenience API:
   POST /api/v1/credentials/rotate          -> trigger rotation
   GET  /api/v1/credentials/rotation-status -> schedule + history
   GET  /api/v1/providers                   -> providers + health

Ready!
`);

    // Start rotation scheduler (after server is listening)
    if (pool) {
      scheduler.start();
    }

    // Graceful shutdown: drain pool connections
    const shutdown = async (signal) => {
      console.log(`\n${signal} received — shutting down credential-broker`);
      server.close();
      if (pool) await pool.end();
      process.exit(0);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  });
}

start();
