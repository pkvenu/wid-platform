// =============================================================================
// Production Credential Broker - Plugin-Based Architecture
// Add new providers by creating *-provider.js files in src/providers/
// =============================================================================

const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

const providerManager = require('./providers');
const cache = require('./utils/cache');
const { RotationScheduler } = require('./rotation/scheduler');
const { mountLifecycleRoutes } = require('./rotation/lifecycle-routes');

const app = express();
app.use(express.json());

// Configuration
const PORT = process.env.PORT || 3002;
const OPA_URL = process.env.OPA_URL || 'http://opa:8181';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@postgres:5432/workload_identity';
const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret-key';

let dbClient = null;

// =============================================================================
// Initialize
// =============================================================================
async function initDatabase() {
  try {
    dbClient = new Client({ connectionString: DATABASE_URL });
    await dbClient.connect();
    console.log('✅ Database: Connected');
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
      const decoded = jwt.verify(token, JWT_SECRET);
      workloadId = decoded.sub;
      actor = decoded.act?.sub || decoded.sub;
      console.log(`  Workload: ${workloadId}, Actor: ${actor}`);
    } catch (error) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    // Check policy
    const allowed = await checkPolicy(workloadId, target);
    if (!allowed) {
      console.log(`  ❌ DENIED`);
      if (dbClient) {
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
    if (dbClient) {
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
  if (!dbClient) return;
  try {
    await dbClient.query(`
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
// Health Check
// =============================================================================
app.get('/health', async (req, res) => {
  try {
    const opaHealthy = await axios.get(`${OPA_URL}/health`, { timeout: 2000 }).then(() => true).catch(() => false);
    const dbHealthy = dbClient ? await dbClient.query('SELECT 1').then(() => true).catch(() => false) : false;
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

  // Startup migration: ensure credential_rotations table exists
  if (dbClient) {
    try {
      await dbClient.query(`
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
    } catch (e) {
      console.log('  credential_rotations migration:', e.message);
    }
  }

  // Mount lifecycle API routes
  const scheduler = new RotationScheduler(dbClient, providerManager, {
    defaultMaxAgeDays: parseInt(process.env.ROTATION_MAX_AGE_DAYS) || 90,
    evaluationInterval: parseInt(process.env.ROTATION_EVAL_INTERVAL_MS) || 3600000,
  });
  mountLifecycleRoutes(app, dbClient, providerManager, scheduler);

  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  Credential Broker v2.1 - Plugin Architecture             ║
║  Port: ${PORT}                                                 ║
╚════════════════════════════════════════════════════════════╝

✨ Plugin-Based Secret Providers
   Add new providers by creating *-provider.js files!

🔄 Lifecycle API:
   POST /v1/credentials/:id/rotate     → trigger rotation
   GET  /v1/credentials/:id/history    → rotation history
   POST /v1/credentials/:id/revoke     → revoke credential
   GET  /v1/credentials/stale          → list stale credentials
   POST /v1/credentials/migrate        → cross-provider migration
   GET  /v1/credentials/providers      → provider capabilities
   POST /v1/credentials/dynamic        → generate dynamic secret

Ready! 🚀
`);

    // Start rotation scheduler (after server is listening)
    if (dbClient) {
      scheduler.start();
    }
  });
}

start();
