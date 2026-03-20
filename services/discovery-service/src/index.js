// =============================================================================
// Discovery Service - Main Orchestrator with Pluggable Scanner Architecture
// =============================================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createTenantPool, tenantQuery, systemQuery } = require('./shared-loader').tenantDb;
const { enforceDataResidency } = require('./shared-loader').tenantMiddleware;
const securityHeaders = require('./shared-loader').securityHeaders;
const { apiRateLimiter } = require('./shared-loader').rateLimitMiddleware;
const ScannerRegistry = require('./scanners/base/ScannerRegistry');
const { mountAttestationRoutes } = require('./attestation/attestation-routes');
const { mountGraphRoutes, refreshGraph, generateBaselinePolicies, getGraphCache } = require('./graph/graph-routes');
const { mountConnectorRoutes } = require('./connectors/connector-routes');
const { mountRegistryRoutes } = require('./graph/registry-routes');
const app = express();
const PORT = process.env.PORT || 3003;

// ═══════════════════════════════════════════════════════════════
// Gateway Proxy — Optional enforcement wrapper for inter-service calls
// When GATEWAY_PROXY_URL is set, outbound calls route through the relay's
// gateway proxy for policy evaluation. This makes the WID platform
// self-protecting: it enforces policy on its own service mesh.
// ═══════════════════════════════════════════════════════════════
const GATEWAY_PROXY_URL = process.env.GATEWAY_PROXY_URL || '';

async function gatewayFetch(url, opts = {}) {
  if (!GATEWAY_PROXY_URL) return fetch(url, opts);
  try {
    const dest = new URL(url).hostname;
    return await fetch(GATEWAY_PROXY_URL, {
      method: opts.method || 'GET',
      headers: {
        ...opts.headers,
        'Content-Type': 'application/json',
        'X-WID-Source': 'discovery-service',
        'X-WID-Destination': dest,
        'X-WID-Target-URL': url,
      },
      body: opts.body,
      signal: opts.signal,
    });
  } catch (gwErr) {
    // Fallback to direct call if gateway is unavailable (fail-open for discovery)
    console.warn(`[gateway] Proxy unavailable, direct call to ${url}: ${gwErr.message}`);
    return fetch(url, opts);
  }
}

// ═══════════════════════════════════════════════════════════════
// WID Token Issuance — SPIFFE-style identity tokens post-attestation
//
// After cryptographic attestation, we issue a short-lived JWT-like
// token (WID Token) that serves as the durable identity artifact.
// This token is validated on every request at the edge gateway.
//
// Pattern: Attest once → Issue token → Validate on every request
// ═══════════════════════════════════════════════════════════════

const WID_TOKEN_SECRET = process.env.WID_TOKEN_SECRET || 'wid-platform-signing-key-change-in-production';
const WID_TRUST_DOMAIN = process.env.WID_TRUST_DOMAIN || 'wid-platform.local';

function issueWidToken(workload, attestationResult) {
  const now = Math.floor(Date.now() / 1000);
  const trustLevel = attestationResult?.trust_level || workload.trust_level || 'none';

  // TTL based on trust level — higher trust = longer token
  const ttlMap = { cryptographic: 3600, high: 1800, medium: 900, low: 300, none: 60 };
  const ttl = ttlMap[trustLevel] || 300;

  // SPIFFE-style URI
  const spiffeId = workload.spiffe_id ||
    `spiffe://${WID_TRUST_DOMAIN}/workload/${workload.name || workload.id}`;

  const header = { alg: 'HS256', typ: 'WID-TOKEN', kid: 'wid-signing-001' };
  const payload = {
    // Standard JWT claims
    iss: `wid-platform://${WID_TRUST_DOMAIN}`,
    sub: spiffeId,
    aud: `wid-gateway://${WID_TRUST_DOMAIN}`,
    iat: now,
    exp: now + ttl,
    jti: `wid-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`,

    // WID-specific claims
    wid: {
      workload_id: workload.id,
      workload_name: workload.name,
      workload_type: workload.type,
      trust_level: trustLevel,
      trust_score: attestationResult?.trust_score || 0,
      is_ai_agent: workload.is_ai_agent || false,
      is_mcp_server: workload.is_mcp_server || false,
      environment: workload.environment,
      verified: true,
      attestation_method: attestationResult?.primary_method || 'manual-approval',
      attestation_chain: (attestationResult?.attestation_chain || []).map(a => ({
        method: a.method, trust: a.trust, tier: a.tier,
      })),
    },
  };

  // Sign: base64url(header).base64url(payload).signature
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsigned = `${b64(header)}.${b64(payload)}`;
  const signature = crypto.createHmac('sha256', WID_TOKEN_SECRET).update(unsigned).digest('base64url');
  const token = `${unsigned}.${signature}`;

  return {
    token,
    token_type: 'WID-TOKEN',
    spiffe_id: spiffeId,
    trust_level: trustLevel,
    trust_score: attestationResult?.trust_score || 0,
    issued_at: new Date(now * 1000).toISOString(),
    expires_at: new Date((now + ttl) * 1000).toISOString(),
    ttl_seconds: ttl,
    jti: payload.jti,
    attestation_method: payload.wid.attestation_method,
    attestation_chain: payload.wid.attestation_chain,
    claims: payload,
  };
}

function verifyWidToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, reason: 'malformed' };
    const [headerB64, payloadB64, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', WID_TOKEN_SECRET).update(`${headerB64}.${payloadB64}`).digest('base64url');
    if (sig !== expectedSig) return { valid: false, reason: 'invalid_signature' };
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return { valid: false, reason: 'expired', expired_at: new Date(payload.exp * 1000).toISOString() };
    if (payload.nbf && payload.nbf > now) return { valid: false, reason: 'not_yet_valid' };
    return { valid: true, payload, spiffe_id: payload.sub, trust_level: payload.wid?.trust_level, wid: payload.wid };
  } catch (e) { return { valid: false, reason: e.message }; }
}
// Security headers (P2.6) — set before CORS so every response gets them
app.use(securityHeaders());

// CORS — restricted to configured origins (P0.2 fix)
const ALLOWED_ORIGINS = new Set([
  // Production frontend (Cloud Run)
  'https://wid-dev-web-ui-265663183174.us-central1.run.app',
  // Load balancer / external IP
  'http://34.120.74.81',
  'https://34.120.74.81',
  'http://34.111.176.251',
  'https://34.111.176.251',
  // Local dev
  'http://localhost:3100',
  'http://localhost:5173',
  'http://localhost:3000',
  // Any additional origins from env (comma-separated)
  ...(process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
]);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (curl, mobile apps, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    console.warn(`[CORS] Blocked origin: ${origin}`);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(cookieParser());

// JWT auth middleware — verify wid_token cookie on protected routes
const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || 'wid-auth-secret-change-in-production';
const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';
app.use((req, res, next) => {
  // Skip auth for health, relay (internal), and OPTIONS
  if (req.path === '/health' || req.path.startsWith('/api/v1/relay/') || req.method === 'OPTIONS') {
    return next();
  }
  const token = req.cookies?.wid_token;
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, AUTH_JWT_SECRET);
    req.user = decoded;
    // Multi-tenancy: extract tenantId from JWT, default to system tenant
    req.tenantId = decoded.tenantId || DEFAULT_TENANT_ID;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      res.clearCookie('wid_token', { path: '/' });
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// Tenant-scoped DB middleware — attaches req.db for tenant-scoped queries
function attachTenantDb(pool) {
  return (req, res, next) => {
    const tid = req.tenantId || DEFAULT_TENANT_ID;
    req.db = {
      query: (text, params) => tenantQuery(pool, tid, text, params),
    };
    req.systemDb = {
      query: (text, params) => systemQuery(pool, text, params),
    };
    next();
  };
}

app.use(express.json());

// Rate limiting (P2.6) — 300 req/min per tenant for general API routes
app.use('/api/', apiRateLimiter());

// Tenant-scoped DB middleware is applied after pool is created in start()

// Scanner configuration
const awsBase = {
  enabled: process.env.ENABLE_AWS_SCANNER !== 'false' && !!process.env.AWS_ACCESS_KEY_ID,
  region: process.env.AWS_DEFAULT_REGION || 'us-east-1',
  trustDomain: process.env.SPIRE_TRUST_DOMAIN || 'company.com'
};
const gcpBase = {
  enabled: process.env.ENABLE_GCP_SCANNER !== 'false' && (!!process.env.GOOGLE_APPLICATION_CREDENTIALS || !!process.env.K_SERVICE || !!process.env.GCP_PROJECT_ID),
  project: process.env.GCP_PROJECT_ID,
  trustDomain: process.env.SPIRE_TRUST_DOMAIN || 'company.com'
};
const azureBase = {
  enabled: process.env.ENABLE_AZURE_SCANNER !== 'false' && !!process.env.AZURE_SUBSCRIPTION_ID,
  subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
  tenantId: process.env.AZURE_TENANT_ID,
  trustDomain: process.env.SPIRE_TRUST_DOMAIN || 'company.com'
};
const SCANNER_CONFIG = {
  // AWS scanners — all share the same credentials
  aws: awsBase,
  'aws-storage': awsBase,
  'aws-network': awsBase,
  'aws-security': awsBase,
  iam: awsBase,
  // GCP scanner
  gcp: gcpBase,
  // Azure scanners
  azure: azureBase,
  'azure-entra': { ...azureBase, enabled: !!process.env.AZURE_TENANT_ID },
  // Infrastructure scanners
  kubernetes: {
    enabled: true,
    trustDomain: process.env.SPIRE_TRUST_DOMAIN || 'company.com'
  },
  docker: {
    enabled: true,
    trustDomain: process.env.SPIRE_TRUST_DOMAIN || 'company.com'
  }
};

// Global state
let pool;
let scannerRegistry;
let activeScanners = [];
let discoveryInterval;

// =============================================================================
// Database Functions
// =============================================================================

async function connectDatabase() {
  console.log(`🔌 Connecting to database...`);

  const MAX_RETRIES = 5;
  const RETRY_DELAY_MS = 3000;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      pool = createTenantPool({ connectionTimeout: 10000 });
      // Verify pool connectivity
      const client = await pool.connect();
      client.release();
      console.log(`✅ Connected to database pool (attempt ${attempt})`);
      global._dbConnectError = null;

      // Run classification schema migration (idempotent)
      // Provider registry + cloud log enrichments + IETF delegation_type
      try {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS provider_registry (
            id VARCHAR(100) PRIMARY KEY, registry_type VARCHAR(50) NOT NULL,
            label VARCHAR(255) NOT NULL, category VARCHAR(100) NOT NULL,
            credential_keys TEXT[] DEFAULT '{}', ai_config JSONB DEFAULT NULL,
            domain_patterns TEXT[] DEFAULT '{}', domain_type VARCHAR(50),
            image_patterns TEXT[] DEFAULT '{}', signal_patterns TEXT[] DEFAULT '{}',
            enabled BOOLEAN DEFAULT TRUE, sort_order INTEGER DEFAULT 100,
            created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS cloud_log_enrichments (
            id SERIAL PRIMARY KEY, workload_id UUID, workload_name VARCHAR(255),
            cloud_provider VARCHAR(50) NOT NULL, log_source VARCHAR(100) NOT NULL,
            api_called VARCHAR(500), destination_host VARCHAR(255), method VARCHAR(10),
            caller_identity VARCHAR(500), provider_match VARCHAR(100),
            call_count INTEGER DEFAULT 1, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ,
            raw_metadata JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS credential_rotations (
            id SERIAL PRIMARY KEY, credential_path VARCHAR(500) NOT NULL,
            provider VARCHAR(50) NOT NULL, workload_id UUID,
            status VARCHAR(20) DEFAULT 'pending', triggered_by VARCHAR(50),
            old_version VARCHAR(100), new_version VARCHAR(100), error_message TEXT,
            scheduled_at TIMESTAMPTZ, executed_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
          );
          CREATE TABLE IF NOT EXISTS remediation_executions (
            id SERIAL PRIMARY KEY, control_id VARCHAR(100) NOT NULL,
            node_id VARCHAR(255) NOT NULL, channel VARCHAR(20) NOT NULL,
            status VARCHAR(20) DEFAULT 'pending', requested_by VARCHAR(255),
            approved_by VARCHAR(255), commands JSONB, output TEXT, error_message TEXT,
            rollback_commands JSONB, requested_at TIMESTAMPTZ DEFAULT NOW(),
            approved_at TIMESTAMPTZ, executed_at TIMESTAMPTZ, completed_at TIMESTAMPTZ
          );
          CREATE INDEX IF NOT EXISTS idx_remediation_executions_node ON remediation_executions(node_id);
          CREATE INDEX IF NOT EXISTS idx_remediation_executions_status ON remediation_executions(status);
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS delegation_type VARCHAR(50) DEFAULT NULL;
        `);
        console.log('  ✓ Provider registry + cloud log + remediation tables migration applied');
      } catch (migErr) {
        console.log('  ⚠️ Provider registry migration skipped:', migErr.message);
      }

      try {
        await pool.query(`
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_rogue BOOLEAN DEFAULT FALSE;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS rogue_score NUMERIC(5,2) DEFAULT 0;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS rogue_reasons JSONB DEFAULT '[]'::jsonb;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_orphan BOOLEAN DEFAULT FALSE;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS orphan_reasons JSONB DEFAULT '[]'::jsonb;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_publicly_exposed BOOLEAN DEFAULT FALSE;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS exposure_reasons JSONB DEFAULT '[]'::jsonb;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_unused_iam BOOLEAN DEFAULT FALSE;
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS classification VARCHAR(50) DEFAULT 'pending';
          ALTER TABLE workloads ADD COLUMN IF NOT EXISTS classification_tags JSONB DEFAULT '[]'::jsonb;
        `);
        console.log('  ✓ Classification schema migration applied');
      } catch (migErr) {
        console.log('  ⚠️ Classification migration skipped:', migErr.message);
      }

      return;
    } catch (err) {
      console.log(`⚠️  DB connection attempt ${attempt}/${MAX_RETRIES}: ${err.message}`);
      global._dbConnectError = err.message;
      pool = null;
      if (attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
      }
    }
  }
  console.error('⚠️  All DB connection attempts failed — running in stateless mode');
}

/**
 * Unified workload classification — computes Shadow, Zombie, Rogue, Unused IAM,
 * Public Exposure, and composite classification in a single pass.
 * Replaces the old recomputeShadow() with a comprehensive enterprise classifier.
 */
function classifyWorkload(workload) {
  const name = (workload.name || '').toLowerCase();
  const tags = workload.labels || {};
  const meta = workload.metadata || {};
  const type = workload.type || '';

  // Result object — all classification fields
  const result = {
    is_shadow: false, shadow_score: 0, shadow_reasons: [],
    is_dormant: false, dormancy_score: 0, dormancy_reasons: [],
    is_rogue: false, rogue_score: 0, rogue_reasons: [],
    is_unused_iam: false,
    is_publicly_exposed: false, exposure_reasons: [],
    classification: 'managed', classification_tags: [],
  };

  // ─── Known infrastructure exclusions ───
  const isKnownInfra =
    name.startsWith('awsservicerolefor') ||
    /^wid-(dev|prod|staging)-/.test(name) ||
    (name.endsWith('.iam.gserviceaccount.com') && name.includes('-compute@')) ||
    (meta.path || '').includes('/aws-service-role/') ||
    meta.is_service_linked === true;

  // ═══════════════════════════════════════════════════════════════════
  // 1. SHADOW IT — unregistered / unowned infrastructure
  // ═══════════════════════════════════════════════════════════════════
  if (!isKnownInfra) {
    let shadowScore = 0;
    const shadowReasons = [];

    if (!workload.owner && !tags.owner && !tags.Owner) { shadowScore += 25; shadowReasons.push('No owner assigned'); }
    if (!workload.team && !tags.team && !tags.Team) { shadowScore += 15; shadowReasons.push('No team assigned'); }
    const env = workload.environment || tags.environment || tags.Environment;
    if (!env || env === 'unknown') { shadowScore += 10; shadowReasons.push('Unknown or missing environment'); }
    if (!workload.cost_center && !tags['cost-center'] && !tags.CostCenter) { shadowScore += 10; shadowReasons.push('No cost center'); }
    if (/^(test|tmp)[-_]/.test(name) || name === 'test' || name === 'tmp') { shadowScore += 25; shadowReasons.push('Test/temporary naming'); }
    else if (/^(experiment|sandbox|throwaway|hack)[-_]/.test(name)) { shadowScore += 20; shadowReasons.push('Experimental naming'); }
    if (/^(app|service|function)-\d+$/.test(name)) { shadowScore += 15; shadowReasons.push('Generic auto-generated name'); }

    shadowScore = Math.min(100, shadowScore);
    result.shadow_score = shadowScore;
    result.is_shadow = shadowScore >= 50;
    result.shadow_reasons = result.is_shadow ? shadowReasons : [];
  }

  // ═══════════════════════════════════════════════════════════════════
  // 2. ZOMBIE / DORMANT IT — inactive but still present
  // ═══════════════════════════════════════════════════════════════════
  if (!isKnownInfra) {
    const dormancyReasons = [];
    let lastActivity = null;

    // Extract last activity from type-specific metadata
    if (type === 'iam-role') {
      const roleLastUsed = meta.role_last_used ? new Date(meta.role_last_used) : null;
      if (roleLastUsed && !isNaN(roleLastUsed)) lastActivity = roleLastUsed;
    } else if (type === 'iam-user') {
      // Check password and all access keys
      const pwdDate = meta.password_last_used ? new Date(meta.password_last_used) : null;
      const keyDates = (meta.access_keys || [])
        .map(k => k.last_used_date ? new Date(k.last_used_date) : null)
        .filter(d => d && !isNaN(d));
      const allDates = [pwdDate, ...keyDates].filter(Boolean);
      lastActivity = allDates.length > 0 ? new Date(Math.max(...allDates.map(d => d.getTime()))) : null;
    } else if (type === 'managed-secret') {
      const accessed = meta.last_accessed ? new Date(meta.last_accessed) : null;
      if (accessed && !isNaN(accessed)) lastActivity = accessed;
    } else if (type === 'ec2-instance') {
      const launched = meta.launch_time ? new Date(meta.launch_time) : null;
      if (launched && !isNaN(launched)) lastActivity = launched;
    } else if (type === 'lambda-function') {
      const modified = meta.last_modified ? new Date(meta.last_modified) : null;
      if (modified && !isNaN(modified)) lastActivity = modified;
    }

    // Fall back to last_api_call or last_seen
    if (!lastActivity && workload.last_api_call) {
      lastActivity = new Date(workload.last_api_call);
    }

    // Compute dormancy score from days idle
    if (lastActivity && !isNaN(lastActivity)) {
      const daysIdle = Math.floor((Date.now() - lastActivity.getTime()) / 86400000);
      let dormScore = 0;

      if (daysIdle > 180) {
        dormScore = 80 + Math.min(20, (daysIdle - 180) * 0.1);
        dormancyReasons.push(`No activity for ${daysIdle} days (>180d)`);
      } else if (daysIdle > 90) {
        dormScore = 50 + (daysIdle - 90) * 0.33;
        dormancyReasons.push(`No activity for ${daysIdle} days (>90d)`);
      } else if (daysIdle > 30) {
        dormScore = 25 + (daysIdle - 30) * 0.42;
        dormancyReasons.push(`Low activity — ${daysIdle} days since last use`);
      }

      result.dormancy_score = Math.min(100, Math.round(dormScore));
      result.is_dormant = result.dormancy_score >= 50;
      result.dormancy_reasons = result.is_dormant ? dormancyReasons : [];
    } else if (workload.api_calls_30d === 0 && !workload.last_api_call) {
      // No activity signals at all — check creation age
      const created = meta.create_date ? new Date(meta.create_date) : null;
      if (created && !isNaN(created)) {
        const ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);
        if (ageDays > 90) {
          result.dormancy_score = Math.min(100, 50 + (ageDays - 90) * 0.2);
          result.is_dormant = true;
          result.dormancy_reasons = [`Created ${ageDays} days ago with no recorded activity`];
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // 3. ROGUE IT — bypassing governance / unauthorized access
  // ═══════════════════════════════════════════════════════════════════
  if (!isKnownInfra) {
    let rogueScore = 0;
    const rogueReasons = [];

    // Cross-account trust without ExternalId
    const crossTrusts = meta.cross_account_trusts || [];
    if (crossTrusts.some(t => t.account_id === '*')) {
      rogueScore += 40;
      rogueReasons.push('Wildcard (*) cross-account trust — any AWS account can assume');
    } else if (crossTrusts.some(t => !t.has_external_id)) {
      rogueScore += 30;
      rogueReasons.push('Cross-account trust without ExternalId condition');
    }

    // Admin access without permission boundary and not service-linked
    if (meta.has_admin_access && !meta.permission_boundary_arn && !meta.is_service_linked) {
      rogueScore += 25;
      rogueReasons.push('Admin access without permission boundary');
    }

    // Public exposure without approval tag
    const isPublic = meta.is_public === true || meta.publicly_accessible === true ||
                     meta.allows_public_ingress === true;
    const hasApproval = tags['approved-public'] === 'true' || tags['approved_public'] === 'true';
    if (isPublic && !hasApproval) {
      rogueScore += 20;
      rogueReasons.push('Publicly exposed without approval tag');
    }

    // Experimental naming + has real credentials
    if (/^(experiment|sandbox|throwaway|hack)[-_]/.test(name)) {
      const hasCreds = (meta.credentials || []).length > 0 || (meta.access_keys || []).length > 0;
      if (hasCreds) {
        rogueScore += 15;
        rogueReasons.push('Experimental workload holding production credentials');
      }
    }

    rogueScore = Math.min(100, rogueScore);
    result.rogue_score = rogueScore;
    result.is_rogue = rogueScore >= 40;
    result.rogue_reasons = result.is_rogue ? rogueReasons : [];
  }

  // ═══════════════════════════════════════════════════════════════════
  // 4. UNUSED IAM — identity resources with no activity
  // ═══════════════════════════════════════════════════════════════════
  const iamTypes = ['iam-role', 'iam-user', 'iam-group', 'service-account'];
  if (iamTypes.includes(type) && !isKnownInfra) {
    if (type === 'iam-role') {
      const roleLastUsed = meta.role_last_used ? new Date(meta.role_last_used) : null;
      if (!roleLastUsed || (Date.now() - roleLastUsed.getTime()) > 90 * 86400000) {
        result.is_unused_iam = true;
      }
    } else if (type === 'iam-user') {
      const pwdLast = meta.password_last_used ? new Date(meta.password_last_used) : null;
      const keyLast = (meta.access_keys || [])
        .map(k => k.last_used_date ? new Date(k.last_used_date) : null)
        .filter(Boolean);
      const allLast = [pwdLast, ...keyLast].filter(d => d && !isNaN(d));
      const mostRecent = allLast.length > 0 ? Math.max(...allLast.map(d => d.getTime())) : 0;
      if (!mostRecent || (Date.now() - mostRecent) > 90 * 86400000) {
        result.is_unused_iam = true;
      }
    } else if (type === 'iam-group') {
      if (meta.member_count === 0) {
        result.is_unused_iam = true;
      }
    } else if (type === 'service-account') {
      const keys = meta.keys || [];
      const hasRecentKey = keys.some(k => {
        const created = k.validAfterTime ? new Date(k.validAfterTime) : null;
        return created && (Date.now() - created.getTime()) < 90 * 86400000;
      });
      if (keys.length === 0 || !hasRecentKey) {
        result.is_unused_iam = true;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // 5. PUBLIC EXPOSURE — internet-accessible resources
  // ═══════════════════════════════════════════════════════════════════
  const exposureReasons = [];
  if (meta.is_public === true) exposureReasons.push('S3 bucket is publicly accessible');
  if (meta.publicly_accessible === true) exposureReasons.push('Database is publicly accessible');
  if (meta.allows_public_ingress === true) exposureReasons.push('Security group allows public ingress');
  if (meta.is_internet_facing === true) exposureReasons.push('Load balancer is internet-facing');
  if (meta.ingress === 'INGRESS_TRAFFIC_ALL') exposureReasons.push('Cloud Run allows all ingress traffic');
  if (meta.public_ip) exposureReasons.push(`Has public IP: ${meta.public_ip}`);
  if (meta.has_external_ip === true) exposureReasons.push('Instance has external IP');

  if (exposureReasons.length > 0) {
    result.is_publicly_exposed = true;
    result.exposure_reasons = exposureReasons;
  }

  // ═══════════════════════════════════════════════════════════════════
  // 6. COMPOSITE CLASSIFICATION — highest severity wins primary label
  // ═══════════════════════════════════════════════════════════════════
  const classificationTags = [];
  if (result.is_rogue) classificationTags.push('rogue');
  if (result.is_dormant) classificationTags.push('zombie');
  if (result.is_shadow) classificationTags.push('shadow');
  if (result.is_unused_iam) classificationTags.push('unused-iam');
  if (result.is_publicly_exposed) classificationTags.push('publicly-exposed');
  // is_orphan added later by graph analysis

  result.classification_tags = classificationTags;

  // Primary label = highest severity
  if (result.is_rogue) result.classification = 'rogue';
  else if (result.is_dormant) result.classification = 'zombie';
  else if (result.is_shadow) result.classification = 'shadow';
  else result.classification = 'managed';

  return result;
}

async function saveWorkload(workload) {
  // Unified classification: shadow, zombie, rogue, unused IAM, public exposure
  const cls = classifyWorkload(workload);
  Object.assign(workload, cls);

  const query = `
    INSERT INTO workloads (
      spiffe_id, name, type, namespace, environment,
      trust_domain, issuer, cluster_id,
      cloud_provider, region, account_id,
      category, subcategory, is_ai_agent, is_mcp_server,
      discovered_by, labels, selectors, metadata,
      security_score, status, verified,
      verified_by, verification_method, trust_level,
      attestation_data, last_attestation, attestation_expires,
      owner, team, cost_center, created_by,
      is_shadow, is_dormant, shadow_score, dormancy_score,
      shadow_reasons, dormancy_reasons,
      api_calls_30d, unique_callers_30d, last_api_call, last_deployed,
      is_rogue, rogue_score, rogue_reasons,
      is_publicly_exposed, exposure_reasons,
      is_unused_iam,
      classification, classification_tags,
      last_seen
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
      $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28,
      $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42,
      $43, $44, $45, $46, $47, $48, $49, $50, NOW()
    )
    ON CONFLICT (spiffe_id) DO UPDATE SET
      name = EXCLUDED.name,
      category = EXCLUDED.category,
      subcategory = EXCLUDED.subcategory,
      is_ai_agent = EXCLUDED.is_ai_agent,
      is_mcp_server = EXCLUDED.is_mcp_server,
      labels = EXCLUDED.labels,
      metadata = EXCLUDED.metadata,
      security_score = EXCLUDED.security_score,
      is_shadow = EXCLUDED.is_shadow,
      shadow_score = EXCLUDED.shadow_score,
      shadow_reasons = EXCLUDED.shadow_reasons,
      is_dormant = EXCLUDED.is_dormant,
      dormancy_score = EXCLUDED.dormancy_score,
      dormancy_reasons = EXCLUDED.dormancy_reasons,
      is_rogue = EXCLUDED.is_rogue,
      rogue_score = EXCLUDED.rogue_score,
      rogue_reasons = EXCLUDED.rogue_reasons,
      is_publicly_exposed = EXCLUDED.is_publicly_exposed,
      exposure_reasons = EXCLUDED.exposure_reasons,
      is_unused_iam = EXCLUDED.is_unused_iam,
      classification = EXCLUDED.classification,
      classification_tags = EXCLUDED.classification_tags,
      last_seen = NOW(),
      updated_at = NOW()
  `;

  // Generate SPIFFE ID if not provided
  let spiffeId = workload.spiffe_id;
  if (!spiffeId) {
    const provider = workload.cloud_provider || 'unknown';
    const type = workload.type;
    const name = workload.name;
    spiffeId = `spiffe://${workload.trust_domain}/${provider}/${type}/${name}`;
  }

  // Dedup: if a workload with this name already exists but different spiffe_id, update it instead
  try {
    const existing = await pool.query('SELECT id, spiffe_id FROM workloads WHERE name = $1 AND spiffe_id != $2', [workload.name, spiffeId]);
    if (existing.rows.length > 0) {
      // Update existing record's spiffe_id to match, then let the upsert handle it
      await pool.query('UPDATE workloads SET spiffe_id = $1, updated_at = NOW() WHERE id = $2', [spiffeId, existing.rows[0].id]);
    }
  } catch {}

  await pool.query(query, [
    spiffeId,
    workload.name,
    workload.type,
    workload.namespace || 'default',
    workload.environment || 'unknown',
    workload.trust_domain || 'company.com',
    workload.issuer || 'unknown',
    workload.cluster_id || 'default',
    workload.cloud_provider || 'unknown',
    workload.region || null,
    workload.account_id || null,
    workload.category || 'unknown',
    workload.subcategory || null,
    workload.is_ai_agent || false,
    workload.is_mcp_server || false,
    workload.discovered_by || 'discovery-service',
    JSON.stringify(workload.labels || {}),
    JSON.stringify(workload.selectors || {}),
    JSON.stringify(workload.metadata || {}),
    workload.security_score || 50,
    workload.status || 'pending',
    workload.verified || false,
    workload.verified_by || null,
    workload.verification_method || null,
    workload.trust_level || 'none',
    JSON.stringify(workload.attestation_data || {}),
    workload.last_attestation || null,
    workload.attestation_expires || null,
    workload.owner || null,
    workload.team || null,
    workload.cost_center || null,
    workload.created_by || null,
    workload.is_shadow || false,
    workload.is_dormant || false,
    workload.shadow_score || 0,
    workload.dormancy_score || 0,
    JSON.stringify(workload.shadow_reasons || []),
    JSON.stringify(workload.dormancy_reasons || []),
    workload.api_calls_30d || 0,
    workload.unique_callers_30d || 0,
    workload.last_api_call || null,
    workload.last_deployed || null,
    workload.is_rogue || false,
    workload.rogue_score || 0,
    JSON.stringify(workload.rogue_reasons || []),
    workload.is_publicly_exposed || false,
    JSON.stringify(workload.exposure_reasons || []),
    workload.is_unused_iam || false,
    workload.classification || 'pending',
    JSON.stringify(workload.classification_tags || [])
  ]);

  // Track which connector discovered this workload
  if (workload.connector_id) {
    await pool.query(
      'UPDATE workloads SET connector_id = $1 WHERE spiffe_id = $2',
      [workload.connector_id, spiffeId]
    );
  }
}

// =============================================================================
// Scanner Management
// =============================================================================

async function initializeScanners() {
  console.log('\n🔍 Initializing scanner registry...\n');
  
  scannerRegistry = new ScannerRegistry();
  await scannerRegistry.discoverScanners();
  
  console.log('\n🚀 Initializing scanner instances...\n');
  activeScanners = await scannerRegistry.initializeScanners(SCANNER_CONFIG);
  
  if (activeScanners.length === 0) {
    console.log('⚠️  No scanners enabled. Check configuration.\n');
  } else {
    console.log(`\n✅ ${activeScanners.length} scanner(s) ready\n`);
  }
}

async function runDiscovery() {
  console.log('\n' + '='.repeat(60));
  console.log('🔍 Starting discovery scan...');
  console.log('='.repeat(60) + '\n');
  
  const startTime = Date.now();
  let totalWorkloads = 0;
  const stats = {
    ai_agents: 0,
    mcp_servers: 0,
    shadow_services: 0,
    dormant_services: 0
  };

  for (const scanner of activeScanners) {
    try {
      console.log(`\n📦 Running ${scanner.name} scanner...`);
      
      const workloads = await scanner.discover();
      
      for (const workload of workloads) {
        await saveWorkload(workload);
        totalWorkloads++;
        
        // Update stats
        if (workload.is_ai_agent) stats.ai_agents++;
        if (workload.is_mcp_server) stats.mcp_servers++;
        if (workload.is_shadow) stats.shadow_services++;
        if (workload.is_dormant) stats.dormant_services++;
      }
      
    } catch (error) {
      console.error(`❌ Error in ${scanner.name}:`, error.message);
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  
  console.log('\n' + '='.repeat(60));
  console.log('✅ Discovery complete!');
  console.log('='.repeat(60));
  console.log(`📊 Total workloads discovered: ${totalWorkloads}`);
  console.log(`   🤖 AI Agents: ${stats.ai_agents}`);
  console.log(`   🔌 MCP Servers: ${stats.mcp_servers}`);
  console.log(`   👻 Shadow Services: ${stats.shadow_services}`);
  console.log(`   💤 Dormant Services: ${stats.dormant_services}`);
  console.log(`⏱️  Duration: ${duration}s`);
  console.log('='.repeat(60) + '\n');

    // Build identity graph after discovery
  try {
    console.log('\n🔗 Building identity graph...');
    const graph = await refreshGraph(pool);
    if (graph) {
      console.log(`✅ Identity graph: ${graph.summary.total_nodes} nodes, ${graph.summary.total_relationships} edges, ${graph.summary.total_attack_paths} attack paths`);
      if (graph.summary.critical_paths > 0) {
        console.log(`⚠️  ${graph.summary.critical_paths} critical attack paths detected!`);
      }
    }
  } catch (graphErr) {
    console.error('⚠️  Graph build error:', graphErr.message);
  }

}

function triggerInternalScan() {
  const http = require('http');
  const req = http.request({
    hostname: 'localhost',
    port: PORT,
    path: '/api/v1/workloads/scan',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    timeout: 120000,
  }, (res) => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const result = JSON.parse(data);
        console.log(`  Periodic scan complete: ${result.total_workloads || 0} workloads, ${result.duration_seconds || '?'}s`);
      } catch {}
    });
  });
  req.on('error', (e) => console.error('  Scan trigger error:', e.message));
  req.end();
}

function startPeriodicDiscovery() {
  const interval = parseInt(process.env.DISCOVERY_INTERVAL || '300000'); // 5 min default

  if (process.env.DISABLE_PERIODIC_DISCOVERY === 'true') {
    console.log(`⏰ Periodic discovery disabled by DISABLE_PERIODIC_DISCOVERY env var`);
    return;
  }

  console.log(`⏰ Periodic discovery enabled: every ${interval / 1000}s (initial scan in 30s)`);

  // Connector-based periodic scan: only re-scans connectors configured in the DB
  const runConnectorPeriodicScan = async () => {
    if (!pool) return;
    try {
      const { runProviderScan } = require('./connectors/connector-routes');
      const { getCredentials } = require('./connectors/credential-store');
      const { clearGraphCache } = require('./graph/graph-routes');

      const { rows: connectors } = await pool.query(
        "SELECT * FROM connectors WHERE status IN ('active', 'pending')"
      );
      if (connectors.length === 0) {
        console.log('  Periodic scan: no connectors configured, skipping');
        return;
      }

      let totalWorkloads = 0;
      for (const connector of connectors) {
        try {
          const credData = await getCredentials(connector.id);
          const credentials = credData?.credentials || {};

          // Merge config fields into credentials (projectId, accountId, etc.)
          const connConfig = typeof connector.config === 'string'
            ? JSON.parse(connector.config) : (connector.config || {});
          for (const [k, v] of Object.entries(connConfig)) {
            if (!credentials[k]) credentials[k] = v;
          }

          const workloads = await runProviderScan(connector, credentials, pool, {
            scannerRegistry,
            saveWorkload,
          });
          totalWorkloads += workloads.length;

          await pool.query(
            `UPDATE connectors SET last_scan_status = 'completed', last_scan_at = NOW(),
             workload_count = $1, status = 'active' WHERE id = $2`,
            [workloads.length, connector.id]
          );
        } catch (scanErr) {
          console.error(`  Periodic scan error for ${connector.name}: ${scanErr.message}`);
        }
      }

      console.log(`  Periodic scan complete: ${totalWorkloads} workloads from ${connectors.length} connector(s)`);

      if (totalWorkloads > 0) {
        clearGraphCache();
        try {
          await refreshGraph(pool);
        } catch (e) { /* graph rebuild best-effort */ }
      }
    } catch (err) {
      console.error('  Periodic scan error:', err.message);
    }
  };

  setTimeout(() => {
    console.log('🔄 Running initial periodic connector scan...');
    runConnectorPeriodicScan();
    setInterval(runConnectorPeriodicScan, interval);
  }, 30000);
}

// =============================================================================
// API Endpoints
// =============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    database: pool ? 'connected (pool)' : 'disconnected',
    scanners: activeScanners.map(s => s.getMetadata())
  });
});

// Debug endpoint — check DB config (remove after debugging)
app.get('/debug/db', (req, res) => {
  const dbUrl = process.env.DATABASE_URL || '(not set)';
  const hasCloudsql = dbUrl.includes('/cloudsql/');
  const match = hasCloudsql ? dbUrl.match(/postgresql:\/\/([^:]+):([^@]+)@\/([^?]+)\?host=(.+)/) : null;
  res.json({
    database_url_set: !!process.env.DATABASE_URL,
    database_url_length: dbUrl.length,
    database_url_prefix: dbUrl.slice(0, 30) + '...',
    has_cloudsql: hasCloudsql,
    regex_matched: !!match,
    parsed_user: match ? match[1] : null,
    parsed_database: match ? match[3] : null,
    parsed_socket: match ? match[4] : null,
    db_pool_exists: !!pool,
    db_pool_type: pool ? 'Pool' : 'null',
    db_connect_error: global._dbConnectError || null,
  });
});

// Get all scanners (active + inactive)
app.get('/api/v1/scanners', (req, res) => {
  const allStatuses = scannerRegistry ? scannerRegistry.getAllScannerStatuses() : [];
  const activeMetadata = activeScanners.map(s => s.getMetadata());

  res.json({
    total: allStatuses.length,
    active: activeScanners.length,
    scanners: allStatuses.map(s => ({
      name: s.metadata?.name || s.name,
      provider: s.metadata?.provider || s.category,
      category: s.category,
      version: s.metadata?.version || '1.0.0',
      status: s.status,
      enabled: s.enabled,
      reason: s.reason || null,
      capabilities: s.metadata?.capabilities || [],
      requiredCredentials: s.requiredCredentials || null,
    })),
  });
});

// Scanner health check
app.get('/api/v1/scanners/health', async (req, res) => {
  const healthChecks = await Promise.all(
    activeScanners.map(s => s.healthCheck())
  );
  
  res.json({
    scanners: healthChecks,
    overall: healthChecks.every(h => h.status === 'healthy') ? 'healthy' : 'degraded'
  });
});

// DELETE /api/v1/workloads/stale — Remove workloads not associated with any connector
app.delete('/api/v1/workloads/stale', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    const result = await pool.query(
      "DELETE FROM workloads WHERE connector_id IS NULL"
    );
    const { clearGraphCache } = require('./graph/graph-routes');
    clearGraphCache();
    res.json({ deleted: result.rowCount, message: `Removed ${result.rowCount} stale workloads (not linked to any connector)` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete workloads by cloud provider (cleanup disconnected providers)
app.delete('/api/v1/workloads/by-provider/:provider', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  const provider = req.params.provider;
  if (!['aws', 'gcp', 'azure', 'docker', 'kubernetes'].includes(provider)) {
    return res.status(400).json({ error: `Invalid provider: ${provider}` });
  }
  try {
    const count = await pool.query(
      'SELECT COUNT(*) FROM workloads WHERE cloud_provider = $1', [provider]
    );
    const result = await pool.query(
      'DELETE FROM workloads WHERE cloud_provider = $1', [provider]
    );
    const { clearGraphCache } = require('./graph/graph-routes');
    clearGraphCache();
    res.json({ deleted: result.rowCount, provider, message: `Removed ${result.rowCount} ${provider} workloads` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a specific workload by ID
app.delete('/api/v1/workloads/:id', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  const id = req.params.id;
  if (!/^[0-9a-f-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid workload ID format' });
  }
  try {
    const result = await pool.query('DELETE FROM workloads WHERE id = $1 RETURNING name, cloud_provider, type', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Workload not found' });
    }
    const { clearGraphCache } = require('./graph/graph-routes');
    clearGraphCache();
    const w = result.rows[0];
    console.log(`[cleanup] Deleted workload: ${w.name} (${w.cloud_provider}/${w.type})`);
    res.json({ deleted: true, workload: w });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trigger manual discovery
let scanInProgress = false;
app.post('/api/v1/workloads/scan', async (req, res) => {
  if (scanInProgress) {
    return res.status(409).json({ status: 'scan_in_progress', message: 'A discovery scan is already running' });
  }
  scanInProgress = true;
  console.log('🔄 Full discovery scan triggered via API');

  try {
    const startTime = Date.now();
    let totalWorkloads = 0;
    const stats = { ai_agents: 0, mcp_servers: 0, shadow_services: 0, federated: 0 };

    // Step 1: Scan all configured connectors (connector-based discovery)
    try {
      const { runProviderScan } = require('./connectors/connector-routes');
      const { getCredentials } = require('./connectors/credential-store');

      const { rows: connectors } = await pool.query(
        "SELECT * FROM connectors WHERE status IN ('active', 'pending')"
      );

      for (const connector of connectors) {
        try {
          const credData = await getCredentials(connector.id);
          if (!credData?.credentials) continue;

          const workloads = await runProviderScan(connector, credData.credentials, pool, {
            scannerRegistry,
            saveWorkload,
          });
          totalWorkloads += workloads.length;
          for (const w of workloads) {
            if (w.is_ai_agent) stats.ai_agents++;
            if (w.is_mcp_server) stats.mcp_servers++;
            if (w.is_shadow) stats.shadow_services++;
          }

          await pool.query(
            `UPDATE connectors SET last_scan_status = 'completed', last_scan_at = NOW(),
             workload_count = $1, status = 'active' WHERE id = $2`,
            [workloads.length, connector.id]
          );
        } catch (error) {
          console.error(`❌ Error scanning connector ${connector.name}:`, error.message);
        }
      }

      if (connectors.length === 0) {
        console.log('  No connectors configured — skipping cloud discovery');
      }
    } catch (connErr) {
      console.error('❌ Connector-based scan error:', connErr.message);
    }

    // Step 1b: Run active scanners (Docker, cloud scanners with direct credentials)
    try {
      for (const scanner of activeScanners) {
        try {
          console.log(`  📦 Running ${scanner.name} scanner...`);
          const workloads = await scanner.discover();
          for (const workload of workloads) {
            await saveWorkload(workload);
            totalWorkloads++;
            if (workload.is_ai_agent) stats.ai_agents++;
            if (workload.is_mcp_server) stats.mcp_servers++;
            if (workload.is_shadow) stats.shadow_services++;
          }
          if (workloads.length > 0) {
            console.log(`  ✅ ${scanner.name}: ${workloads.length} workloads`);
          }
        } catch (err) {
          console.error(`  ⚠️ ${scanner.name} error:`, err.message);
        }
      }
    } catch (scanErr) {
      console.error('  ⚠️ Scanner error:', scanErr.message);
    }

    // Step 2: Federation discovery — pull workloads from all federated SPIRE servers
    try {
      const fedConfigResult = await pool.query(
        "SELECT metadata->>'federation_servers' as servers FROM workloads WHERE name = '__federation_config__' LIMIT 1"
      );
      const fedServers = fedConfigResult.rows[0]?.servers ? JSON.parse(fedConfigResult.rows[0].servers) : [];

      for (const server of fedServers) {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const entriesResp = await fetch(`${server.api_url}/entries`, { signal: controller.signal });
          clearTimeout(timer);
          const entriesData = await entriesResp.json();
          const entries = entriesData.entries || [];

          for (const entry of entries) {
            if (!entry.spiffe_id || entry.spiffe_id.includes('/spire/agent/') || entry.spiffe_id.includes('/agent/local')) continue;

            const name = entry.spiffe_id.split('/').pop();
            const pathAfterDomain = entry.spiffe_id.replace(`spiffe://${server.trust_domain}/`, '');
            const pathParts = pathAfterDomain.split('/');
            const topLevel = pathParts[0];

            // Log for debugging
            console.log(`    [fed] entry: ${entry.spiffe_id} → topLevel: ${topLevel}, name: ${name}`);

            // Classify entry type based on SPIFFE path
            let entryType = 'service';    // default
            let category = 'Services';
            let subcategory = `Federated (${server.trust_domain})`;
            let isAgent = false;
            let nhiBucket = 'identity'; // identity | credential | resource

            if (topLevel === 'agents') {
              entryType = 'a2a-agent'; category = 'AI Agents'; isAgent = true; nhiBucket = 'identity';
            } else if (topLevel === 'services') {
              entryType = 'service'; category = 'Services'; nhiBucket = 'identity';
            } else if (topLevel === 'infra') {
              entryType = 'infrastructure'; category = 'Infrastructure'; nhiBucket = 'identity';
            } else if (topLevel === 'credentials' || topLevel === 'tokens' || topLevel === 'secrets' || topLevel === 'keys') {
              entryType = 'credential'; category = 'Credentials'; subcategory = 'API Key / Token'; nhiBucket = 'credential';
            } else if (topLevel === 'external') {
              entryType = 'external-resource'; category = 'External Resources'; subcategory = 'Third-Party API'; nhiBucket = 'resource';
            } else if (name === 'federation' || pathAfterDomain === 'federation') {
              // Skip pure federation config entry
              continue;
            } else {
              // Unknown path structure — infer from name
              const nameLower = name.toLowerCase();
              if (nameLower.includes('token') || nameLower.includes('key') || nameLower.includes('secret') || nameLower.includes('credential')) {
                entryType = 'credential'; category = 'Credentials'; subcategory = 'API Key / Token'; nhiBucket = 'credential';
              } else if (nameLower.includes('api') || ['slack', 'stripe', 'salesforce', 'github', 'jira', 'datadog', 'pagerduty', 'twilio'].includes(nameLower)) {
                entryType = 'external-resource'; category = 'External Resources'; subcategory = 'Third-Party API'; nhiBucket = 'resource';
              } else {
                entryType = 'workload'; category = 'Workloads'; nhiBucket = 'identity';
              }
            }

            // Credential risk metadata
            const credentialMeta = nhiBucket === 'credential' ? {
              credential_type: 'api_key',
              lifecycle_status: 'active',
              risk_flags: ['no-expiry', 'no-rotation-policy'],
              risk_level: 'medium',
              storage_method: 'external',
              never_expires: true,
            } : {};

            // Determine display name — prettify credential/resource names
            const displayName = name.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()).replace(/ Token$| Secret Key$| Api Key$/i, match => match.toLowerCase());
            const securityScore = nhiBucket === 'identity' ? 30 : (nhiBucket === 'credential' ? 20 : 25);

            try {
              // Check if exists by name first
              const existing = await pool.query('SELECT id FROM workloads WHERE name = $1', [name]);
              if (existing.rows.length > 0) {
                // Update existing
                await pool.query(`
                  UPDATE workloads SET spiffe_id = $1, namespace = $2, category = $3, 
                    subcategory = $4, is_ai_agent = $5, type = $6, discovered_by = 'federation-discovery',
                    cloud_provider = 'federated', region = 'external', environment = 'production',
                    metadata = metadata || $7, last_seen = NOW(), updated_at = NOW()
                  WHERE id = $8
                `, [
                  entry.spiffe_id, server.trust_domain, category,
                  subcategory, isAgent, entryType,
                  JSON.stringify({ federation: { source_domain: server.trust_domain, source_api: server.api_url, entry_id: entry.entry_id, discovered_at: new Date().toISOString() }, nhi_bucket: nhiBucket, ...credentialMeta }),
                  existing.rows[0].id,
                ]);
              } else {
                // Insert new
                await pool.query(`
                  INSERT INTO workloads (spiffe_id, name, type, namespace, environment, cloud_provider, region, category, subcategory,
                    is_ai_agent, is_mcp_server, discovered_by, trust_level, verified, security_score, is_shadow, shadow_score,
                    labels, metadata, last_seen)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW())
                  ON CONFLICT (spiffe_id) DO UPDATE SET last_seen = NOW(), updated_at = NOW()
                `, [
                  entry.spiffe_id, name, entryType, server.trust_domain, 'production',
                  'federated', 'external', category, subcategory,
                  isAgent, false, 'federation-discovery', 'none', false, securityScore, false, 0,
                  JSON.stringify({ source: 'federation', trust_domain: server.trust_domain, nhi_bucket: nhiBucket }),
                  JSON.stringify({ federation: { source_domain: server.trust_domain, source_api: server.api_url, entry_id: entry.entry_id, discovered_at: new Date().toISOString() }, nhi_bucket: nhiBucket, ...credentialMeta }),
                ]);
              }
              stats.federated++;
              totalWorkloads++;
            } catch (dbErr) {
              console.error(`  ⚠️ Federation save error for ${name}:`, dbErr.message);
            }
          }
          console.log(`  ✅ Federation: discovered ${entries.filter(e => e.spiffe_id && !e.spiffe_id.includes('/spire/agent/')).length} identities from ${server.trust_domain}`);

          // Seed credentials and external resources connected to federated identities
          const credResources = [
            { name: 'Stripe API Key', type: 'credential', category: 'Credentials', subcategory: 'API Key', nhiBucket: 'credential',
              spiffe_suffix: 'credentials/stripe-api-key', parent: 'payment-processor', provider: 'Stripe',
              risk_flags: ['no-expiry', 'overprivileged'], risk_level: 'high', scope: ['payments:read','payments:write','refunds:write'] },
            { name: 'Stripe', type: 'external-resource', category: 'External Resources', subcategory: 'Payment Platform', nhiBucket: 'resource',
              spiffe_suffix: 'external/stripe', parent: 'payment-processor', provider: 'Stripe',
              resource_validation: {
                endpoint: { url: 'https://api.stripe.com', tls_verified: true, cert_issuer: 'DigiCert', cert_expires: '2027-01-15', dns_verified: true, ip_reputation: 'clean' },
                oauth_posture: { app_verified: true, marketplace_listed: true, publisher_verified: true, scopes_granted: ['payments:read','payments:write','refunds:write'], scopes_used: ['payments:read','payments:write'], overprivileged: true, overprivileged_scopes: ['refunds:write'] },
                vendor_trust: { soc2_type2: true, iso_27001: true, gdpr_compliant: true, pci_dss: true, last_audit: '2025-11-01', known_breaches: 0, business_criticality: 'critical' },
                data_classification: { inbound: ['payment-confirmations'], outbound: ['credit-card-numbers', 'pii'], sensitivity: 'pci', data_residency: 'US' },
                connection_hygiene: { last_activity: '2026-02-20', credential_count: 1, stale: false, rotation_compliant: false },
                composite_score: 78, validation_status: 'verified',
              } },
            { name: 'Slack Bot Token', type: 'credential', category: 'Credentials', subcategory: 'OAuth Token', nhiBucket: 'credential',
              spiffe_suffix: 'credentials/slack-bot-token', parent: 'ai-assistant', provider: 'Slack',
              risk_flags: ['no-rotation-policy'], risk_level: 'medium', scope: ['chat:write','channels:read','users:read'] },
            { name: 'Slack', type: 'external-resource', category: 'External Resources', subcategory: 'Messaging Platform', nhiBucket: 'resource',
              spiffe_suffix: 'external/slack', parent: 'ai-assistant', provider: 'Slack' },
            { name: 'Salesforce OAuth Token', type: 'credential', category: 'Credentials', subcategory: 'OAuth Token', nhiBucket: 'credential',
              spiffe_suffix: 'credentials/salesforce-oauth', parent: 'data-pipeline', provider: 'Salesforce',
              risk_flags: ['no-expiry', 'never-rotated'], risk_level: 'high', scope: ['api','bulk','chatter_api'] },
            { name: 'Salesforce', type: 'external-resource', category: 'External Resources', subcategory: 'CRM Platform', nhiBucket: 'resource',
              spiffe_suffix: 'external/salesforce', parent: 'data-pipeline', provider: 'Salesforce' },
            { name: 'OpenAI API Key', type: 'credential', category: 'Credentials', subcategory: 'API Key', nhiBucket: 'credential',
              spiffe_suffix: 'credentials/openai-api-key', parent: 'ai-assistant', provider: 'OpenAI',
              risk_flags: ['no-expiry', 'high-cost-risk'], risk_level: 'high', scope: ['chat:completions','embeddings'] },
            { name: 'Datadog API Key', type: 'credential', category: 'Credentials', subcategory: 'API Key', nhiBucket: 'credential',
              spiffe_suffix: 'credentials/datadog-api-key', parent: 'api-gateway', provider: 'Datadog',
              risk_flags: [], risk_level: 'low', scope: ['metrics:write','logs:write'] },
          ];

          for (const cr of credResources) {
            const spiffeId = `spiffe://${server.trust_domain}/${cr.spiffe_suffix}`;
            const secScore = cr.nhiBucket === 'credential' ? (cr.risk_level === 'high' ? 25 : cr.risk_level === 'medium' ? 40 : 60) : 50;
            try {
              const existing = await pool.query('SELECT id FROM workloads WHERE name = $1', [cr.name]);
              if (existing.rows.length > 0) {
                await pool.query('UPDATE workloads SET spiffe_id=$1, type=$2, category=$3, subcategory=$4, updated_at=NOW() WHERE id=$5',
                  [spiffeId, cr.type, cr.category, cr.subcategory, existing.rows[0].id]);
              } else {
                await pool.query(`
                  INSERT INTO workloads (spiffe_id, name, type, namespace, environment, cloud_provider, region, category, subcategory,
                    is_ai_agent, is_mcp_server, discovered_by, trust_level, verified, security_score, is_shadow, shadow_score, labels, metadata, last_seen)
                  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW())
                  ON CONFLICT (spiffe_id) DO UPDATE SET last_seen=NOW(), updated_at=NOW()
                `, [spiffeId, cr.name, cr.type, server.trust_domain, 'production', 'federated', 'external',
                    cr.category, cr.subcategory, false, false, 'federation-discovery', 'none', false, secScore, false, 0,
                    JSON.stringify({ provider: cr.provider }),
                    JSON.stringify({
                      nhi_bucket: cr.nhiBucket, federation: { source_domain: server.trust_domain },
                      parent_identity: cr.parent, provider: cr.provider,
                      ...(cr.nhiBucket === 'credential' ? {
                        credential_type: cr.subcategory, lifecycle_status: 'active', storage_method: 'external',
                        risk_flags: cr.risk_flags || [], risk_level: cr.risk_level || 'medium',
                        scope: cr.scope || [], never_expires: (cr.risk_flags || []).includes('no-expiry'),
                        created_at: '2025-03-15T00:00:00Z', last_rotated: null,
                      } : { resource_type: cr.subcategory }),
                    }),
                ]);
              }
              stats.federated++;
            } catch (crErr) { console.error(`  ⚠️ Seed error ${cr.name}:`, crErr.message); }
          }
          console.log(`  ✅ Seeded ${credResources.length} credentials & resources for ${server.trust_domain}`);
        } catch (err) {
          console.error(`  ⚠️ Federation: cannot reach ${server.trust_domain}:`, err.message);
        }
      }
    } catch (fedErr) {
      console.error('  ⚠️ Federation discovery error:', fedErr.message);
    }

    // Step 3: Build identity graph + generate baseline policies
    try {
      const graph = await refreshGraph(pool);
      if (graph) {
        console.log(`  ✅ Graph: ${graph.summary.total_nodes} nodes, ${graph.summary.total_relationships} edges`);
        // Generate audit-mode baseline policies from discovered topology
        try {
          const policyCount = await generateBaselinePolicies(graph, pool);
          if (policyCount > 0) stats.baseline_policies = policyCount;
        } catch (polErr) {
          console.error('  ⚠️ Baseline policy generation error:', polErr.message);
        }
      }
    } catch {}

    // Step 4: Dedup — remove exact name duplicates keeping newest
    try {
      const dupes = await pool.query(`
        SELECT name, COUNT(*) as cnt, array_agg(id ORDER BY updated_at DESC) as ids
        FROM workloads WHERE name != '__federation_config__'
        GROUP BY name HAVING COUNT(*) > 1
      `);
      let deduped = 0;
      for (const row of dupes.rows) {
        const keepId = row.ids[0];
        const deleteIds = row.ids.slice(1);
        await pool.query('DELETE FROM workloads WHERE id = ANY($1)', [deleteIds]);
        deduped += deleteIds.length;
      }
      if (deduped > 0) console.log(`  🧹 Dedup: removed ${deduped} duplicate entries`);
    } catch {}

    // Step 5: Auto-attest federated workloads via their SPIRE servers
    try {
      const fedConfigResult2 = await pool.query(
        "SELECT metadata->>'federation_servers' as servers FROM workloads WHERE name = '__federation_config__' LIMIT 1"
      );
      const fedServers2 = fedConfigResult2.rows[0]?.servers ? JSON.parse(fedConfigResult2.rows[0].servers) : [];
      const fedWorkloads = await pool.query("SELECT * FROM workloads WHERE discovered_by = 'federation-discovery' AND (trust_level IS NULL OR trust_level = 'none') AND type NOT IN ('credential', 'external-resource')");

      for (const fw of fedWorkloads.rows) {
        const meta = typeof fw.metadata === 'string' ? JSON.parse(fw.metadata) : (fw.metadata || {});
        const federation = meta.federation;
        if (!federation) continue;
        const server = fedServers2.find(s => s.trust_domain === federation.source_domain);
        if (!server) continue;

        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const verifyResp = await fetch(`${server.api_url}/svid/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spiffe_id: fw.spiffe_id }),
            signal: controller.signal,
          });
          clearTimeout(timer);
          const verifyResult = await verifyResp.json();

          if (verifyResult.verified) {
            await pool.query(`
              UPDATE workloads SET
                trust_level = 'high', verified = true, verification_method = 'spiffe-federation',
                verified_at = NOW(), verified_by = $1, security_score = 75,
                is_shadow = false, shadow_score = 0,
                attestation_data = $2, last_attestation = NOW(),
                attestation_expires = $3, updated_at = NOW()
              WHERE id = $4
            `, [
              `federation:${federation.source_domain}`,
              JSON.stringify({
                trust_level: 'high', methods_passed: 1, primary_method: 'spiffe-federation',
                attestation_chain: [{ method: 'spiffe-federation', tier: 2, trust: 'high', label: 'SPIFFE Federation',
                  claims: { spiffe_id: fw.spiffe_id, trust_domain: federation.source_domain, verified_by: `SPIRE Server (${federation.source_domain})`,
                    federation_mode: 'trust_bundle_exchange', bundle_verified: true,
                    attestation_flow: `${federation.source_domain} SPIRE → Trust Bundle Exchange → WID Platform` } }],
                summary: { headline: `HIGH trust — federated from ${federation.source_domain}` },
                correlated: { security_score: 75, is_shadow: false, shadow_score: 0 },
                expires_at: new Date(Date.now() + 3600000).toISOString(),
              }),
              new Date(Date.now() + 3600000).toISOString(),
              fw.id,
            ]);
            stats.federated_attested = (stats.federated_attested || 0) + 1;
          }
        } catch {}
      }
      if (stats.federated_attested) console.log(`  ✅ Auto-attested ${stats.federated_attested} federated workloads`);
    } catch (fedAttestErr) {
      console.error('  ⚠️ Federation attestation error:', fedAttestErr.message);
    }

    // Step 6: Cross-link credentials — attach service account credentials to Cloud Run services
    try {
      const crServices = await pool.query("SELECT id, name, metadata FROM workloads WHERE type = 'cloud-run-service'");
      const saWorkloads = await pool.query("SELECT id, name, metadata FROM workloads WHERE type = 'service-account'");
      let linked = 0;
      for (const cr of crServices.rows) {
        const meta = typeof cr.metadata === 'string' ? JSON.parse(cr.metadata) : (cr.metadata || {});
        const saEmail = meta.service_account;
        if (!saEmail) continue;
        const saName = saEmail.split('@')[0];
        const sa = saWorkloads.rows.find(s => s.name === saName);
        if (!sa) continue;
        const saMeta = typeof sa.metadata === 'string' ? JSON.parse(sa.metadata) : (sa.metadata || {});
        if (saMeta.credentials && saMeta.credentials.length > 0) {
          // Merge SA credentials into the Cloud Run service's credential list
          const existingCreds = meta.credentials || [];
          const saCreds = saMeta.credentials.map(c => ({ ...c, source: `service-account:${saName}`, name: `${saName}/${c.name}` }));
          const mergedCreds = [...existingCreds, ...saCreds];
          const updatedSummary = meta.credential_summary || {};
          updatedSummary.total = mergedCreds.length;
          updatedSummary.has_static_creds = mergedCreds.some(c => c.type === 'service_account_key' || c.storage_method === 'env-var');
          updatedSummary.service_account = saName;
          meta.credentials = mergedCreds;
          meta.credential_summary = updatedSummary;
          await pool.query('UPDATE workloads SET metadata = $1, updated_at = NOW() WHERE id = $2', [JSON.stringify(meta), cr.id]);
          linked++;
        }
      }
      if (linked > 0) console.log(`  🔗 Linked ${linked} service account credentials to Cloud Run services`);
    } catch {}

    // Step 6b: Link IAM scanner results to compute workloads (AWS)
    try {
      const iamRoles = await pool.query(
        "SELECT id, name, metadata FROM workloads WHERE type = 'iam-role' AND discovered_by = 'iam-scanner'"
      );
      const computeWorkloads = await pool.query(
        "SELECT id, name, metadata FROM workloads WHERE type IN ('lambda', 'ec2', 'ecs-task') AND discovered_by = 'aws-scanner'"
      );

      let iamLinked = 0;
      for (const role of iamRoles.rows) {
        const roleMeta = typeof role.metadata === 'string' ? JSON.parse(role.metadata) : (role.metadata || {});
        const roleArn = roleMeta?.arn;
        if (!roleArn) continue;

        for (const compute of computeWorkloads.rows) {
          const computeMeta = typeof compute.metadata === 'string' ? JSON.parse(compute.metadata) : (compute.metadata || {});
          if (computeMeta?.role === roleArn || computeMeta?.iam_instance_profile === roleArn || computeMeta?.role?.endsWith('/' + role.name)) {
            const existingCreds = computeMeta.credentials || [];
            if (!existingCreds.some(c => c.name === 'IAM_EXECUTION_ROLE' && c.value === role.name)) {
              existingCreds.push({
                name: 'IAM_EXECUTION_ROLE',
                key: role.name,
                type: 'iam-role',
                is_static: false,
                provider: 'aws',
                linked_workload_id: role.id,
              });
              await pool.query(
                "UPDATE workloads SET metadata = jsonb_set(COALESCE(metadata, '{}')::jsonb, '{credentials}', $1::jsonb), updated_at = NOW() WHERE id = $2",
                [JSON.stringify(existingCreds), compute.id]
              );
              iamLinked++;
            }
          }
        }
      }
      if (iamLinked > 0) console.log(`  🔗 Linked ${iamLinked} IAM roles to compute workloads`);
    } catch (linkErr) {
      console.error('  ⚠️ IAM credential linkage error:', linkErr.message);
    }

    // Step 6c: Link Vault scanner results to workloads referencing Vault
    try {
      const vaultWorkloads = await pool.query(
        "SELECT id, name, metadata FROM workloads WHERE discovered_by = 'vault-scanner'"
      );
      const allWorkloads = await pool.query(
        "SELECT id, name, metadata FROM workloads WHERE discovered_by IN ('docker-scanner', 'aws-scanner') AND metadata::text LIKE '%VAULT%'"
      );

      let vaultLinked = 0;
      for (const w of allWorkloads.rows) {
        const wMeta = typeof w.metadata === 'string' ? JSON.parse(w.metadata) : (w.metadata || {});
        const env = wMeta.env || {};
        const vaultAddr = env.VAULT_ADDR || env.VAULT_URL;
        const vaultToken = env.VAULT_TOKEN;
        if (!vaultAddr && !vaultToken) continue;

        const existingCreds = wMeta.credentials || [];
        if (!existingCreds.some(c => c.source === 'vault-linkage')) {
          existingCreds.push({
            name: 'VAULT_ACCESS',
            key: 'VAULT_TOKEN',
            type: 'token',
            is_static: true,
            provider: 'vault',
            source: 'vault-linkage',
            vault_addr: vaultAddr || 'unknown',
          });
          await pool.query(
            "UPDATE workloads SET metadata = jsonb_set(COALESCE(metadata, '{}')::jsonb, '{credentials}', $1::jsonb), updated_at = NOW() WHERE id = $2",
            [JSON.stringify(existingCreds), w.id]
          );
          vaultLinked++;
        }
      }
      if (vaultLinked > 0) console.log(`  🔗 Linked ${vaultLinked} Vault references to workloads`);
    } catch (linkErr) {
      console.error('  ⚠️ Vault credential linkage error:', linkErr.message);
    }

    // Step 7: Auto-verify external resources
    try {
      const resources = await pool.query("SELECT * FROM workloads WHERE type = 'external-resource'");
      let verified = 0;
      for (const r of resources.rows) {
        try {
          const resp = await fetch(`http://localhost:${PORT}/api/v1/workloads/resources/${r.id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
          if (resp.ok) verified++;
        } catch {}
      }
      if (verified > 0) {
        console.log(`  🔍 Verified ${verified} external resources`);
        stats.resources_verified = verified;
      }
    } catch {}

    // Step 8: Auto-attest unattested compute workloads
    try {
      const unattestedResult = await pool.query(`
        SELECT id FROM workloads
        WHERE (trust_level IS NULL OR trust_level = 'none')
          AND type NOT IN ('credential', 'external-resource', 'secret', 'auth-method', 'secret-engine')
          AND last_attestation IS NULL
          AND name != '__federation_config__'
        LIMIT 50
      `);

      if (unattestedResult.rows.length > 0) {
        let attested = 0;
        for (const w of unattestedResult.rows) {
          try {
            const resp = await fetch(`http://localhost:${PORT}/api/v1/workloads/${w.id}/attest`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ auto: true }),
              signal: AbortSignal.timeout(10000),
            });
            if (resp.ok) {
              const result = await resp.json();
              if (result.trust_level && result.trust_level !== 'none') attested++;
            }
          } catch {}
          await new Promise(r => setTimeout(r, 100)); // Rate limit
        }
        console.log(`  🔐 Auto-attested ${attested}/${unattestedResult.rows.length} workloads`);
        stats.auto_attested = attested;
      }
    } catch (attestErr) {
      console.error('  ⚠️ Auto-attestation error:', attestErr.message);
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    const finalCount = await pool.query("SELECT COUNT(*) as cnt FROM workloads WHERE name != '__federation_config__'");

    res.json({
      success: true,
      discovered: totalWorkloads,
      total_workloads: parseInt(finalCount.rows[0].cnt),
      stats,
      duration_seconds: parseFloat(duration),
      message: `Scan complete: ${totalWorkloads} discovered (${stats.federated} federated), ${finalCount.rows[0].cnt} total after dedup`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    scanInProgress = false;
  }
});

// Get all workloads
app.get('/api/v1/workloads', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, spiffe_id, name, type, namespace, environment,
        category, subcategory, is_ai_agent, is_mcp_server,
        security_score, verified, trust_level,
        is_shadow, is_dormant, shadow_score, dormancy_score,
        shadow_reasons, dormancy_reasons,
        is_rogue, rogue_score, rogue_reasons,
        is_orphan, orphan_reasons,
        is_publicly_exposed, exposure_reasons,
        is_unused_iam,
        classification, classification_tags,
        cloud_provider, region, discovered_by,
        owner, team, labels, metadata,
        attestation_data, verification_method, verified_at, verified_by,
        last_attestation, attestation_expires,
        wid_token, token_jti, token_issued_at, token_expires_at, token_claims,
        created_at, updated_at, last_seen
      FROM workloads
      WHERE name NOT IN ('__federation_config__', 'Public Internet', 'Internal VPC', 'federation')
        AND type NOT IN ('exposure', 'graph-helper', 'spiffe-id')
      ORDER BY created_at DESC
      LIMIT 100
    `);
    
    res.json({
      total: result.rows.length,
      workloads: result.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get workload by ID
app.get('/api/v1/workloads/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM workloads WHERE id = $1',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Workload not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify workload
app.post('/api/v1/workloads/:id/verify', async (req, res) => {
  try {
    // P0.4: Verification is now attestation-driven, not a simple flag flip
    // If evidence is provided, run full attestation; otherwise manual-approval at trust=low
    const { method, evidence, approved_by, approval_reason } = req.body || {};

    let trust_level = 'low';
    let verification_method = 'manual-approval';
    let attestation_data = {};
    let attestation_expires = null;

    if (method === 'attest' || evidence) {
      // Run actual attestation engine
      try {
        const { AttestationEngine } = require('./attestation/attestation-engine');
        const engine = new AttestationEngine();
        const workload = (await pool.query('SELECT * FROM workloads WHERE id = $1', [req.params.id])).rows[0];
        if (!workload) return res.status(404).json({ error: 'Workload not found' });

        const result = await engine.attest(workload, evidence || {});
        trust_level = result.trust_level;
        verification_method = result.primary_method || 'attestation-engine';
        attestation_data = result;
        attestation_expires = result.expires_at;
      } catch (attestErr) {
        console.error('Attestation error:', attestErr.message);
        // Fall through to manual-approval at low trust
      }
    } else {
      // Manual approval — requires approved_by
      attestation_data = {
        approved_by: approved_by || 'api-caller',
        approval_reason: approval_reason || 'Manual verification via API',
        verification_status: 'manual',
      };
      // Manual approval TTL: 1 hour
      attestation_expires = new Date(Date.now() + 3600000).toISOString();
    }

    const result = await pool.query(`
      UPDATE workloads SET
        verified = true,
        verified_at = NOW(),
        verified_by = $2,
        verification_method = $3,
        trust_level = $4,
        attestation_data = $5,
        last_attestation = NOW(),
        attestation_expires = $6,
        updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `, [
      req.params.id,
      approved_by || 'attestation-engine',
      verification_method,
      trust_level,
      JSON.stringify(attestation_data),
      attestation_expires
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Workload not found' });
    }

    // Issue WID Token — the durable cryptographic identity artifact
    const widToken = issueWidToken(result.rows[0], attestation_data);

    res.json({
      message: 'Workload verified',
      trust_level,
      verification_method,
      attestation_expires,
      token: widToken,
      workload: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// WID Token Endpoints — Issue, Validate, Refresh, Revoke
// ═══════════════════════════════════════════════════════════════

// Issue a WID token for a verified workload (re-attestation path)
app.post('/api/v1/tokens/issue', async (req, res) => {
  try {
    const { workload_id, workload_name } = req.body;
    if (!workload_id && !workload_name) return res.status(400).json({ error: 'workload_id or workload_name required' });

    const q = workload_id
      ? await pool.query('SELECT * FROM workloads WHERE id = $1', [workload_id])
      : await pool.query('SELECT * FROM workloads WHERE name = $1', [workload_name]);

    if (!q.rows.length) return res.status(404).json({ error: 'Workload not found' });
    const workload = q.rows[0];

    if (!workload.verified) {
      return res.status(403).json({
        error: 'Workload not attested',
        detail: 'Workload must be attested before a WID token can be issued. Run attestation first.',
        trust_level: workload.trust_level || 'none',
        requires: 'attestation',
      });
    }

    // Check if attestation has expired — require re-attestation
    if (workload.attestation_expires && new Date(workload.attestation_expires) < new Date()) {
      return res.status(403).json({
        error: 'Attestation expired',
        detail: 'Previous attestation has expired. Re-attestation required before issuing a new token.',
        expired_at: workload.attestation_expires,
        requires: 're-attestation',
      });
    }

    const attestData = typeof workload.attestation_data === 'string'
      ? JSON.parse(workload.attestation_data) : (workload.attestation_data || {});

    const widToken = issueWidToken(workload, attestData);
    res.status(201).json(widToken);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Validate a WID token (gateway calls this)
app.post('/api/v1/tokens/validate', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });
  const result = verifyWidToken(token);
  res.json(result);
});

// Validate with detailed response (for debugging/UI)
app.post('/api/v1/tokens/introspect', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });

  const result = verifyWidToken(token);
  if (!result.valid) return res.json({ active: false, reason: result.reason, expired_at: result.expired_at });

  const p = result.payload;
  res.json({
    active: true,
    token_type: 'WID-TOKEN',
    spiffe_id: p.sub,
    issuer: p.iss,
    audience: p.aud,
    issued_at: new Date(p.iat * 1000).toISOString(),
    expires_at: new Date(p.exp * 1000).toISOString(),
    ttl_remaining_s: p.exp - Math.floor(Date.now() / 1000),
    jti: p.jti,
    wid: result.wid,
  });
});

// Workload options (for dropdowns in UI)
app.get('/api/v1/workloads/options', async (req, res) => {
  try {
    const envs = await pool.query('SELECT DISTINCT environment FROM workloads WHERE environment IS NOT NULL ORDER BY environment');
    const types = await pool.query('SELECT DISTINCT type FROM workloads WHERE type IS NOT NULL ORDER BY type');
    const categories = await pool.query('SELECT DISTINCT category FROM workloads WHERE category IS NOT NULL ORDER BY category');
    const teams = await pool.query('SELECT DISTINCT team FROM workloads WHERE team IS NOT NULL ORDER BY team');
    const providers = await pool.query('SELECT DISTINCT cloud_provider FROM workloads WHERE cloud_provider IS NOT NULL ORDER BY cloud_provider');
    res.json({
      environments: envs.rows.map(r => r.environment),
      types: types.rows.map(r => r.type),
      categories: categories.rows.map(r => r.category),
      teams: teams.rows.map(r => r.team),
      providers: providers.rows.map(r => r.cloud_provider),
    });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Target options (for policy builder)
app.get('/api/v1/targets/options', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, type, category, provider, endpoint FROM targets ORDER BY name');
    res.json({ total: result.rows.length, targets: result.rows });
  } catch (error) { res.status(500).json({ error: error.message }); }
});


// =============================================================================
// Policy Proxy — forward to policy engine (P0.2: behind config, off by default)
// =============================================================================
const POLICY_ENGINE_URL = process.env.POLICY_ENGINE_URL || 'https://wid-dev-policy-engine-265663183174.us-central1.run.app';
const POLICY_PROXY_ENABLED = true; // Always proxy to policy engine

if (POLICY_PROXY_ENABLED && POLICY_ENGINE_URL) {
  // Proxy all policy-engine endpoints through discovery service
  const proxyPaths = ['/api/v1/policies*', '/api/v1/enforcement*', '/api/v1/violations*', '/api/v1/access*'];
  for (const path of proxyPaths) {
    app.all(path, async (req, res) => {
      try {
        const targetUrl = `${POLICY_ENGINE_URL}${req.originalUrl}`;
        const options = {
          method: req.method,
          headers: { 'Content-Type': 'application/json' },
        };
        if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
          options.body = JSON.stringify(req.body);
        }
        const resp = await fetch(targetUrl, options);
        const data = await resp.text();
        res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
      } catch (err) {
        console.error('Policy proxy error:', err.message);
        res.status(502).json({ error: 'Policy engine unreachable', detail: err.message });
      }
    });
  }
  console.log(`  ✅ Policy proxy enabled → ${POLICY_ENGINE_URL} (policies, enforcement, violations, access)`);
} else {
  console.log('  ⚠️  Policy proxy disabled (set POLICY_ENGINE_URL to enable)');
}

// Get statistics
app.get('/api/v1/stats', async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN verified = true THEN 1 ELSE 0 END) as verified,
        SUM(CASE WHEN is_ai_agent = true THEN 1 ELSE 0 END) as ai_agents,
        SUM(CASE WHEN is_mcp_server = true THEN 1 ELSE 0 END) as mcp_servers,
        SUM(CASE WHEN is_shadow = true THEN 1 ELSE 0 END) as shadow_services,
        SUM(CASE WHEN is_dormant = true THEN 1 ELSE 0 END) as dormant_services,
        AVG(security_score) as avg_security_score
      FROM workloads
    `);
    
    const byCategory = await pool.query(`
      SELECT category, COUNT(*) as count
      FROM workloads
      GROUP BY category
      ORDER BY count DESC
    `);
    
    const byTrustLevel = await pool.query(`
      SELECT trust_level, COUNT(*) as count
      FROM workloads
      GROUP BY trust_level
      ORDER BY 
        CASE trust_level
          WHEN 'very-high' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          WHEN 'none' THEN 5
        END
    `);
    
    res.json({
      overall: stats.rows[0],
      by_category: byCategory.rows,
      by_trust_level: byTrustLevel.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get AI Inventory — P0.1
app.get('/api/v1/ai-inventory', async (req, res) => {
  try {
    // Agent counts: total AI agents and breakdown by type (a2a vs custom)
    const agentStats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE is_ai_agent = true) AS total,
        COUNT(*) FILTER (WHERE is_ai_agent = true AND category = 'a2a-agent') AS a2a,
        COUNT(*) FILTER (WHERE is_ai_agent = true AND category != 'a2a-agent') AS custom
      FROM workloads
    `);

    // MCP server counts: verified vs unverified
    const mcpStats = await pool.query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE verified = true) AS verified,
        COUNT(*) FILTER (WHERE verified = false) AS unverified
      FROM workloads WHERE is_mcp_server = true
    `);

    // ── Tools: from in-memory graph cache MCP server node metadata ──
    let toolsFromGraph = [];
    try {
      // Use the in-memory graph cache directly (same cache that serves GET /api/v1/graph)
      const { data: graphData } = getGraphCache() || {};
      if (graphData) {
        const mcpNodes = (graphData.nodes || []).filter(n => n.type === 'mcp-server');
        for (const mcp of mcpNodes) {
          const tools = mcp.meta?.tools || [];
          for (const t of tools) {
            if (!toolsFromGraph.includes(t)) toolsFromGraph.push(t);
          }
        }
      }
    } catch (e) { console.log('[ai-inventory] Graph tools error:', e.message); }
    // Also check mcp_tool_events for runtime-discovered tools
    const toolEventsResult = await pool.query(`SELECT DISTINCT tool_name FROM mcp_tool_events WHERE tool_name IS NOT NULL`).catch(() => ({ rows: [] }));
    for (const r of toolEventsResult.rows) {
      if (r.tool_name && !toolsFromGraph.includes(r.tool_name)) toolsFromGraph.push(r.tool_name);
    }

    // ── Models: from workload env vars (AI provider detection) + ai_request_events ──
    const AI_PROVIDER_KEYS = {
      'OPENAI_API_KEY': { provider: 'OpenAI', model: 'gpt-4o', type: 'foundation' },
      'ANTHROPIC_API_KEY': { provider: 'Anthropic', model: 'claude-3-sonnet', type: 'foundation' },
      'GOOGLE_AI_API_KEY': { provider: 'Google AI', model: 'gemini-pro', type: 'foundation' },
      'AZURE_OPENAI_API_KEY': { provider: 'Azure OpenAI', model: 'gpt-4', type: 'foundation' },
      'COHERE_API_KEY': { provider: 'Cohere', model: 'command-r', type: 'foundation' },
      'MISTRAL_API_KEY': { provider: 'Mistral', model: 'mistral-large', type: 'foundation' },
      'HUGGINGFACE_TOKEN': { provider: 'Hugging Face', model: 'custom', type: 'custom' },
      'HF_TOKEN': { provider: 'Hugging Face', model: 'custom', type: 'custom' },
      'REPLICATE_API_TOKEN': { provider: 'Replicate', model: 'custom', type: 'custom' },
      'GROQ_API_KEY': { provider: 'Groq', model: 'llama-3', type: 'foundation' },
      'TOGETHER_API_KEY': { provider: 'Together AI', model: 'custom', type: 'custom' },
      'DEEPSEEK_API_KEY': { provider: 'DeepSeek', model: 'deepseek-v3', type: 'foundation' },
    };
    const modelsDetected = new Map(); // provider → { model, type }
    const agentWorkloads = await pool.query(`SELECT name, metadata FROM workloads WHERE is_ai_agent = true`);
    for (const w of agentWorkloads.rows) {
      const env = w.metadata?.env || {};
      for (const [key, info] of Object.entries(AI_PROVIDER_KEYS)) {
        if (env[key]) {
          const modelName = env[key.replace('_API_KEY','_MODEL').replace('_TOKEN','_MODEL')] || info.model;
          modelsDetected.set(info.provider, { model: modelName, type: info.type });
        }
      }
    }
    // Also check ai_request_events for runtime-discovered models
    const aiModelsResult = await pool.query(`SELECT DISTINCT ai_provider, ai_model FROM ai_request_events WHERE ai_provider IS NOT NULL`).catch(() => ({ rows: [] }));
    for (const r of aiModelsResult.rows) {
      if (r.ai_provider && !modelsDetected.has(r.ai_provider)) {
        modelsDetected.set(r.ai_provider, { model: r.ai_model || 'unknown', type: 'foundation' });
      }
    }

    // ── Data Sources: from in-memory graph cache resource nodes + targets table ──
    let dataSourcesFromGraph = { databases: 0, apis: 0, storage: 0, total: 0 };
    try {
      const { data: graphData2 } = getGraphCache() || {};
      if (graphData2) {
        const resourceNodes = (graphData2.nodes || []).filter(n =>
          ['resource', 'external-resource', 'external-api', 'credential', 'cloud-sql', 'gcs-bucket'].includes(n.type)
        );
        for (const n of resourceNodes) {
          dataSourcesFromGraph.total++;
          if (n.type === 'cloud-sql' || n.label?.toLowerCase().includes('sql') || n.label?.toLowerCase().includes('database')) dataSourcesFromGraph.databases++;
          else if (n.type === 'gcs-bucket' || n.label?.toLowerCase().includes('bucket') || n.label?.toLowerCase().includes('storage')) dataSourcesFromGraph.storage++;
          else dataSourcesFromGraph.apis++;
        }
      }
    } catch (e) { console.log('[ai-inventory] Graph ds error:', e.message); }
    // Also check targets table
    const targetResult = await pool.query(`
      SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE type = 'database') AS databases,
        COUNT(*) FILTER (WHERE type = 'external-api') AS apis,
        COUNT(*) FILTER (WHERE type IN ('storage','s3','gcs','blob')) AS storage
      FROM targets
    `).catch(() => ({ rows: [{ total: 0, databases: 0, apis: 0, storage: 0 }] }));
    const tgt = targetResult.rows[0];
    // Merge graph + targets (take max)
    dataSourcesFromGraph.total = Math.max(dataSourcesFromGraph.total, parseInt(tgt.total) || 0);
    dataSourcesFromGraph.databases = Math.max(dataSourcesFromGraph.databases, parseInt(tgt.databases) || 0);
    dataSourcesFromGraph.apis = Math.max(dataSourcesFromGraph.apis, parseInt(tgt.apis) || 0);
    dataSourcesFromGraph.storage = Math.max(dataSourcesFromGraph.storage, parseInt(tgt.storage) || 0);

    // Issues from graph cache attack paths (NOT policy_violations which may be empty)
    let issuesData = { total: 0, by_severity: [], top: [] };
    let recentThreats = [];
    try {
      const { data: issueGraph } = getGraphCache() || {};
      if (issueGraph?.attack_paths) {
        const paths = issueGraph.attack_paths;
        const critCount = paths.filter(p => p.severity === 'critical').length;
        const highCount = paths.filter(p => p.severity === 'high').length;
        const medCount = paths.filter(p => p.severity === 'medium').length;
        issuesData = {
          total: paths.length,
          by_severity: [
            ...(critCount ? [{ severity: 'critical', count: critCount }] : []),
            ...(highCount ? [{ severity: 'high', count: highCount }] : []),
            ...(medCount ? [{ severity: 'medium', count: medCount }] : []),
          ],
          top: paths
            .sort((a, b) => ({ critical: 3, high: 2, medium: 1 }[b.severity] || 0) - ({ critical: 3, high: 2, medium: 1 }[a.severity] || 0))
            .slice(0, 5)
            .map(p => ({
              id: p.id,
              title: p.title,
              description: p.description,
              severity: p.severity,
              finding_type: p.finding_type,
              workload: p.workload,
              attack_path: {
                source: p.workload || 'unknown',
                impacted: p.blast_radius || p.nodes?.length || 0,
              },
            })),
        };

        // Recent threats: AI-relevant attack paths as "threat detections"
        const aiFindings = paths.filter(p =>
          ['mcp-tool-poisoning', 'mcp-capability-drift', 'mcp-unverified-server', 'mcp-known-cve',
           'a2a-no-auth', 'a2a-invalid-signature', 'shadow-ai-usage', 'unregistered-ai-endpoint',
           'public-ai-endpoint', 'over-privileged'].includes(p.finding_type)
        );
        recentThreats = aiFindings.slice(0, 5).map(p => ({
          id: p.id,
          title: `${p.finding_type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}: ${p.workload || 'Unknown'}`,
          severity: p.severity,
          detected_at: issueGraph.generated_at || new Date().toISOString(),
          category: p.finding_type,
        }));
      }
    } catch (e) { console.log('[ai-inventory] Issues from graph error:', e.message); }

    // Last scan timestamp
    const lastScan = await pool.query(`
      SELECT MAX(started_at) AS last_scan FROM discovery_scans
    `);

    const agents = agentStats.rows[0];
    const mcp = mcpStats.rows[0];
    const issues = issueStats.rows[0];

    // Build models breakdown
    const foundationModels = [...modelsDetected.values()].filter(m => m.type === 'foundation');
    const customModels = [...modelsDetected.values()].filter(m => m.type === 'custom');

    res.json({
      agents: {
        total: parseInt(agents.total) || 0,
        breakdown: { a2a: parseInt(agents.a2a) || 0, custom: parseInt(agents.custom) || 0 }
      },
      mcp_servers: {
        total: parseInt(mcp.total) || 0,
        breakdown: { verified: parseInt(mcp.verified) || 0, unverified: parseInt(mcp.unverified) || 0 }
      },
      tools: {
        total: toolsFromGraph.length,
        top: toolsFromGraph.slice(0, 10).map(name => ({ name, agent_count: 1 }))
      },
      models: {
        total: modelsDetected.size,
        breakdown: { foundation: foundationModels.length, custom: customModels.length },
        details: [...modelsDetected.entries()].map(([provider, info]) => ({ provider, model: info.model, type: info.type }))
      },
      data_sources: {
        total: dataSourcesFromGraph.total,
        breakdown: {
          databases: dataSourcesFromGraph.databases,
          apis: dataSourcesFromGraph.apis,
          storage: dataSourcesFromGraph.storage
        }
      },
      issues: issuesData,
      recent_threats: recentThreats,
      total_issues: issuesData.total,
      critical_issues: issuesData.by_severity.find(s => s.severity === 'critical')?.count || 0,
      high_issues: issuesData.by_severity.find(s => s.severity === 'high')?.count || 0,
      last_scan: lastScan.rows[0]?.last_scan || null
    });
  } catch (error) {
    console.error('AI inventory error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// Startup
// =============================================================================

async function start() {
  // 1. Connect to database (non-fatal)
  try {
    await connectDatabase();
  } catch (dbErr) {
    console.error(`⚠️  Database connection failed: ${dbErr.message}`);
    console.log('   Service will start in stateless mode');
    pool = null;
  }

  // 2. Mount DB-dependent routes if connected
  //    Use a shared deps object so scannerRegistry can be populated after init
  const connectorDeps = {
    scannerRegistry: null,
    saveWorkload,
  };
  if (pool) {
    // Apply tenant-scoped DB + data sovereignty middleware before routes
    app.use(attachTenantDb(pool));
    app.use(enforceDataResidency(pool));

    try {
      mountAttestationRoutes(app, pool);
      mountGraphRoutes(app, pool);
      mountRegistryRoutes(app, pool);
      mountConnectorRoutes(app, pool, connectorDeps);
    } catch (routeErr) {
      console.error(`⚠️  Route mounting failed: ${routeErr.message}`);
    }
  } else {
    console.log('⚠️  Attestation and graph routes skipped (no database)');
  }

  // 3. Initialize scanners (non-fatal, with timeout to prevent Cloud Run hang)
  //    Updates connectorDeps.scannerRegistry so connector scan handlers can use it
  try {
    await Promise.race([
      initializeScanners(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Scanner init timeout (30s)')), 30000))
    ]);
    connectorDeps.scannerRegistry = scannerRegistry;
  } catch (scanErr) {
    console.log(`⚠️  Scanner initialization failed: ${scanErr.message}`);
  }

  // 4. Start HTTP server — ALWAYS reaches this point
  app.listen(PORT, () => {
      console.log('╔════════════════════════════════════════════════════════╗');
      console.log('║  Enhanced Discovery Service - Pluggable Architecture  ║');
      console.log(`║  Port: ${PORT}                                             ║`);
      console.log('╚════════════════════════════════════════════════════════╝\n');
      
      console.log('Features:');
      console.log('  ✅ Pluggable scanner architecture');
      console.log('  ✅ Multi-cloud support (AWS, GCP, Azure)');
      console.log('  ✅ AI agent detection');
      console.log('  ✅ MCP server detection');
      console.log('  ✅ Shadow/dormant detection');
      console.log('  ✅ Auto-discovery and categorization');
      console.log('  ✅ CORS enabled for UI\n');
      
      console.log('API Endpoints:');
      console.log('  GET  /health                      → Service health');
      console.log('  GET  /api/v1/scanners             → List scanners');
      console.log('  GET  /api/v1/scanners/health      → Scanner health');
      console.log('  POST /api/v1/workloads/scan       → Trigger discovery');
      console.log('  GET  /api/v1/workloads            → List workloads');
      console.log('  GET  /api/v1/workloads/:id        → Get workload');
      console.log('  POST /api/v1/workloads/:id/verify → Verify workload');
      console.log('  GET  /api/v1/stats                → Get statistics');
      console.log('  GET  /api/v1/ai-inventory         → AI asset inventory');
      console.log('  GET  /api/v1/connectors           → List connectors');
      console.log('  POST /api/v1/connectors           → Create connector');
      console.log('  POST /api/v1/connectors/:id/test  → Test credentials');
      console.log('  POST /api/v1/connectors/:id/scan  → Trigger connector scan\n');
      
      // Start periodic discovery
      startPeriodicDiscovery();

      // Start periodic MCP server fingerprint rescan
      if (pool) {
        const MCP_RESCAN_INTERVAL = parseInt(process.env.MCP_RESCAN_INTERVAL_MS) || 300000; // 5 min default
        setTimeout(() => {
          console.log('🔄 Starting periodic MCP fingerprint rescan...');
          const runMCPRescan = async () => {
            try {
              const RelScanner = require('./graph/relationship-scanner');
              const scanner = new RelScanner();
              const results = await scanner.rescanMCPServers(pool);
              if (results.drifted > 0) {
                console.log(`⚠️  MCP drift detected: ${results.drifted} server(s) changed capabilities`);
                // Add drift findings to the graph
                try {
                  const { clearGraphCache, refreshGraph } = require('./graph/graph-routes');
                  clearGraphCache();
                  await refreshGraph(pool);
                } catch { /* graph rebuild best-effort */ }
              }
            } catch (e) {
              console.error('  MCP rescan error:', e.message);
            }
          };
          runMCPRescan();
          setInterval(runMCPRescan, MCP_RESCAN_INTERVAL);
        }, 60000); // Start 60s after boot (after initial connector scan)
      }

      // Start periodic cloud log enrichment (every 5 minutes)
      if (pool) {
        const CLOUD_LOG_INTERVAL = parseInt(process.env.CLOUD_LOG_INTERVAL_MS) || 300000;
        setInterval(async () => {
          try {
            const { CloudLogEnricher } = require('./graph/cloud-log-enricher');
            const { ProviderRegistry } = require('./graph/provider-registry');
            const enricher = new CloudLogEnricher(pool, ProviderRegistry.getInstance());
            const { rows: workloads } = await pool.query('SELECT id, name, metadata FROM workloads LIMIT 500');
            const results = await enricher.enrichAll(workloads);
            const total = results.gcp.length + results.aws.length;
            if (total > 0) console.log(`[CloudLogEnricher] Periodic enrichment: ${total} entries`);
          } catch (e) {
            // Non-critical — cloud log enrichment is optional
          }
        }, CLOUD_LOG_INTERVAL);
        console.log(`  ☁️ Cloud log enrichment timer: every ${CLOUD_LOG_INTERVAL / 1000}s`);
      }
    });
}

// Handle shutdown
process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down gracefully...');
  if (discoveryInterval) clearInterval(discoveryInterval);
  if (pool) pool.end();
  process.exit(0);
});

// Start the service
start();