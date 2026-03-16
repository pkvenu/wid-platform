// =============================================================================
// Policy Service — NHI Governance Engine
// =============================================================================
// Owns: policy CRUD, evaluation, violation tracking, pluggable compilation
// Port: 3001
// =============================================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { tenantDb: { createTenantPool, systemQuery }, tenantMiddleware: { enforceDataResidency }, securityHeaders, rateLimitMiddleware } = require('./shared-loader');
const { mountPolicyRoutes, mountAdminRoutes } = require('./routes');
const { mountAuthRoutes } = require('./auth/auth-routes');
const { requireAuth, attachTenantDb } = require('./auth/auth-middleware');
const { mountFederationRoutes } = require('./federation/federation-routes');
const { authRateLimiter, apiRateLimiter } = rateLimitMiddleware;

const app = express();
const PORT = process.env.PORT || 3001;
const COMPILER = process.env.POLICY_COMPILER || 'rego';

// Security headers (P2.6) — set before CORS so every response gets them
app.use(securityHeaders());

// CORS — allow credentials for cookie-based auth
const ALLOWED_ORIGINS = new Set([
  'https://wid-dev-web-ui-265663183174.us-central1.run.app',
  'http://34.120.74.81',
  'https://34.120.74.81',
  'http://34.111.176.251',
  'https://34.111.176.251',
  'http://localhost:3100',
  'http://localhost:5173',
  'http://localhost:3000',
  ...(process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
]);

app.use(cors({
  origin: function (origin, callback) {
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
app.use(express.json());

let pool;

async function connectDB() {
  pool = createTenantPool({ max: 20 });
  // Verify connection
  const client = await pool.connect();
  await client.query('SELECT 1');
  client.release();
  console.log('  ✅ Connected to database (pool)');
}

app.get('/health', async (req, res) => {
  try {
    await systemQuery(pool, 'SELECT 1');
    res.json({ service: 'policy-service', status: 'healthy', compiler: COMPILER, port: PORT });
  } catch (e) {
    res.status(503).json({ service: 'policy-service', status: 'unhealthy', error: e.message });
  }
});

async function start() {
  await connectDB();

  // Store pool on app for middleware access
  app.locals.pool = pool;

  // Auto-migrate: tenants table + tenant_id columns
  try {
    // 1. Create tenants table
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS tenants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        plan TEXT NOT NULL DEFAULT 'trial',
        max_users INTEGER NOT NULL DEFAULT 10,
        max_workloads INTEGER NOT NULL DEFAULT 1000,
        max_connectors INTEGER NOT NULL DEFAULT 20,
        max_policies INTEGER NOT NULL DEFAULT 500,
        data_region TEXT NOT NULL DEFAULT 'us',
        data_residency_strict BOOLEAN NOT NULL DEFAULT false,
        allowed_regions TEXT[] NOT NULL DEFAULT '{us}',
        settings JSONB NOT NULL DEFAULT '{}',
        features JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    // Default tenant
    await systemQuery(pool,
      `INSERT INTO tenants (id, name, slug, plan, data_region)
       VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'enterprise', 'us')
       ON CONFLICT (id) DO NOTHING`
    );
    console.log('  [startup] tenants table ready');

    // 2. Tenant invitations
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS tenant_invitations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        invited_by UUID,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        accepted_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // 3. Tenant usage
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS tenant_usage (
        tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
        user_count INTEGER NOT NULL DEFAULT 0,
        workload_count INTEGER NOT NULL DEFAULT 0,
        connector_count INTEGER NOT NULL DEFAULT 0,
        policy_count INTEGER NOT NULL DEFAULT 0,
        last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await systemQuery(pool,
      `INSERT INTO tenant_usage (tenant_id) VALUES ('00000000-0000-0000-0000-000000000001') ON CONFLICT DO NOTHING`
    );

    // 4. Add tenant_id to tables that need it
    const tenantMigrations = [
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "UPDATE policies SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE policy_violations ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE access_decisions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE access_policies ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE workloads ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE targets ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
      "ALTER TABLE token_chain ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'",
    ];
    let tmMigrated = 0;
    for (const sql of tenantMigrations) {
      try { await systemQuery(pool, sql); tmMigrated++; } catch { /* already exists */ }
    }
    console.log(`  [startup] Tenant migrations: ${tmMigrated}/${tenantMigrations.length} applied`);

    // Also try optional tables
    const optionalTables = [
      'remediation_intents', 'identity_graph', 'policy_snapshots',
      'mcp_tool_events', 'mcp_fingerprints', 'cloud_log_enrichments',
      'credential_usage', 'attestation_history', 'credential_rotations',
      'remediation_executions', 'authorization_events', 'policy_evaluations',
      'identity_graph_history',
    ];
    for (const t of optionalTables) {
      try {
        await systemQuery(pool, `ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001'`);
      } catch { /* table may not exist */ }
    }

    // Data sovereignty: add data_region to audit tables
    const auditTables = ['ext_authz_decisions', 'ai_request_events', 'mcp_tool_events', 'policy_snapshots'];
    for (const t of auditTables) {
      try {
        await systemQuery(pool, `ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'us'`);
        await systemQuery(pool, `CREATE INDEX IF NOT EXISTS idx_${t.substring(0,10)}_tenant_region ON ${t}(tenant_id, data_region)`);
      } catch { /* table may not exist or column exists */ }
    }

    // Audit events by region view
    try {
      await systemQuery(pool, `
        CREATE OR REPLACE VIEW audit_events_by_region AS
          SELECT 'ext_authz' AS event_type, id, tenant_id, data_region, decision_id, created_at FROM ext_authz_decisions
          UNION ALL
          SELECT 'ai_request', id, tenant_id, data_region, decision_id, created_at FROM ai_request_events
          UNION ALL
          SELECT 'mcp_tool', id, tenant_id, data_region, decision_id, created_at FROM mcp_tool_events
          UNION ALL
          SELECT 'policy_snapshot', id, tenant_id, data_region, NULL, created_at FROM policy_snapshots
      `);
    } catch { /* view creation may fail if tables don't exist yet */ }

    console.log('  [startup] Data sovereignty columns + view ready');

    // 5. Federation tables (ADR-13: mTLS Federation)
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS spoke_relays (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
        relay_id VARCHAR(100) UNIQUE NOT NULL,
        environment_name VARCHAR(255) NOT NULL,
        environment_type VARCHAR(50) NOT NULL,
        region VARCHAR(50) NOT NULL,
        cluster_id VARCHAR(255),
        spiffe_id TEXT UNIQUE,
        cert_fingerprint VARCHAR(128),
        cert_issuer TEXT,
        cert_not_before TIMESTAMPTZ,
        cert_not_after TIMESTAMPTZ,
        cert_serial VARCHAR(128),
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_heartbeat_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        revoked_reason TEXT,
        webhook_url TEXT,
        webhook_enabled BOOLEAN DEFAULT TRUE,
        relay_version VARCHAR(50),
        capabilities TEXT[] DEFAULT '{}',
        data_region TEXT NOT NULL DEFAULT 'us',
        data_residency_strict BOOLEAN DEFAULT FALSE,
        allowed_regions TEXT[] DEFAULT '{us}',
        policy_version INTEGER DEFAULT 0,
        policy_count INTEGER DEFAULT 0,
        audit_buffer_size INTEGER DEFAULT 0,
        adapter_count INTEGER DEFAULT 0,
        uptime_seconds INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_spoke_relays_status ON spoke_relays(status) WHERE status = \'active\'');
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_spoke_relays_spiffe ON spoke_relays(spiffe_id) WHERE spiffe_id IS NOT NULL');

    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS federation_events (
        id SERIAL PRIMARY KEY,
        tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
        relay_id VARCHAR(100) NOT NULL,
        event_type VARCHAR(50) NOT NULL,
        spiffe_id TEXT,
        cert_fingerprint VARCHAR(128),
        details JSONB DEFAULT '{}',
        source_ip INET,
        data_region TEXT NOT NULL DEFAULT 'us',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_fed_events_relay ON federation_events(relay_id, created_at DESC)');
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_fed_events_type ON federation_events(event_type, created_at DESC)');

    // Add relay identity columns to ext_authz_decisions
    await systemQuery(pool, 'ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS relay_spiffe_id TEXT').catch(() => {});
    await systemQuery(pool, 'ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS origin_relay_spiffe_id TEXT').catch(() => {});
    await systemQuery(pool, 'ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS origin_environment VARCHAR(255)').catch(() => {});

    console.log('  [startup] Federation tables ready (ADR-13: mTLS)');
  } catch (e) { console.log(`  [startup] Tenant migration: ${e.message}`); }

  // Auto-migrate: create users table if not exists (with tenant_id)
  try {
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
      )
    `);
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    console.log('  [startup] users table ready');
  } catch (e) { console.log(`  [startup] users table: ${e.message}`); }

  // Rate limiting (P2.6) — auth routes get strict 10/min per IP
  app.use('/api/v1/auth', authRateLimiter());

  // Mount auth routes FIRST (before middleware)
  mountAuthRoutes(app, pool);

  // Mount federation routes BEFORE auth middleware (federation uses mTLS/API key auth, not JWT)
  mountFederationRoutes(app, pool, { tlsManager: null /* loaded from env at runtime */ });

  // Apply auth middleware + tenant DB scoping + data sovereignty to all subsequent routes
  app.use(requireAuth);
  app.use(attachTenantDb(pool));
  app.use(enforceDataResidency(pool));

  // General API rate limiting (P2.6) — 300/min per tenant, applied after auth
  app.use(apiRateLimiter());

  mountPolicyRoutes(app, pool, { compiler: COMPILER });
  mountAdminRoutes(app, pool);

  // Auto-migrate: ensure all required columns exist on policies table
  try {
    const alters = [
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS effect VARCHAR(20) DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 100",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}'",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS client_workload_id UUID DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS server_workload_id UUID DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS credential_policy JSONB DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS time_window JSONB DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS geo_restrictions TEXT[] DEFAULT NULL",
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS template_version INTEGER DEFAULT NULL",
      "ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_policy_type_check",
      "ALTER TABLE policies ADD CONSTRAINT policies_policy_type_check CHECK (policy_type IN ('enforcement','compliance','lifecycle','access','conditional_access','ai_agent','least_privilege'))",
      // Trace support for ext_authz_decisions
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS trace_id VARCHAR(100) DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS parent_decision_id VARCHAR(100) DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS hop_index INTEGER DEFAULT 0",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS total_hops INTEGER DEFAULT 1",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS source_type VARCHAR(50) DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS destination_type VARCHAR(50) DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS enforcement_action VARCHAR(50) DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS enforcement_detail TEXT DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS token_context TEXT DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS request_context JSONB DEFAULT NULL",
      "ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS response_context JSONB DEFAULT NULL",
      "CREATE INDEX IF NOT EXISTS idx_authz_trace ON ext_authz_decisions(trace_id)",
      // Workload-scoped policy support
      "ALTER TABLE policies ADD COLUMN IF NOT EXISTS attack_path_id VARCHAR(255) DEFAULT NULL",
      "ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_name_key",
      "CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(enabled, enforcement_mode, client_workload_id) WHERE enabled = true",
      "CREATE INDEX IF NOT EXISTS idx_policies_attack_path ON policies(attack_path_id) WHERE attack_path_id IS NOT NULL",
    ];
    let migrated = 0;
    for (const sql of alters) {
      try { await systemQuery(pool, sql); migrated++; } catch { /* column may exist or constraint active */ }
    }
    console.log(`  [startup] Schema migration: ${migrated}/${alters.length} statements applied`);
  } catch (e) { console.log(`  [startup] Schema migration skipped: ${e.message}`); }

  // Auto-migrate: audit log encryption at rest (pgcrypto + encrypted detail columns)
  try {
    await systemQuery(pool, 'CREATE EXTENSION IF NOT EXISTS pgcrypto').catch(() => {});
    await systemQuery(pool, 'ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS details_encrypted BYTEA').catch(() => {});
    await systemQuery(pool, 'ALTER TABLE policy_violations ADD COLUMN IF NOT EXISTS details_encrypted BYTEA').catch(() => {});
    console.log('  [startup] Audit encryption columns ready (pgcrypto)');
  } catch (e) { console.log(`  [startup] Audit encryption migration: ${e.message}`); }

  // Auto-create: ai_request_events table (Phase 2 — AI telemetry persistence)
  try {
    await systemQuery(pool, `
      CREATE TABLE IF NOT EXISTS ai_request_events (
        id                     SERIAL PRIMARY KEY,
        decision_id            VARCHAR(64),
        source_name            VARCHAR(255),
        source_principal       TEXT,
        destination_host       VARCHAR(255),
        method                 VARCHAR(10),
        path_pattern           TEXT,
        ai_provider            VARCHAR(50) NOT NULL,
        ai_provider_label      VARCHAR(100),
        ai_model               VARCHAR(255),
        ai_operation           VARCHAR(50),
        tool_count             INTEGER DEFAULT 0,
        tool_names             TEXT[] DEFAULT '{}',
        message_count          INTEGER DEFAULT 0,
        has_system_prompt      BOOLEAN DEFAULT FALSE,
        estimated_input_tokens INTEGER DEFAULT 0,
        stream                 BOOLEAN DEFAULT FALSE,
        temperature            NUMERIC(4,2),
        max_tokens             INTEGER,
        body_bytes             INTEGER DEFAULT 0,
        truncated              BOOLEAN DEFAULT FALSE,
        relay_id               VARCHAR(100),
        relay_env              VARCHAR(100),
        gateway_id             VARCHAR(100),
        tenant_id              UUID,
        created_at             TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_ai_req_provider ON ai_request_events(ai_provider)');
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_ai_req_source   ON ai_request_events(source_name)');
    await systemQuery(pool, 'CREATE INDEX IF NOT EXISTS idx_ai_req_created  ON ai_request_events(created_at DESC)');
    console.log('  [startup] ai_request_events table ready');
  } catch (e) { console.log(`  [startup] ai_request_events: ${e.message}`); }

  // Auto-migrate: add response metadata columns to ai_request_events
  try {
    const aiAlters = [
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS response_status INTEGER",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS actual_input_tokens INTEGER",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS actual_output_tokens INTEGER",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS total_tokens INTEGER",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS estimated_cost_usd NUMERIC(10,6)",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS finish_reason VARCHAR(50)",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS provider_latency_ms INTEGER",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS provider_request_id VARCHAR(255)",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS error_code VARCHAR(50)",
      "ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS rate_limit_remaining INTEGER",
    ];
    let aiMigrated = 0;
    for (const sql of aiAlters) {
      try { await systemQuery(pool, sql); aiMigrated++; } catch { /* column may exist */ }
    }
    console.log(`  [startup] ai_request_events response columns: ${aiMigrated}/${aiAlters.length} applied`);
  } catch (e) { console.log(`  [startup] ai_request_events migration: ${e.message}`); }

  // Auto-sync: ensure all in-code templates exist in DB (idempotent upsert)
  try {
    const { POLICY_TEMPLATES } = require('./engine/templates');
    // Ensure tags column exists (migration safety)
    await systemQuery(pool, 'ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT \'{}\'').catch(() => {});
    let synced = 0;
    for (const [id, tpl] of Object.entries(POLICY_TEMPLATES)) {
      try {
        await systemQuery(pool, `
          INSERT INTO policy_templates (id, name, description, policy_type, severity, conditions, actions, scope_environment, effect, tags)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          ON CONFLICT (id) DO UPDATE SET
            name=EXCLUDED.name, description=EXCLUDED.description, policy_type=EXCLUDED.policy_type,
            severity=EXCLUDED.severity, conditions=EXCLUDED.conditions, actions=EXCLUDED.actions,
            scope_environment=EXCLUDED.scope_environment, effect=EXCLUDED.effect, tags=EXCLUDED.tags
        `, [id, tpl.name, tpl.description, tpl.policy_type, tpl.severity,
            JSON.stringify(tpl.conditions), JSON.stringify(tpl.actions),
            tpl.scope_environment || null, tpl.effect || null, tpl.tags || []]);
        synced++;
      } catch { /* skip */ }
    }
    console.log(`  [startup] Synced ${synced}/${Object.keys(POLICY_TEMPLATES).length} templates to DB`);
  } catch (e) {
    console.log(`  [startup] Template sync skipped: ${e.message}`);
    console.log(`  [startup] Run POST /admin/migrate-templates to initialize`);
  }

  app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║  Policy Service — NHI Governance Engine          ║
║  Port: ${PORT}                                        ║
╚══════════════════════════════════════════════════╝

  Compiler:  ${COMPILER}
  Pool:      max 20 connections

  Endpoints:
    POST   /api/v1/auth/register         Register (creates tenant + admin)
    POST   /api/v1/auth/login            Login
    POST   /api/v1/auth/logout           Logout
    GET    /api/v1/auth/me               Current user + tenant
    POST   /api/v1/auth/accept-invite    Accept tenant invitation
    GET    /api/v1/tenant                Tenant details + usage
    PUT    /api/v1/tenant                Update tenant settings
    GET    /api/v1/tenant/users          List tenant users
    POST   /api/v1/tenant/invite         Invite user to tenant
    GET    /api/v1/policies              List policies
    POST   /api/v1/policies              Create policy
    PUT    /api/v1/policies/:id          Update policy
    DELETE /api/v1/policies/:id          Delete policy
    PATCH  /api/v1/policies/:id/toggle   Enable/disable
    POST   /api/v1/policies/:id/evaluate Evaluate against workloads
    POST   /api/v1/policies/test         Dry-run test
    POST   /api/v1/policies/evaluate-all Evaluate all policies
    GET    /api/v1/violations            List violations
    PATCH  /api/v1/violations/:id        Resolve violation
    GET    /api/v1/policies/templates    Template gallery
    POST   /api/v1/policies/from-template/:id  Deploy template
    POST   /api/v1/policies/compile      Compile to target format
    GET    /api/v1/policies/compilers    Available compilers
    GET    /health                       Service health

  Federation (ADR-13 mTLS):
    POST   /api/v1/federation/register        Relay registration (mTLS)
    POST   /api/v1/federation/heartbeat       Relay heartbeat
    POST   /api/v1/federation/revoke/:id      Revoke relay
    GET    /api/v1/federation/relays          List relays + cert status
    GET    /api/v1/federation/events          Federation audit log
    POST   /api/v1/federation/push            Policy push broadcast
    POST   /api/v1/federation/bootstrap-cert  Bootstrap client cert

✅ Policy Service ready (multi-tenant + federation)!
`);
  });
}

start().catch(err => { console.error('❌ Failed to start:', err); process.exit(1); });
process.on('SIGTERM', () => { pool?.end(); process.exit(0); });
