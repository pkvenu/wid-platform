// =============================================================================
// Policy Service — NHI Governance Engine
// =============================================================================
// Owns: policy CRUD, evaluation, violation tracking, pluggable compilation
// Port: 3001
// =============================================================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Client } = require('pg');
const { mountPolicyRoutes, mountAdminRoutes } = require('./routes');
const { mountAuthRoutes } = require('./auth/auth-routes');
const { requireAuth } = require('./auth/auth-middleware');

const app = express();
const PORT = process.env.PORT || 3001;
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@postgres:5432/workload_identity';
const COMPILER = process.env.POLICY_COMPILER || 'rego';

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

let dbClient;

async function connectDB() {
  dbClient = new Client({ connectionString: DATABASE_URL });
  await dbClient.connect();
  console.log('  ✅ Connected to database');
}

app.get('/health', async (req, res) => {
  try {
    await dbClient.query('SELECT 1');
    res.json({ service: 'policy-service', status: 'healthy', compiler: COMPILER, port: PORT });
  } catch (e) {
    res.status(503).json({ service: 'policy-service', status: 'unhealthy', error: e.message });
  }
});

async function start() {
  await connectDB();

  // Auto-migrate: create users table if not exists
  try {
    await dbClient.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ
      )
    `);
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    console.log('  [startup] users table ready');
  } catch (e) { console.log(`  [startup] users table: ${e.message}`); }

  // Mount auth routes FIRST (before middleware)
  mountAuthRoutes(app, dbClient);

  // Apply auth middleware to all subsequent routes
  app.use(requireAuth);

  mountPolicyRoutes(app, dbClient, { compiler: COMPILER });
  mountAdminRoutes(app, dbClient);

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
      try { await dbClient.query(sql); migrated++; } catch { /* column may exist or constraint active */ }
    }
    console.log(`  [startup] Schema migration: ${migrated}/${alters.length} statements applied`);
  } catch (e) { console.log(`  [startup] Schema migration skipped: ${e.message}`); }

  // Auto-create: ai_request_events table (Phase 2 — AI telemetry persistence)
  try {
    await dbClient.query(`
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
        created_at             TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_ai_req_provider ON ai_request_events(ai_provider)');
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_ai_req_source   ON ai_request_events(source_name)');
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_ai_req_created  ON ai_request_events(created_at DESC)');
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
      try { await dbClient.query(sql); aiMigrated++; } catch { /* column may exist */ }
    }
    console.log(`  [startup] ai_request_events response columns: ${aiMigrated}/${aiAlters.length} applied`);
  } catch (e) { console.log(`  [startup] ai_request_events migration: ${e.message}`); }

  // Auto-sync: ensure all in-code templates exist in DB (idempotent upsert)
  try {
    const { POLICY_TEMPLATES } = require('./engine/templates');
    // Ensure tags column exists (migration safety)
    await dbClient.query('ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT \'{}\'').catch(() => {});
    let synced = 0;
    for (const [id, tpl] of Object.entries(POLICY_TEMPLATES)) {
      try {
        await dbClient.query(`
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
  Database:  ${DATABASE_URL.replace(/:[^:@]+@/, ':***@')}

  Endpoints:
    POST   /api/v1/auth/register         Register first user
    POST   /api/v1/auth/login            Login
    POST   /api/v1/auth/logout           Logout
    GET    /api/v1/auth/me               Current user
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

✅ Policy Service ready!
`);
  });
}

start().catch(err => { console.error('❌ Failed to start:', err); process.exit(1); });
process.on('SIGTERM', () => { dbClient?.end(); process.exit(0); });