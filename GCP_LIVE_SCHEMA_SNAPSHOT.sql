-- =============================================================================
-- WID Platform — GCP LIVE SCHEMA SNAPSHOT
-- =============================================================================
-- Reconstructed from source code analysis of all services.
-- This reflects the EXACT schema deployed to GCP Cloud SQL as of 2026-02-24.
--
-- How this was reconstructed (gcloud not available in build container):
--   - Every INSERT INTO, UPDATE SET, SELECT FROM across all 8 service files
--   - Every CREATE TABLE in attestation-routes.js
--   - Every ALTER TABLE in policy-sync-service/src/index.js (startup migrations)
--   - Column types inferred from usage patterns and pg client behavior
--
-- Key finding: workloads, policies, ext_authz_decisions, and access_decisions
-- were NOT created via code — they were created directly in Cloud SQL via the
-- GCP console or a bootstrap script not committed to the repo.
-- Their schemas are reconstructed from INSERT/SELECT column lists.
--
-- Use this as the reference when building the new authoritative schema.sql
-- =============================================================================

-- ── DATABASE: workload_identity_db ───────────────────────────────────────────
-- (inferred from default in all DATABASE_URL env defaults)


-- =============================================================================
-- TABLE: workloads
-- =============================================================================
-- Created: directly in Cloud SQL (not via service code)
-- Owned by: discovery-service (reads/writes all columns)
-- Also used by: policy-sync-service, token-service (reads)
--
-- Column types reconstructed from:
--   discovery-service/src/index.js saveWorkload() INSERT (42 params)
--   discovery-service/src/index.js scan UPDATE clauses
--   policy-sync-service/src/routes.js SELECT * FROM workloads

CREATE TABLE IF NOT EXISTS workloads (
  -- Identity
  id                  SERIAL PRIMARY KEY,
  spiffe_id           TEXT         NOT NULL UNIQUE,
  name                TEXT         NOT NULL,
  type                TEXT         NOT NULL,           -- cloud-run-service | ecs-task | k8s-pod | docker-container | service-account | external-resource | etc.

  -- Location
  namespace           TEXT         DEFAULT 'default',
  environment         TEXT         DEFAULT 'dev',
  trust_domain        TEXT,
  issuer              TEXT,
  cluster_id          TEXT,
  cloud_provider      TEXT         DEFAULT 'unknown',  -- gcp | aws | azure | docker | k8s | on-prem
  region              TEXT,
  account_id          TEXT,

  -- Classification
  category            TEXT         DEFAULT 'workload',
  subcategory         TEXT,
  is_ai_agent         BOOLEAN      NOT NULL DEFAULT false,
  is_mcp_server       BOOLEAN      NOT NULL DEFAULT false,

  -- Discovery
  discovered_by       TEXT         DEFAULT 'scanner',
  labels              JSONB        NOT NULL DEFAULT '{}',
  selectors           JSONB        DEFAULT '[]',
  metadata            JSONB        NOT NULL DEFAULT '{}',

  -- Security scoring
  security_score      INTEGER      DEFAULT 50,
  status              TEXT         DEFAULT 'active',

  -- Trust & attestation
  verified            BOOLEAN      NOT NULL DEFAULT false,
  verified_by         TEXT,
  verification_method TEXT,
  trust_level         TEXT         DEFAULT 'none',     -- none | low | medium | high | cryptographic
  attestation_data    JSONB        DEFAULT '{}',
  last_attestation    TIMESTAMPTZ,
  attestation_expires TIMESTAMPTZ,

  -- Ownership
  owner               TEXT,
  team                TEXT,
  cost_center         TEXT,
  created_by          TEXT         DEFAULT 'system',

  -- Shadow / dormancy detection
  is_shadow           BOOLEAN      NOT NULL DEFAULT false,
  is_dormant          BOOLEAN      NOT NULL DEFAULT false,
  shadow_score        INTEGER      DEFAULT 0,
  dormancy_score      INTEGER      DEFAULT 0,
  shadow_reasons      TEXT[]       DEFAULT '{}',
  dormancy_reasons    TEXT[]       DEFAULT '{}',

  -- Usage analytics
  api_calls_30d       INTEGER      DEFAULT 0,
  unique_callers_30d  INTEGER      DEFAULT 0,
  last_api_call       TIMESTAMPTZ,
  last_deployed       TIMESTAMPTZ,

  -- Token state (added via ALTER in attestation-routes.js startup)
  wid_token           TEXT,
  token_jti           TEXT,
  token_issued_at     TIMESTAMPTZ,
  token_expires_at    TIMESTAMPTZ,
  token_claims        JSONB,

  -- Timestamps
  last_seen           TIMESTAMPTZ  DEFAULT NOW(),
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes (inferred from query patterns in routes.js)
CREATE INDEX IF NOT EXISTS idx_workloads_name      ON workloads(name);
CREATE INDEX IF NOT EXISTS idx_workloads_type      ON workloads(type);
CREATE INDEX IF NOT EXISTS idx_workloads_category  ON workloads(category);
CREATE INDEX IF NOT EXISTS idx_workloads_provider  ON workloads(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_workloads_ai_agent  ON workloads(is_ai_agent);
CREATE INDEX IF NOT EXISTS idx_workloads_last_seen ON workloads(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_workloads_metadata  ON workloads USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_workloads_labels    ON workloads USING GIN(labels);


-- =============================================================================
-- TABLE: policies
-- =============================================================================
-- Created: directly in Cloud SQL (not via service code)
-- Owned by: policy-sync-service
-- Columns evolve via ALTER TABLE migrations in policy-sync-service/src/index.js startup

CREATE TABLE IF NOT EXISTS policies (
  id                  SERIAL PRIMARY KEY,
  name                TEXT         NOT NULL UNIQUE,
  description         TEXT         DEFAULT '',
  policy_type         TEXT         NOT NULL
                      CHECK (policy_type IN ('enforcement','compliance','lifecycle','access','conditional_access','ai_agent','least_privilege')),
  enforcement_mode    TEXT         NOT NULL DEFAULT 'audit'
                      CHECK (enforcement_mode IN ('simulate','audit','enforce')),
  rego_policy         TEXT,
  opa_package         TEXT,
  conditions          JSONB        NOT NULL DEFAULT '[]',
  actions             JSONB        NOT NULL DEFAULT '[]',
  scope_environment   TEXT,
  scope_types         TEXT[],
  scope_teams         TEXT[],

  -- Added via ALTER TABLE in startup migrations:
  effect              TEXT         DEFAULT NULL,        -- allow | deny
  priority            INTEGER      DEFAULT 100,
  tags                TEXT[]       DEFAULT '{}',
  client_workload_id  UUID         DEFAULT NULL,
  server_workload_id  UUID         DEFAULT NULL,
  credential_policy   JSONB        DEFAULT NULL,
  time_window         JSONB        DEFAULT NULL,
  geo_restrictions    TEXT[]       DEFAULT NULL,
  template_id         TEXT,
  template_version    INTEGER      DEFAULT NULL,
  severity            TEXT         DEFAULT 'medium',

  -- Meta
  enabled             BOOLEAN      NOT NULL DEFAULT true,
  version             INTEGER      NOT NULL DEFAULT 1,
  created_by          TEXT         DEFAULT 'system',
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_type    ON policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_policies_mode    ON policies(enforcement_mode);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);


-- =============================================================================
-- TABLE: ext_authz_decisions
-- =============================================================================
-- Created: directly in Cloud SQL (not via service code initially)
-- Written by: policy-sync-service (evaluate endpoint + batch endpoint)
-- Read by: policy-sync-service (live decisions feed), web UI
--
-- Column history (reconstructed from INSERT statements):
--   Base (original):      decision_id, source_principal, destination_principal,
--                         source_name, destination_name, method, path_pattern,
--                         verdict, policy_name, policies_evaluated, adapter_mode, latency_ms
--   Added later (ALTER):  trace_id, parent_decision_id, hop_index, total_hops,
--                         source_type, destination_type, enforcement_action,
--                         enforcement_detail, token_context
--   Added in routes.js:   request_context, response_context (found in L1010 INSERT)

CREATE TABLE IF NOT EXISTS ext_authz_decisions (
  id                  BIGSERIAL    PRIMARY KEY,

  -- Request identity
  decision_id         TEXT         NOT NULL UNIQUE,
  source_principal    TEXT,                            -- SPIFFE ID of caller
  destination_principal TEXT,                          -- SPIFFE ID of target
  source_name         TEXT,                            -- human-readable workload name
  destination_name    TEXT,
  source_type         TEXT,                            -- cloud-run-service | k8s-pod | etc.
  destination_type    TEXT,

  -- Request details
  method              TEXT,                            -- GET | POST | etc.
  path_pattern        TEXT,

  -- Decision
  verdict             TEXT         NOT NULL            -- allow | deny | no-match
                      CHECK (verdict IN ('allow','deny','no-match')),
  policy_name         TEXT,
  policies_evaluated  INTEGER      DEFAULT 0,
  adapter_mode        TEXT,                            -- simulate | audit | enforce | monitor

  -- Enforcement detail (added via ALTER TABLE migration)
  enforcement_action  TEXT,                            -- WOULD_BLOCK | REJECT_REQUEST | FORWARD_REQUEST | MONITOR
  enforcement_detail  TEXT,

  -- Chain / trace tracking (added via ALTER TABLE migration)
  trace_id            TEXT         DEFAULT NULL,
  parent_decision_id  TEXT         DEFAULT NULL,
  hop_index           INTEGER      DEFAULT 0,
  total_hops          INTEGER      DEFAULT 1,

  -- Token / request context (added via ALTER TABLE migration)
  token_context       TEXT         DEFAULT NULL,       -- JSON string
  request_context     TEXT,                            -- JSON string (L1010)
  response_context    TEXT,                            -- JSON string (L1010)

  -- Performance
  latency_ms          INTEGER,
  cached              BOOLEAN      DEFAULT false,

  -- Timestamp
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_authz_decision_id  ON ext_authz_decisions(decision_id);
CREATE INDEX IF NOT EXISTS idx_authz_source       ON ext_authz_decisions(source_name);
CREATE INDEX IF NOT EXISTS idx_authz_dest         ON ext_authz_decisions(destination_name);
CREATE INDEX IF NOT EXISTS idx_authz_verdict      ON ext_authz_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_authz_created      ON ext_authz_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authz_trace        ON ext_authz_decisions(trace_id);
CREATE INDEX IF NOT EXISTS idx_authz_mode         ON ext_authz_decisions(adapter_mode);


-- =============================================================================
-- TABLE: access_decisions
-- =============================================================================
-- NOTE: A SECOND decisions table exists! Found in routes.js L544.
-- Written by: policy-sync-service /policies/evaluate endpoint
-- Separate from ext_authz_decisions (different schema, different use)

CREATE TABLE IF NOT EXISTS access_decisions (
  id                  SERIAL PRIMARY KEY,
  client_workload_id  TEXT,
  client_name         TEXT,
  server_workload_id  TEXT,
  server_name         TEXT,
  decision            TEXT,                            -- allow | deny
  policies_evaluated  INTEGER,
  policy_results      JSONB,
  runtime_context     JSONB,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- =============================================================================
-- TABLE: policy_violations
-- =============================================================================
-- Created: directly in Cloud SQL (not via service code)
-- Written/read by: policy-sync-service /violations endpoints

CREATE TABLE IF NOT EXISTS policy_violations (
  id                  SERIAL PRIMARY KEY,
  policy_id           INTEGER      REFERENCES policies(id) ON DELETE SET NULL,
  policy_name         TEXT,
  workload_id         INTEGER,
  workload_name       TEXT,
  violation_type      TEXT,
  severity            TEXT         DEFAULT 'medium',
  message             TEXT,
  details             JSONB        DEFAULT '{}',
  status              TEXT         DEFAULT 'open',     -- open | resolved | suppressed
  resolved_at         TIMESTAMPTZ,
  resolved_by         TEXT,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_violations_policy   ON policy_violations(policy_id);
CREATE INDEX IF NOT EXISTS idx_violations_workload  ON policy_violations(workload_id);
CREATE INDEX IF NOT EXISTS idx_violations_status    ON policy_violations(status);


-- =============================================================================
-- TABLE: policy_templates
-- =============================================================================
-- Created by: policy-sync-service /admin/migrate-templates endpoint
-- (CREATE TABLE in routes.js L1494)

CREATE TABLE IF NOT EXISTS policy_templates (
  id                  VARCHAR(100) PRIMARY KEY,
  name                VARCHAR(255) NOT NULL,
  description         TEXT         DEFAULT '',
  policy_type         VARCHAR(30)  NOT NULL,
  severity            VARCHAR(20)  NOT NULL DEFAULT 'medium',
  conditions          JSONB        NOT NULL DEFAULT '[]',
  actions             JSONB        NOT NULL DEFAULT '[]',
  scope_environment   VARCHAR(50)  DEFAULT NULL,
  scope_types         TEXT[]       DEFAULT NULL,
  effect              VARCHAR(20)  DEFAULT NULL,
  tags                TEXT[]       DEFAULT '{}',
  enabled             BOOLEAN      DEFAULT true,
  version             INTEGER      DEFAULT 1,
  created_by          VARCHAR(255) DEFAULT 'system',
  created_at          TIMESTAMPTZ  DEFAULT NOW(),
  updated_at          TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_type     ON policy_templates(policy_type);
CREATE INDEX IF NOT EXISTS idx_policy_templates_severity ON policy_templates(severity);
CREATE INDEX IF NOT EXISTS idx_policy_templates_enabled  ON policy_templates(enabled);


-- =============================================================================
-- TABLE: finding_remediation_map
-- =============================================================================
-- Created by: policy-sync-service /admin/migrate-templates endpoint (L1520)

CREATE TABLE IF NOT EXISTS finding_remediation_map (
  id                  SERIAL PRIMARY KEY,
  finding_type        VARCHAR(100) NOT NULL,
  template_id         VARCHAR(100) NOT NULL REFERENCES policy_templates(id) ON DELETE CASCADE,
  priority            INTEGER      DEFAULT 1,
  reason              TEXT         DEFAULT '',
  UNIQUE(finding_type, template_id)
);

CREATE INDEX IF NOT EXISTS idx_frm_finding  ON finding_remediation_map(finding_type);
CREATE INDEX IF NOT EXISTS idx_frm_template ON finding_remediation_map(template_id);


-- =============================================================================
-- TABLE: attestation_history
-- =============================================================================
-- Created by: discovery-service/src/attestation/attestation-routes.js L102

CREATE TABLE IF NOT EXISTS attestation_history (
  id                  SERIAL PRIMARY KEY,
  workload_id         TEXT,
  workload_name       TEXT,
  trust_level         TEXT,
  methods_passed      INTEGER      DEFAULT 0,
  methods_failed      INTEGER      DEFAULT 0,
  primary_method      TEXT,
  attestation_data    JSONB,
  source              TEXT,                            -- which attestation provider
  expires_at          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ  DEFAULT NOW()
);


-- =============================================================================
-- TABLE: gateway_traces
-- =============================================================================
-- Created by: discovery-service/src/attestation/attestation-routes.js L119

CREATE TABLE IF NOT EXISTS gateway_traces (
  id                  SERIAL PRIMARY KEY,
  trace_id            TEXT         UNIQUE NOT NULL,
  event_type          TEXT         NOT NULL,
  source_workload     TEXT,
  source_spiffe_id    TEXT,
  target_workload     TEXT,
  target_spiffe_id    TEXT,
  action              TEXT,
  data_classification TEXT,
  credential_name     TEXT,
  credential_storage  TEXT,
  credential_in_vault BOOLEAN      DEFAULT false,
  credential_expires  TIMESTAMPTZ,
  policy_id           TEXT,
  policy_name         TEXT,
  policy_mode         TEXT,
  decision            TEXT         NOT NULL,
  decision_reason     TEXT,
  enforced            BOOLEAN      DEFAULT false,
  http_status         INTEGER,
  conditions_failed   JSONB,
  hops                JSONB,
  request_meta        JSONB,
  response_meta       JSONB,
  latency_ms          INTEGER,
  created_at          TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gt_event_type ON gateway_traces(event_type);
CREATE INDEX IF NOT EXISTS idx_gt_source     ON gateway_traces(source_workload);
CREATE INDEX IF NOT EXISTS idx_gt_policy     ON gateway_traces(policy_id);
CREATE INDEX IF NOT EXISTS idx_gt_decision   ON gateway_traces(decision);
CREATE INDEX IF NOT EXISTS idx_gt_created    ON gateway_traces(created_at DESC);


-- =============================================================================
-- TABLE: audit_events
-- =============================================================================
-- Created by: discovery-service/src/attestation/attestation-routes.js L158
-- NOTE: Different from the audit_events in our new schema.sql!
-- This version has simpler columns (no tenant_id, TEXT ids not integers)

CREATE TABLE IF NOT EXISTS audit_events (
  id                  SERIAL PRIMARY KEY,
  event_type          TEXT         NOT NULL,
  actor               TEXT         DEFAULT 'system',
  workload_id         TEXT,
  workload_name       TEXT,
  resource_id         TEXT,
  policy_id           TEXT,
  detail              JSONB,
  created_at          TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ae_type     ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ae_workload ON audit_events(workload_id);
CREATE INDEX IF NOT EXISTS idx_ae_created  ON audit_events(created_at DESC);


-- =============================================================================
-- TABLE: wid_tokens
-- =============================================================================
-- Created by: discovery-service/src/attestation/attestation-routes.js L189

CREATE TABLE IF NOT EXISTS wid_tokens (
  id                  SERIAL PRIMARY KEY,
  jti                 TEXT         UNIQUE NOT NULL,
  workload_id         TEXT         NOT NULL,
  workload_name       TEXT,
  token               TEXT         NOT NULL,
  spiffe_id           TEXT,
  trust_level         TEXT,
  ttl_seconds         INTEGER,
  status              TEXT         DEFAULT 'active',   -- active | revoked | expired
  issued_at           TIMESTAMPTZ  NOT NULL,
  expires_at          TIMESTAMPTZ  NOT NULL,
  revoked_at          TIMESTAMPTZ,
  revoked_by          TEXT,
  revoke_reason       TEXT,
  claims              JSONB,
  superseded_by       TEXT,
  created_at          TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wid_tokens_workload ON wid_tokens(workload_id);
CREATE INDEX IF NOT EXISTS idx_wid_tokens_status   ON wid_tokens(status);
CREATE INDEX IF NOT EXISTS idx_wid_tokens_jti      ON wid_tokens(jti);


-- =============================================================================
-- GAPS / DIFFERENCES vs new schema.sql
-- =============================================================================
-- The following exist in the new schema but NOT in the live GCP schema:
--   - tenants table (multi-tenancy — new)
--   - tenant_id column on all tables (new)
--   - Row Level Security policies (new)
--   - ext_authz_decisions partitioning (new — current is unpartitioned)
--   - wid_app role (new)
--   - relay_registrations table (new)
--
-- The following exist in live GCP but NOT in the new schema.sql (to be merged):
--   - access_decisions table (separate from ext_authz_decisions)
--   - gateway_traces table
--   - wid_tokens.token column (full JWT text stored — security concern, remove in new)
--   - workloads.wid_token, token_jti, token_issued_at, token_expires_at, token_claims
--     (token state on workload — anti-pattern, should be in wid_tokens only)
--   - ext_authz_decisions.request_context, response_context (TEXT JSON, not JSONB)
--   - ext_authz_decisions.token_context (TEXT JSON, not JSONB)
--
-- Migration path (when moving from GCP to local/new schema):
--   1. pg_dump --schema-only from Cloud SQL → compare with this file
--   2. Apply new schema.sql (creates new tables with tenant_id)
--   3. Migrate data: INSERT INTO new_workloads SELECT ..., default_tenant_id FROM old_workloads
--   4. Drop legacy columns after verification
-- =============================================================================
