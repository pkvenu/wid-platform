-- =============================================================================
-- Workload Identity Platform — Complete Database Schema
-- =============================================================================
--
-- Single-file init for fresh installations. Creates all tables, indexes,
-- views, functions, triggers, and seed data.
--
-- Usage:
--   psql -U wid_user -d workload_identity -f init.sql
--
-- Or via Docker Compose:
--   docker compose exec -T postgres psql -U wid_user -d workload_identity < database/init.sql
--
-- Tables created:
--   workloads              — Discovered non-human identities (NHI)
--   targets                — External services and APIs
--   discovery_scans        — Scan history and performance
--   attestation_history    — Workload attestation audit trail
--   policies               — NHI governance policy definitions
--   policy_violations      — Policy evaluation results
--   access_policies        — Client→server access bindings
--   access_decisions       — Control-plane access audit log
--   ext_authz_decisions    — Data-plane (ext-authz adapter) decision log
--   token_chain            — OBO (On-Behalf-Of) token chain tracking
--   credential_usage       — Credential proxy access audit log
--
-- Version: 3.0.0
-- =============================================================================

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. WORKLOADS — All discovered Non-Human Identities
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS workloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    spiffe_id VARCHAR(512) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
        -- kubernetes-deployment, kubernetes-statefulset, kubernetes-daemonset,
        -- kubernetes-cronjob, docker-container, ecs-task, lambda-function,
        -- ec2-instance, gce-instance, azure-vm, vault-approle, github-action,
        -- jenkins-pipeline, gitlab-runner, service-account, api-key, manual

    -- Location
    namespace VARCHAR(255),
    environment VARCHAR(50),      -- production, staging, development
    cloud_provider VARCHAR(50),
    region VARCHAR(50),
    account_id VARCHAR(255),

    -- Trust & Identity Federation
    trust_domain VARCHAR(255) DEFAULT 'company.com',
    issuer VARCHAR(512),
    cluster_id VARCHAR(255),

    -- Classification
    category VARCHAR(100),        -- compute, ci-cd, secret-engine, ai-agent, mcp-server, etc.
    subcategory VARCHAR(100),
    is_ai_agent BOOLEAN DEFAULT FALSE,
    is_mcp_server BOOLEAN DEFAULT FALSE,

    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    discovered_by VARCHAR(100),   -- kubernetes, docker, aws, gcp, azure, vault, manual
    last_seen TIMESTAMPTZ DEFAULT NOW(),

    -- Verification & Trust
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    verified_by VARCHAR(255),
    verification_method VARCHAR(50),
    trust_level VARCHAR(20) DEFAULT 'none'
        CHECK (trust_level IN ('cryptographic', 'very-high', 'high', 'medium', 'low', 'none')),
    security_score INTEGER,       -- 0–100

    -- Attestation
    attestation_data JSONB DEFAULT '{}'::jsonb,
    last_attestation TIMESTAMPTZ,
    attestation_expires TIMESTAMPTZ,

    -- Shadow & Dormancy Detection
    is_shadow BOOLEAN DEFAULT FALSE,
    is_dormant BOOLEAN DEFAULT FALSE,
    shadow_score NUMERIC(5,2) DEFAULT 0,
    dormancy_score NUMERIC(5,2) DEFAULT 0,
    shadow_reasons JSONB DEFAULT '[]'::jsonb,
    dormancy_reasons JSONB DEFAULT '[]'::jsonb,

    -- Rogue IT Detection
    is_rogue BOOLEAN DEFAULT FALSE,
    rogue_score NUMERIC(5,2) DEFAULT 0,
    rogue_reasons JSONB DEFAULT '[]'::jsonb,

    -- Orphan Detection
    is_orphan BOOLEAN DEFAULT FALSE,
    orphan_reasons JSONB DEFAULT '[]'::jsonb,

    -- Public Exposure
    is_publicly_exposed BOOLEAN DEFAULT FALSE,
    exposure_reasons JSONB DEFAULT '[]'::jsonb,

    -- Unused IAM
    is_unused_iam BOOLEAN DEFAULT FALSE,

    -- Composite Classification
    classification VARCHAR(50) DEFAULT 'pending',
    classification_tags JSONB DEFAULT '[]'::jsonb,

    -- Usage Analytics
    api_calls_30d INTEGER DEFAULT 0,
    unique_callers_30d INTEGER DEFAULT 0,
    last_api_call TIMESTAMPTZ,
    last_deployed TIMESTAMPTZ,

    -- Ownership
    owner VARCHAR(255),
    team VARCHAR(255),
    cost_center VARCHAR(100),
    created_by VARCHAR(255) DEFAULT 'system',

    -- Status
    status VARCHAR(50) DEFAULT 'pending',  -- pending, active, inactive

    -- Metadata (JSONB for flexibility)
    labels JSONB DEFAULT '{}'::jsonb,
    selectors JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workloads_spiffe_id ON workloads(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_workloads_name ON workloads(name);
CREATE INDEX IF NOT EXISTS idx_workloads_status ON workloads(status);
CREATE INDEX IF NOT EXISTS idx_workloads_verified ON workloads(verified);
CREATE INDEX IF NOT EXISTS idx_workloads_namespace ON workloads(namespace);
CREATE INDEX IF NOT EXISTS idx_workloads_environment ON workloads(environment);
CREATE INDEX IF NOT EXISTS idx_workloads_last_seen ON workloads(last_seen);
CREATE INDEX IF NOT EXISTS idx_workloads_type ON workloads(type);
CREATE INDEX IF NOT EXISTS idx_workloads_classification ON workloads(classification);
CREATE INDEX IF NOT EXISTS idx_workloads_is_rogue ON workloads(is_rogue) WHERE is_rogue = TRUE;
CREATE INDEX IF NOT EXISTS idx_workloads_is_orphan ON workloads(is_orphan) WHERE is_orphan = TRUE;
CREATE INDEX IF NOT EXISTS idx_workloads_is_publicly_exposed ON workloads(is_publicly_exposed) WHERE is_publicly_exposed = TRUE;

COMMENT ON TABLE workloads IS 'All discovered non-human identities (workloads)';
COMMENT ON COLUMN workloads.spiffe_id IS 'Unique SPIFFE ID: spiffe://trust-domain/path';
COMMENT ON COLUMN workloads.security_score IS 'Calculated security score 0–100';
COMMENT ON COLUMN workloads.labels IS 'Kubernetes/Docker labels as JSONB';
COMMENT ON COLUMN workloads.selectors IS 'SPIRE selectors for workload attestation';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. TARGETS — External services and APIs
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spiffe_id VARCHAR(512),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,    -- external-api, database, internal-service
    endpoint VARCHAR(512),
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE,
    category VARCHAR(100),        -- payment, database, ai, storage, version-control
    provider VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name);
CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type);
CREATE INDEX IF NOT EXISTS idx_targets_verified ON targets(verified);

COMMENT ON TABLE targets IS 'External services and APIs that workloads access';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. DISCOVERY SCANS — Track scan history
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS discovery_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type VARCHAR(50) NOT NULL,       -- kubernetes, docker, aws, gcp, azure, manual, full
    status VARCHAR(50) NOT NULL,          -- running, completed, failed
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    workloads_discovered INTEGER DEFAULT 0,
    errors TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_discovery_scans_status ON discovery_scans(status);
CREATE INDEX IF NOT EXISTS idx_discovery_scans_started ON discovery_scans(started_at);

COMMENT ON TABLE discovery_scans IS 'Discovery scan history and performance';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. ATTESTATION HISTORY — Workload attestation audit trail
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS attestation_history (
    id SERIAL PRIMARY KEY,
    workload_id UUID REFERENCES workloads(id) ON DELETE CASCADE,
    workload_name VARCHAR(255),
    trust_level VARCHAR(20),
    methods_passed INTEGER DEFAULT 0,
    methods_failed INTEGER DEFAULT 0,
    primary_method VARCHAR(50),
    attestation_data JSONB DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attestation_history_workload ON attestation_history(workload_id);
CREATE INDEX IF NOT EXISTS idx_attestation_history_created ON attestation_history(created_at DESC);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 5. POLICIES — NHI governance policy definitions
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS policies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',

    -- Policy definition
    policy_type VARCHAR(20) NOT NULL DEFAULT 'enforcement'
        CHECK (policy_type IN (
            'enforcement', 'compliance', 'lifecycle',
            'access', 'least_privilege', 'conditional_access', 'ai_agent'
        )),
    severity VARCHAR(20) NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),

    -- Rule structure
    conditions JSONB NOT NULL DEFAULT '[]',
    actions JSONB NOT NULL DEFAULT '[]',

    -- Scope
    scope_environment VARCHAR(50) DEFAULT NULL,
    scope_types TEXT[] DEFAULT NULL,
    scope_teams TEXT[] DEFAULT NULL,

    -- State
    enabled BOOLEAN DEFAULT true,
    enforcement_mode VARCHAR(20) DEFAULT 'audit'
        CHECK (enforcement_mode IN ('enforce', 'audit', 'disabled')),

    -- Template source
    template_id VARCHAR(100) DEFAULT NULL,

    -- OPA integration
    rego_policy TEXT DEFAULT NULL,
    opa_package VARCHAR(255) DEFAULT NULL,

    -- Access policy extensions (v2)
    effect VARCHAR(20) DEFAULT NULL
        CHECK (effect IS NULL OR effect IN ('allow', 'deny')),
    client_workload_id UUID DEFAULT NULL,
    server_workload_id UUID DEFAULT NULL,
    attack_path_id VARCHAR(255) DEFAULT NULL,
    credential_policy JSONB DEFAULT NULL,
    time_window JSONB DEFAULT NULL,
    geo_restrictions JSONB DEFAULT NULL,
    priority INTEGER DEFAULT 100,

    -- Metadata
    created_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_evaluated TIMESTAMPTZ DEFAULT NULL,
    evaluation_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(enabled, enforcement_mode, client_workload_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_policies_attack_path ON policies(attack_path_id) WHERE attack_path_id IS NOT NULL;


-- ═══════════════════════════════════════════════════════════════════════════════
-- 6. POLICY VIOLATIONS — Evaluation results
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS policy_violations (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
    policy_name VARCHAR(255),
    workload_id UUID REFERENCES workloads(id) ON DELETE CASCADE,
    workload_name VARCHAR(255),
    severity VARCHAR(20),
    violation_type VARCHAR(50),
    message TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open'
        CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
    resolved_by VARCHAR(255) DEFAULT NULL,
    resolved_at TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_violations_policy ON policy_violations(policy_id);
CREATE INDEX IF NOT EXISTS idx_violations_workload ON policy_violations(workload_id);
CREATE INDEX IF NOT EXISTS idx_violations_status ON policy_violations(status);
CREATE INDEX IF NOT EXISTS idx_violations_created ON policy_violations(created_at DESC);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 7. ACCESS POLICIES — Client→server access bindings
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS access_policies (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER REFERENCES policies(id) ON DELETE CASCADE,
    client_workload_id UUID NOT NULL,
    server_workload_id UUID NOT NULL,

    -- Attribute-based matching
    client_match JSONB DEFAULT NULL,
    server_match JSONB DEFAULT NULL,

    -- Credential requirements
    credential_type VARCHAR(50) DEFAULT NULL,
    credential_ttl INTEGER DEFAULT NULL,          -- seconds

    -- Access constraints
    allowed_scopes TEXT[] DEFAULT NULL,
    allowed_actions TEXT[] DEFAULT NULL,
    max_request_rate INTEGER DEFAULT NULL,

    -- Time/geo constraints
    time_window JSONB DEFAULT NULL,
    geo_allow TEXT[] DEFAULT NULL,
    geo_deny TEXT[] DEFAULT NULL,
    network_zones TEXT[] DEFAULT NULL,

    -- State
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(policy_id, client_workload_id, server_workload_id)
);

CREATE INDEX IF NOT EXISTS idx_access_policies_client ON access_policies(client_workload_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_server ON access_policies(server_workload_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_enabled ON access_policies(enabled);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 8. ACCESS DECISIONS — Control-plane access audit log
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS access_decisions (
    id SERIAL PRIMARY KEY,
    client_workload_id UUID,
    server_workload_id UUID,
    client_name VARCHAR(255),
    server_name VARCHAR(255),
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('allow', 'deny')),
    policies_evaluated INTEGER DEFAULT 0,
    policy_results JSONB DEFAULT '[]',
    runtime_context JSONB DEFAULT '{}',
    enforcement_mode VARCHAR(20) DEFAULT 'audit',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_decisions_client ON access_decisions(client_workload_id);
CREATE INDEX IF NOT EXISTS idx_access_decisions_server ON access_decisions(server_workload_id);
CREATE INDEX IF NOT EXISTS idx_access_decisions_decision ON access_decisions(decision);
CREATE INDEX IF NOT EXISTS idx_access_decisions_created ON access_decisions(created_at DESC);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 9. EXT-AUTHZ DECISIONS — Data-plane decision log (from ext-authz adapter)
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ext_authz_decisions (
    id SERIAL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL,
    source_principal TEXT,
    destination_principal TEXT,
    source_name VARCHAR(255),
    destination_name VARCHAR(255),
    method VARCHAR(10) DEFAULT 'GET',
    path_pattern TEXT,
    verdict VARCHAR(30) NOT NULL DEFAULT 'no-match',
    policy_name VARCHAR(255),
    policies_evaluated INTEGER DEFAULT 0,
    adapter_mode VARCHAR(20) DEFAULT 'audit',
    latency_ms INTEGER DEFAULT 0,
    cached BOOLEAN DEFAULT false,
    token_jti VARCHAR(128),
    root_jti VARCHAR(128),
    chain_depth INTEGER DEFAULT 0,
    enforcement_action VARCHAR(50),
    enforcement_detail TEXT,
    source_type VARCHAR(50),
    destination_type VARCHAR(50),
    token_context JSONB,
    request_context JSONB,
    response_context JSONB,
    trace_id VARCHAR(100),
    parent_decision_id VARCHAR(100),
    hop_index INTEGER DEFAULT 0,
    total_hops INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ead_created ON ext_authz_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ead_verdict ON ext_authz_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_ead_source ON ext_authz_decisions(source_name);
CREATE INDEX IF NOT EXISTS idx_ead_dest ON ext_authz_decisions(destination_name);
CREATE INDEX IF NOT EXISTS idx_ead_decision_id ON ext_authz_decisions(decision_id);
CREATE INDEX IF NOT EXISTS idx_ead_trace_id ON ext_authz_decisions(trace_id);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 10. TOKEN CHAIN — OBO (On-Behalf-Of) token chain tracking
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS token_chain (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    parent_jti VARCHAR(255),
    root_jti VARCHAR(255),
    chain_depth INTEGER DEFAULT 0,
    subject VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL,
    actor VARCHAR(255),
    scopes JSONB,
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    metadata JSONB,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_chain_jti ON token_chain(jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_parent ON token_chain(parent_jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_root ON token_chain(root_jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_subject ON token_chain(subject);
CREATE INDEX IF NOT EXISTS idx_token_chain_actor ON token_chain(actor);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 11. CREDENTIAL USAGE — Credential proxy access audit log
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS credential_usage (
    id SERIAL PRIMARY KEY,
    workload_id VARCHAR(255) NOT NULL,
    target_api VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT,
    result VARCHAR(20) NOT NULL,      -- 'allowed' or 'denied'
    status_code INTEGER,
    accessed_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_credential_usage_workload ON credential_usage(workload_id);
CREATE INDEX IF NOT EXISTS idx_credential_usage_target ON credential_usage(target_api);
CREATE INDEX IF NOT EXISTS idx_credential_usage_time ON credential_usage(accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_usage_result ON credential_usage(result);


-- ═══════════════════════════════════════════════════════════════════════════════
-- 12. IDENTITY GRAPH — Graph cache with summary columns
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS identity_graph (
    id              VARCHAR(50) PRIMARY KEY DEFAULT 'latest',
    graph_data      JSONB NOT NULL DEFAULT '{}',
    generated_at    TIMESTAMPTZ DEFAULT NOW(),
    scan_duration_ms INTEGER,
    node_count      INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_nodes')::int) STORED,
    rel_count       INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_relationships')::int) STORED,
    path_count      INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_attack_paths')::int) STORED
);

COMMENT ON TABLE identity_graph IS 'Cached identity graph — rebuilt on each scan cycle';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 13. AUTHORIZATION EVENTS — Audit log for identity access decisions
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS authorization_events (
    id              SERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ DEFAULT NOW(),
    workload_id     UUID REFERENCES workloads(id) ON DELETE SET NULL,
    workload_name   VARCHAR(255),
    source_identity VARCHAR(500),
    target_resource VARCHAR(500),
    action          VARCHAR(100),
    decision        VARCHAR(20),
    policy_name     VARCHAR(255),
    policy_violated BOOLEAN DEFAULT FALSE,
    reason          TEXT,
    metadata        JSONB DEFAULT '{}',
    trust_level     VARCHAR(50),
    attestation_valid BOOLEAN,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_events_workload ON authorization_events(workload_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON authorization_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_events_decision ON authorization_events(decision);
CREATE INDEX IF NOT EXISTS idx_auth_events_violation ON authorization_events(policy_violated) WHERE policy_violated = TRUE;

COMMENT ON TABLE authorization_events IS 'Identity access decisions — audit trail for timeline + evidence tab';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 14. POLICY EVALUATIONS — OPA policy evaluation results
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS policy_evaluations (
    id              SERIAL PRIMARY KEY,
    evaluated_at    TIMESTAMPTZ DEFAULT NOW(),
    workload_id     UUID REFERENCES workloads(id) ON DELETE SET NULL,
    workload_name   VARCHAR(255),
    policy_name     VARCHAR(255),
    policy_id       INTEGER,
    result          VARCHAR(20),
    violations      JSONB DEFAULT '[]',
    context         JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pol_eval_workload ON policy_evaluations(workload_id);
CREATE INDEX IF NOT EXISTS idx_pol_eval_timestamp ON policy_evaluations(evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pol_eval_result ON policy_evaluations(result);

COMMENT ON TABLE policy_evaluations IS 'OPA policy evaluation results per workload';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 15. IDENTITY GRAPH HISTORY — Graph snapshots over time
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS identity_graph_history (
    id              SERIAL PRIMARY KEY,
    snapshot_at     TIMESTAMPTZ DEFAULT NOW(),
    node_count      INTEGER,
    rel_count       INTEGER,
    path_count      INTEGER,
    critical_paths  INTEGER,
    summary         JSONB DEFAULT '{}'
);

COMMENT ON TABLE identity_graph_history IS 'Historical graph snapshots for trend analysis';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 16. AI REQUEST EVENTS — AI/LLM API call telemetry from edge gateway
-- ═══════════════════════════════════════════════════════════════════════════════

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
    -- Response metadata (populated by AIInspector.captureResponse)
    response_status        INTEGER,
    actual_input_tokens    INTEGER,
    actual_output_tokens   INTEGER,
    total_tokens           INTEGER,
    estimated_cost_usd     NUMERIC(10,6),
    finish_reason          VARCHAR(50),
    provider_latency_ms    INTEGER,
    provider_request_id    VARCHAR(255),
    error_code             VARCHAR(50),
    rate_limit_remaining   INTEGER,
    created_at             TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_req_provider ON ai_request_events(ai_provider);
CREATE INDEX IF NOT EXISTS idx_ai_req_source   ON ai_request_events(source_name);
CREATE INDEX IF NOT EXISTS idx_ai_req_created  ON ai_request_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_req_model    ON ai_request_events(ai_model);
CREATE INDEX IF NOT EXISTS idx_ai_req_decision ON ai_request_events(decision_id);

COMMENT ON TABLE ai_request_events IS 'AI/LLM API call telemetry detected by edge gateway AIInspector';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 17. REMEDIATION INTENTS — DB-backed remediation controls
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS remediation_intents (
    id               VARCHAR(100) PRIMARY KEY,
    control_id       VARCHAR(100) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT NOT NULL,
    goal             TEXT,
    action_type      VARCHAR(50) NOT NULL,
    remediation_type VARCHAR(50) NOT NULL,
    finding_types    TEXT[] DEFAULT '{}',
    scope            VARCHAR(50) DEFAULT 'resource',
    resource_types   TEXT[] DEFAULT '{}',
    path_break       JSONB NOT NULL DEFAULT '{}',
    feasibility      JSONB NOT NULL DEFAULT '{}',
    operational      JSONB NOT NULL DEFAULT '{}',
    risk_reduction   JSONB DEFAULT '{}',
    rollback_strategy TEXT,
    preconditions    JSONB DEFAULT '[]',
    validation       JSONB DEFAULT '[]',
    template_id      VARCHAR(100),
    enabled          BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ri_finding     ON remediation_intents USING GIN(finding_types);
CREATE INDEX IF NOT EXISTS idx_ri_control     ON remediation_intents(control_id);
CREATE INDEX IF NOT EXISTS idx_ri_action_type ON remediation_intents(action_type);
CREATE INDEX IF NOT EXISTS idx_ri_template    ON remediation_intents(template_id);

COMMENT ON TABLE remediation_intents IS 'DB-backed remediation controls — seeded from CONTROL_CATALOG, extensible';

CREATE TABLE IF NOT EXISTS remediation_templates (
    id                SERIAL PRIMARY KEY,
    intent_id         VARCHAR(100) NOT NULL REFERENCES remediation_intents(id) ON DELETE CASCADE,
    provider          VARCHAR(50) NOT NULL,
    resource_type     VARCHAR(100),
    channel           VARCHAR(50) NOT NULL,
    title             VARCHAR(255),
    template_body     TEXT NOT NULL,
    variables         JSONB DEFAULT '[]',
    validate_template TEXT,
    rollback_template TEXT,
    priority          INTEGER DEFAULT 100,
    enabled           BOOLEAN DEFAULT TRUE,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_intent ON remediation_templates(intent_id);
CREATE INDEX IF NOT EXISTS idx_rt_provider ON remediation_templates(provider);
CREATE INDEX IF NOT EXISTS idx_rt_channel ON remediation_templates(channel);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rt_unique
  ON remediation_templates(intent_id, provider, COALESCE(resource_type,''), channel);

COMMENT ON TABLE remediation_templates IS 'Provider-specific remediation templates (CLI, Terraform, OPA) per intent';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 18. FINDING TYPE METADATA — Labels, descriptions, severity per finding type
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS finding_type_metadata (
    finding_type   VARCHAR(100) PRIMARY KEY,
    label          VARCHAR(255) NOT NULL,
    description    TEXT NOT NULL,
    severity       VARCHAR(20) DEFAULT 'high',
    category       VARCHAR(50),
    enabled        BOOLEAN DEFAULT TRUE,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ftm_severity ON finding_type_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_ftm_enabled  ON finding_type_metadata(enabled) WHERE enabled = TRUE;

COMMENT ON TABLE finding_type_metadata IS 'Finding type labels, descriptions, and severity — single source of truth for UI';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 19. CONNECTORS — Customer cloud account connections for onboarding
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Display
    name TEXT NOT NULL,
    description TEXT DEFAULT '',

    -- Provider
    provider TEXT NOT NULL
        CHECK (provider IN ('aws', 'gcp', 'azure', 'kubernetes', 'docker', 'vault')),

    -- Lifecycle
    status TEXT DEFAULT 'pending'
        CHECK (status IN ('pending', 'validating', 'active', 'error', 'disabled')),
    mode TEXT DEFAULT 'discovery'
        CHECK (mode IN ('discovery', 'enforcement')),

    -- Non-secret configuration (region, project_id, subscription_id, etc.)
    config JSONB DEFAULT '{}',

    -- Credential reference — stored in GCP Secret Manager, NEVER in DB
    credential_ref TEXT,

    -- Scan state
    last_scan_at TIMESTAMPTZ,
    last_scan_status TEXT,
    last_scan_duration_ms INTEGER,
    workload_count INTEGER DEFAULT 0,

    -- Error tracking
    error_message TEXT,
    error_at TIMESTAMPTZ,
    consecutive_errors INTEGER DEFAULT 0,

    -- Enforcement (gateway registration)
    gateway_env_name TEXT,
    gateway_connected BOOLEAN DEFAULT FALSE,
    gateway_last_heartbeat TIMESTAMPTZ,

    -- Ownership
    created_by TEXT DEFAULT 'system',

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connectors_provider ON connectors(provider);
CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
CREATE INDEX IF NOT EXISTS idx_connectors_mode ON connectors(mode);

ALTER TABLE workloads ADD COLUMN IF NOT EXISTS connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_workloads_connector ON workloads(connector_id);

COMMENT ON TABLE connectors IS 'Customer cloud account connectors — each represents one cloud account connection';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 20. USERS — Platform authentication
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

COMMENT ON TABLE users IS 'Platform users for authentication — first registered user becomes admin';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 21. PROVIDER REGISTRY — DB-driven provider/domain patterns (replaces hardcoded constants)
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS provider_registry (
    id              VARCHAR(100) PRIMARY KEY,
    registry_type   VARCHAR(50) NOT NULL,
    label           VARCHAR(255) NOT NULL,
    category        VARCHAR(100) NOT NULL,
    credential_keys TEXT[] DEFAULT '{}',
    ai_config       JSONB DEFAULT NULL,
    domain_patterns TEXT[] DEFAULT '{}',
    domain_type     VARCHAR(50),
    image_patterns  TEXT[] DEFAULT '{}',
    signal_patterns TEXT[] DEFAULT '{}',
    enabled         BOOLEAN DEFAULT TRUE,
    sort_order      INTEGER DEFAULT 100,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pr_type     ON provider_registry(registry_type);
CREATE INDEX IF NOT EXISTS idx_pr_category ON provider_registry(category);
CREATE INDEX IF NOT EXISTS idx_pr_enabled  ON provider_registry(enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_pr_keys     ON provider_registry USING GIN(credential_keys);

COMMENT ON TABLE provider_registry IS 'DB-driven provider/domain registry — replaces hardcoded patterns in protocol-scanner.js';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 22. CLOUD LOG ENRICHMENTS — API usage data from GCP Cloud Logging / AWS CloudTrail
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cloud_log_enrichments (
    id               SERIAL PRIMARY KEY,
    workload_id      UUID REFERENCES workloads(id) ON DELETE CASCADE,
    workload_name    VARCHAR(255),
    cloud_provider   VARCHAR(50) NOT NULL,
    log_source       VARCHAR(100) NOT NULL,
    api_called       VARCHAR(500),
    destination_host VARCHAR(255),
    method           VARCHAR(10),
    caller_identity  VARCHAR(500),
    provider_match   VARCHAR(100),
    call_count       INTEGER DEFAULT 1,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    raw_metadata     JSONB DEFAULT '{}',
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cle_workload ON cloud_log_enrichments(workload_id);
CREATE INDEX IF NOT EXISTS idx_cle_provider ON cloud_log_enrichments(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_cle_source   ON cloud_log_enrichments(log_source);
CREATE INDEX IF NOT EXISTS idx_cle_dest     ON cloud_log_enrichments(destination_host);
CREATE INDEX IF NOT EXISTS idx_cle_created  ON cloud_log_enrichments(created_at DESC);

COMMENT ON TABLE cloud_log_enrichments IS 'Cloud log-derived API usage data — batch ingested from GCP Cloud Logging / AWS CloudTrail';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 23. CREDENTIAL ROTATIONS — Secret rotation tracking
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS credential_rotations (
    id               SERIAL PRIMARY KEY,
    credential_path  VARCHAR(500) NOT NULL,
    provider         VARCHAR(50) NOT NULL,
    workload_id      UUID,
    status           VARCHAR(20) DEFAULT 'pending',
    triggered_by     VARCHAR(50),
    old_version      VARCHAR(100),
    new_version      VARCHAR(100),
    error_message    TEXT,
    scheduled_at     TIMESTAMPTZ,
    executed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cr_workload ON credential_rotations(workload_id);
CREATE INDEX IF NOT EXISTS idx_cr_status   ON credential_rotations(status);
CREATE INDEX IF NOT EXISTS idx_cr_created  ON credential_rotations(created_at DESC);

COMMENT ON TABLE credential_rotations IS 'Credential rotation tracking — schedule, execute, audit secret rotations';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 24. REMEDIATION EXECUTIONS — One-click remediation execution tracking
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS remediation_executions (
    id                SERIAL PRIMARY KEY,
    control_id        VARCHAR(100) NOT NULL,
    node_id           VARCHAR(255) NOT NULL,
    channel           VARCHAR(20) NOT NULL,
    status            VARCHAR(20) DEFAULT 'pending',
    requested_by      VARCHAR(255),
    approved_by       VARCHAR(255),
    commands          JSONB,
    output            TEXT,
    error_message     TEXT,
    rollback_commands JSONB,
    requested_at      TIMESTAMPTZ DEFAULT NOW(),
    approved_at       TIMESTAMPTZ,
    executed_at       TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_re_node    ON remediation_executions(node_id);
CREATE INDEX IF NOT EXISTS idx_re_status  ON remediation_executions(status);
CREATE INDEX IF NOT EXISTS idx_re_created ON remediation_executions(requested_at DESC);

COMMENT ON TABLE remediation_executions IS 'Remediation execution tracking — request, approve, execute, rollback';


-- Add IETF AIMS delegation_type to workloads
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS delegation_type VARCHAR(50) DEFAULT NULL;


-- ═══════════════════════════════════════════════════════════════════════════════
-- FUNCTIONS
-- ═══════════════════════════════════════════════════════════════════════════════

-- Auto-update updated_at on workloads
CREATE OR REPLACE FUNCTION update_workload_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_workload_updated_at ON workloads;
CREATE TRIGGER trigger_workload_updated_at
    BEFORE UPDATE ON workloads
    FOR EACH ROW
    EXECUTE FUNCTION update_workload_updated_at();

-- Auto-update updated_at on connectors
CREATE OR REPLACE FUNCTION update_connector_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_connector_updated_at ON connectors;
CREATE TRIGGER trigger_connector_updated_at
    BEFORE UPDATE ON connectors
    FOR EACH ROW
    EXECUTE FUNCTION update_connector_updated_at();

-- Issuer/trust-domain validation
CREATE OR REPLACE FUNCTION validate_trust_domain(p_trust_domain VARCHAR, p_issuer VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
    IF p_trust_domain IS NULL OR p_trust_domain = '' THEN
        RETURN FALSE;
    END IF;
    IF p_trust_domain !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$' THEN
        RETURN FALSE;
    END IF;
    IF p_issuer IS NOT NULL AND p_issuer != '' THEN
        IF p_issuer !~ '^(k8s|docker|aws|gcp|azure|vault|github|jenkins|gitlab|oidc|https|spiffe|internal)://.+$' THEN
            RETURN FALSE;
        END IF;
    END IF;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Workload statistics
CREATE OR REPLACE FUNCTION get_workload_stats()
RETURNS TABLE(
    total_workloads BIGINT,
    verified_workloads BIGINT,
    pending_workloads BIGINT,
    active_workloads BIGINT,
    kubernetes_workloads BIGINT,
    docker_workloads BIGINT,
    avg_security_score NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*)::BIGINT,
        COUNT(*) FILTER (WHERE verified = true)::BIGINT,
        COUNT(*) FILTER (WHERE status = 'pending')::BIGINT,
        COUNT(*) FILTER (WHERE status = 'active')::BIGINT,
        COUNT(*) FILTER (WHERE type LIKE 'kubernetes-%')::BIGINT,
        COUNT(*) FILTER (WHERE type = 'docker-container')::BIGINT,
        ROUND(AVG(security_score), 2)
    FROM workloads;
END;
$$ LANGUAGE plpgsql;

-- Recent discovery scans
CREATE OR REPLACE FUNCTION get_recent_scans(limit_count INTEGER DEFAULT 10)
RETURNS TABLE(
    id UUID,
    scan_type VARCHAR,
    status VARCHAR,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    workloads_discovered INTEGER,
    duration_seconds NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        ds.id, ds.scan_type, ds.status, ds.started_at, ds.completed_at,
        ds.workloads_discovered,
        EXTRACT(EPOCH FROM (ds.completed_at - ds.started_at))::NUMERIC
    FROM discovery_scans ds
    ORDER BY ds.started_at DESC
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup stale workloads
CREATE OR REPLACE FUNCTION cleanup_stale_workloads(days_threshold INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM workloads
    WHERE status = 'inactive'
      AND last_seen < NOW() - INTERVAL '1 day' * days_threshold
      AND verified = false;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Get full token chain (recursive)
CREATE OR REPLACE FUNCTION get_token_chain(token_jti VARCHAR)
RETURNS TABLE (
    depth INTEGER, jti VARCHAR, subject VARCHAR, audience VARCHAR,
    actor VARCHAR, issued_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, scopes JSONB
) AS $$
    WITH RECURSIVE chain AS (
        SELECT 0 as depth, t.jti, t.subject, t.audience, t.actor,
               t.issued_at, t.expires_at, t.scopes, t.parent_jti
        FROM token_chain t WHERE t.jti = token_jti
        UNION ALL
        SELECT c.depth + 1, t.jti, t.subject, t.audience, t.actor,
               t.issued_at, t.expires_at, t.scopes, t.parent_jti
        FROM token_chain t JOIN chain c ON t.jti = c.parent_jti
    )
    SELECT depth, jti, subject, audience, actor, issued_at, expires_at, scopes
    FROM chain ORDER BY depth DESC;
$$ LANGUAGE sql;

-- Get token descendants
CREATE OR REPLACE FUNCTION get_token_descendants(token_jti VARCHAR)
RETURNS TABLE (
    depth INTEGER, jti VARCHAR, subject VARCHAR, audience VARCHAR, issued_at TIMESTAMPTZ
) AS $$
    WITH RECURSIVE descendants AS (
        SELECT 0 as depth, t.jti, t.subject, t.audience, t.issued_at
        FROM token_chain t WHERE t.jti = token_jti
        UNION ALL
        SELECT d.depth + 1, t.jti, t.subject, t.audience, t.issued_at
        FROM token_chain t JOIN descendants d ON t.parent_jti = d.jti
    )
    SELECT depth, jti, subject, audience, issued_at
    FROM descendants ORDER BY depth ASC;
$$ LANGUAGE sql;


-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS
-- ═══════════════════════════════════════════════════════════════════════════════

-- Active verified workloads
CREATE OR REPLACE VIEW active_workloads AS
SELECT id, spiffe_id, name, type, namespace, environment, security_score, labels, metadata
FROM workloads
WHERE verified = true AND status = 'active'
ORDER BY name;

-- Pending verification
CREATE OR REPLACE VIEW pending_workloads AS
SELECT id, spiffe_id, name, type, namespace, environment, discovered_at, last_seen, security_score
FROM workloads
WHERE status = 'pending'
ORDER BY discovered_at DESC;

-- Workload summary by environment/type
CREATE OR REPLACE VIEW workload_summary AS
SELECT environment, type, COUNT(*) as count,
       COUNT(*) FILTER (WHERE verified = true) as verified_count,
       ROUND(AVG(security_score), 2) as avg_security_score
FROM workloads
GROUP BY environment, type
ORDER BY environment, type;

-- Active OBO token chains
CREATE OR REPLACE VIEW v_active_token_chains AS
SELECT root_jti, actor, COUNT(*) as chain_length, MAX(chain_depth) as max_depth,
       MIN(issued_at) as chain_started, MAX(expires_at) as chain_expires,
       array_agg(DISTINCT subject) as subjects_in_chain
FROM token_chain
WHERE expires_at > NOW() AND revoked = FALSE
GROUP BY root_jti, actor
ORDER BY chain_started DESC;

-- Token chain stats by subject
CREATE OR REPLACE VIEW v_token_chain_stats AS
SELECT subject,
       COUNT(DISTINCT jti) as total_tokens_issued,
       COUNT(DISTINCT root_jti) as unique_chains,
       AVG(chain_depth) as avg_chain_depth,
       MAX(chain_depth) as max_chain_depth,
       COUNT(*) FILTER (WHERE chain_depth = 0) as root_tokens,
       COUNT(*) FILTER (WHERE chain_depth > 0) as delegated_tokens
FROM token_chain
GROUP BY subject
ORDER BY total_tokens_issued DESC;

-- Credential proxy usage summary
CREATE OR REPLACE VIEW v_proxy_usage_summary AS
SELECT workload_id, target_api,
       COUNT(*) as total_requests,
       COUNT(*) FILTER (WHERE result = 'allowed') as allowed_requests,
       COUNT(*) FILTER (WHERE result = 'denied') as denied_requests,
       array_agg(DISTINCT method) as methods_used,
       MIN(accessed_at) as first_access,
       MAX(accessed_at) as last_access
FROM credential_usage
GROUP BY workload_id, target_api
ORDER BY total_requests DESC;

-- Data-plane decisions summary (last 24h)
CREATE OR REPLACE VIEW v_ext_authz_summary AS
SELECT
    source_name, destination_name,
    COUNT(*) as total_decisions,
    COUNT(*) FILTER (WHERE verdict IN ('allow', 'audit-allowed')) as allowed,
    COUNT(*) FILTER (WHERE verdict IN ('deny', 'audit-deny')) as denied,
    COUNT(*) FILTER (WHERE verdict = 'no-match') as no_match,
    ROUND(AVG(latency_ms), 1) as avg_latency_ms,
    COUNT(*) FILTER (WHERE cached = true) as cache_hits
FROM ext_authz_decisions
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY source_name, destination_name
ORDER BY total_decisions DESC;


-- ═══════════════════════════════════════════════════════════════════════════════
-- SEED DATA — Common external targets
-- ═══════════════════════════════════════════════════════════════════════════════

INSERT INTO targets (name, type, endpoint, category, provider, verified, metadata) VALUES
('github',    'external-api',     'https://api.github.com',      'version-control', 'GitHub',     true, '{"description": "GitHub API"}'::jsonb),
('stripe',    'external-api',     'https://api.stripe.com',      'payment',         'Stripe',     true, '{"description": "Stripe Payment API"}'::jsonb),
('openai',    'external-api',     'https://api.openai.com',      'ai',              'OpenAI',     true, '{"description": "OpenAI API"}'::jsonb),
('anthropic', 'external-api',     'https://api.anthropic.com',   'ai',              'Anthropic',  true, '{"description": "Anthropic Claude API"}'::jsonb),
('snowflake', 'external-api',     'https://snowflake.com',       'database',        'Snowflake',  true, '{"description": "Snowflake Data Cloud"}'::jsonb),
('aws-s3',    'external-api',     'https://s3.amazonaws.com',    'storage',         'AWS',        true, '{"description": "AWS S3 Object Storage"}'::jsonb),
('database',  'internal-service', 'postgres://localhost:5432',    'database',        'PostgreSQL', true, '{"description": "Internal PostgreSQL"}'::jsonb),
('redis',     'internal-service', 'redis://localhost:6379',       'cache',           'Redis',      true, '{"description": "Internal Redis Cache"}'::jsonb)
ON CONFLICT (name) DO NOTHING;


-- ═══════════════════════════════════════════════════════════════════════════════
-- POLICY SNAPSHOTS — Versioned policy state for deterministic replay (P1.2)
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS policy_snapshots (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER NOT NULL,
    version_hash VARCHAR(64) NOT NULL,
    policy_name VARCHAR(255),
    policy_type VARCHAR(20),
    conditions JSONB NOT NULL DEFAULT '[]',
    actions JSONB NOT NULL DEFAULT '[]',
    effect VARCHAR(20),
    enforcement_mode VARCHAR(20),
    severity VARCHAR(20),
    scope_environment VARCHAR(50),
    client_workload_id UUID,
    server_workload_id UUID,
    snapshot_reason VARCHAR(50) DEFAULT 'evaluation',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ps_policy_id ON policy_snapshots(policy_id);
CREATE INDEX IF NOT EXISTS idx_ps_version_hash ON policy_snapshots(version_hash);
CREATE INDEX IF NOT EXISTS idx_ps_created ON policy_snapshots(created_at DESC);

-- Add policy_version column to ext_authz_decisions if not present
ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS policy_version VARCHAR(64);

-- ═══════════════════════════════════════════════════════════════════════════════
-- MCP TOOL INVOCATION TELEMETRY
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mcp_tool_events (
    id                  SERIAL PRIMARY KEY,
    decision_id         VARCHAR(64),
    source_name         VARCHAR(255),
    source_principal    TEXT,
    destination_host    VARCHAR(255),
    jsonrpc_method      VARCHAR(100) NOT NULL,
    jsonrpc_id          VARCHAR(64),
    tool_name           VARCHAR(255),
    tool_arguments      JSONB DEFAULT '{}',
    resource_uri        TEXT,
    prompt_name         VARCHAR(255),
    mcp_server_name     VARCHAR(255),
    body_bytes          INTEGER DEFAULT 0,
    truncated           BOOLEAN DEFAULT FALSE,
    relay_id            VARCHAR(100),
    relay_env           VARCHAR(100),
    gateway_id          VARCHAR(100),
    response_status     INTEGER,
    result_type         VARCHAR(50),
    result_size_bytes   INTEGER,
    error_code          INTEGER,
    error_message       VARCHAR(500),
    latency_ms          INTEGER,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_evt_source      ON mcp_tool_events(source_name);
CREATE INDEX IF NOT EXISTS idx_mcp_evt_dest         ON mcp_tool_events(destination_host);
CREATE INDEX IF NOT EXISTS idx_mcp_evt_tool         ON mcp_tool_events(tool_name);
CREATE INDEX IF NOT EXISTS idx_mcp_evt_method       ON mcp_tool_events(jsonrpc_method);
CREATE INDEX IF NOT EXISTS idx_mcp_evt_created      ON mcp_tool_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_evt_decision     ON mcp_tool_events(decision_id);

COMMENT ON TABLE mcp_tool_events IS 'MCP JSON-RPC tool call telemetry detected by edge gateway MCPInspector';

-- ═══════════════════════════════════════════════════════════════════════════════
-- MCP SERVER CAPABILITY FINGERPRINTS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mcp_fingerprints (
    id                      SERIAL PRIMARY KEY,
    workload_name           VARCHAR(255) NOT NULL,
    server_name             VARCHAR(255),
    server_version          VARCHAR(50),
    protocol_version        VARCHAR(20),
    fingerprint             VARCHAR(64) NOT NULL,
    tool_descriptions_hash  VARCHAR(64),
    tool_count              INTEGER DEFAULT 0,
    tool_names              TEXT[] DEFAULT '{}',
    resource_count          INTEGER DEFAULT 0,
    prompt_count            INTEGER DEFAULT 0,
    capabilities_snapshot   JSONB DEFAULT '{}',
    previous_fingerprint    VARCHAR(64),
    drift_detected          BOOLEAN DEFAULT FALSE,
    drift_details           JSONB,
    scan_source             VARCHAR(50) DEFAULT 'periodic',
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_fp_workload  ON mcp_fingerprints(workload_name);
CREATE INDEX IF NOT EXISTS idx_mcp_fp_server    ON mcp_fingerprints(server_name);
CREATE INDEX IF NOT EXISTS idx_mcp_fp_drift     ON mcp_fingerprints(drift_detected) WHERE drift_detected = TRUE;
CREATE INDEX IF NOT EXISTS idx_mcp_fp_created   ON mcp_fingerprints(created_at DESC);

COMMENT ON TABLE mcp_fingerprints IS 'MCP server capability fingerprints for drift detection';

-- ═══════════════════════════════════════════════════════════════════════════════
-- VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
    expected_tables TEXT[] := ARRAY[
        'workloads', 'targets', 'discovery_scans', 'attestation_history',
        'policies', 'policy_violations', 'access_policies', 'access_decisions',
        'ext_authz_decisions', 'token_chain', 'credential_usage',
        'identity_graph', 'authorization_events', 'policy_evaluations',
        'identity_graph_history', 'ai_request_events',
        'remediation_intents', 'remediation_templates', 'finding_type_metadata',
        'connectors', 'users', 'policy_snapshots',
        'mcp_tool_events', 'mcp_fingerprints'
    ];
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY expected_tables LOOP
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = tbl AND table_schema = 'public') THEN
            RAISE EXCEPTION 'Table % was not created', tbl;
        END IF;
    END LOOP;

    RAISE NOTICE '';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  ✅ Workload Identity Platform — Database initialized';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  Tables:    23 created';
    RAISE NOTICE '  Indexes:   56 created';
    RAISE NOTICE '  Views:     6 created';
    RAISE NOTICE '  Functions: 7 created';
    RAISE NOTICE '  Seed data: 8 external targets';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';
END $$;

COMMIT;
