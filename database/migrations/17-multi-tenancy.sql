-- =============================================================================
-- Migration 17: Multi-Tenancy — Tenant Isolation, RLS, Data Sovereignty
-- =============================================================================
--
-- Adds tenant isolation to all data tables. Three-layer defense:
--   L1: Application middleware sets tenant context per request
--   L2: PostgreSQL RLS enforces isolation at DB level
--   L3: In-memory caches keyed by (tenantId, key)
--
-- Run: psql -U wid_user -d workload_identity -f database/migrations/17-multi-tenancy.sql
-- =============================================================================

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. TENANTS TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,                          -- URL-safe identifier (e.g., "acme-corp")

    -- Plan & limits
    plan TEXT NOT NULL DEFAULT 'trial',                 -- trial, pro, enterprise
    max_users INTEGER NOT NULL DEFAULT 10,
    max_workloads INTEGER NOT NULL DEFAULT 1000,
    max_connectors INTEGER NOT NULL DEFAULT 20,
    max_policies INTEGER NOT NULL DEFAULT 500,

    -- Data sovereignty
    data_region TEXT NOT NULL DEFAULT 'us',             -- us, eu, apac
    data_residency_strict BOOLEAN NOT NULL DEFAULT false, -- true = data never leaves region
    allowed_regions TEXT[] NOT NULL DEFAULT '{us}',     -- regions data can exist in

    -- Settings
    settings JSONB NOT NULL DEFAULT '{}',
    features JSONB NOT NULL DEFAULT '{}',               -- feature flags per tenant

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_data_region ON tenants(data_region);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. TENANT INVITATIONS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS tenant_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',                -- admin, operator, viewer
    invited_by UUID,                                    -- references users(id), nullable for bootstrap
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invitations_token ON tenant_invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_tenant ON tenant_invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON tenant_invitations(email);

-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. DEFAULT TENANT — Backfill existing data
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create a default tenant for existing single-tenant data
INSERT INTO tenants (id, name, slug, plan, data_region)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'enterprise', 'us')
ON CONFLICT (id) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. ADD tenant_id TO ALL DATA TABLES
-- ═══════════════════════════════════════════════════════════════════════════════

-- Helper: Add tenant_id column, backfill with default tenant, set NOT NULL
-- We do each table individually for clarity and error isolation

-- 4a. users
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
-- Drop global unique on email, add per-tenant unique
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
-- Add RBAC role column (admin, operator, viewer)
-- Existing 'role' column is kept but semantics change from global to tenant-scoped

-- 4b. connectors
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE connectors SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE connectors ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE connectors ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);

-- 4c. workloads
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE workloads SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE workloads ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE workloads ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_workloads_tenant ON workloads(tenant_id);

-- 4d. targets
ALTER TABLE targets ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE targets SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE targets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE targets ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_targets_tenant ON targets(tenant_id);

-- 4e. discovery_scans
ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE discovery_scans SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE discovery_scans ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE discovery_scans ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON discovery_scans(tenant_id);

-- 4f. policies
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE policies SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE policies ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE policies ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id);

-- 4g. policy_violations
ALTER TABLE policy_violations ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE policy_violations SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE policy_violations ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE policy_violations ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_violations_tenant ON policy_violations(tenant_id);

-- 4h. access_policies
ALTER TABLE access_policies ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE access_policies SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE access_policies ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE access_policies ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_access_policies_tenant ON access_policies(tenant_id);

-- 4i. access_decisions
ALTER TABLE access_decisions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE access_decisions SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE access_decisions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE access_decisions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_access_decisions_tenant ON access_decisions(tenant_id);

-- 4j. ext_authz_decisions
ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE ext_authz_decisions SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE ext_authz_decisions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ext_authz_decisions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_authz_tenant ON ext_authz_decisions(tenant_id);

-- 4k. token_chain
ALTER TABLE token_chain ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE token_chain SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE token_chain ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE token_chain ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_token_chain_tenant ON token_chain(tenant_id);

-- 4l. ai_request_events
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE ai_request_events SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE ai_request_events ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ai_request_events ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_ai_events_tenant ON ai_request_events(tenant_id);

-- 4m. identity_graph
ALTER TABLE identity_graph ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE identity_graph SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE identity_graph ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE identity_graph ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_identity_graph_tenant ON identity_graph(tenant_id);

-- 4n. remediation_intents
ALTER TABLE remediation_intents ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE remediation_intents SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE remediation_intents ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE remediation_intents ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_remediation_tenant ON remediation_intents(tenant_id);

-- 4o. policy_snapshots
ALTER TABLE policy_snapshots ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE policy_snapshots SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE policy_snapshots ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE policy_snapshots ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_policy_snapshots_tenant ON policy_snapshots(tenant_id);

-- 4p. mcp_tool_events
ALTER TABLE mcp_tool_events ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE mcp_tool_events SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE mcp_tool_events ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mcp_tool_events ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_mcp_events_tenant ON mcp_tool_events(tenant_id);

-- 4q. mcp_fingerprints
ALTER TABLE mcp_fingerprints ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE mcp_fingerprints SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE mcp_fingerprints ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mcp_fingerprints ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_mcp_fingerprints_tenant ON mcp_fingerprints(tenant_id);

-- 4r. policy_templates — nullable tenant_id (system templates have NULL)
ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
-- System templates keep tenant_id = NULL (visible to all tenants)
-- Custom tenant templates get scoped

-- 4s. cloud_log_enrichments (if exists)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'cloud_log_enrichments') THEN
    EXECUTE 'ALTER TABLE cloud_log_enrichments ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id)';
    EXECUTE 'UPDATE cloud_log_enrichments SET tenant_id = ''00000000-0000-0000-0000-000000000001'' WHERE tenant_id IS NULL';
    EXECUTE 'ALTER TABLE cloud_log_enrichments ALTER COLUMN tenant_id SET NOT NULL';
    EXECUTE 'ALTER TABLE cloud_log_enrichments ALTER COLUMN tenant_id SET DEFAULT ''00000000-0000-0000-0000-000000000001''';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_cloud_logs_tenant ON cloud_log_enrichments(tenant_id)';
  END IF;
END $$;

-- 4t. credential_usage (if exists)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'credential_usage') THEN
    EXECUTE 'ALTER TABLE credential_usage ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id)';
    EXECUTE 'UPDATE credential_usage SET tenant_id = ''00000000-0000-0000-0000-000000000001'' WHERE tenant_id IS NULL';
    EXECUTE 'ALTER TABLE credential_usage ALTER COLUMN tenant_id SET NOT NULL';
    EXECUTE 'ALTER TABLE credential_usage ALTER COLUMN tenant_id SET DEFAULT ''00000000-0000-0000-0000-000000000001''';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_cred_usage_tenant ON credential_usage(tenant_id)';
  END IF;
END $$;

-- 4u. attestation_history (if exists)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'attestation_history') THEN
    EXECUTE 'ALTER TABLE attestation_history ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id)';
    EXECUTE 'UPDATE attestation_history SET tenant_id = ''00000000-0000-0000-0000-000000000001'' WHERE tenant_id IS NULL';
    EXECUTE 'ALTER TABLE attestation_history ALTER COLUMN tenant_id SET NOT NULL';
    EXECUTE 'ALTER TABLE attestation_history ALTER COLUMN tenant_id SET DEFAULT ''00000000-0000-0000-0000-000000000001''';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_attestation_tenant ON attestation_history(tenant_id)';
  END IF;
END $$;


-- ═══════════════════════════════════════════════════════════════════════════════
-- 5. ROW-LEVEL SECURITY (RLS) — Defense Layer 2
-- ═══════════════════════════════════════════════════════════════════════════════
--
-- RLS uses the session variable `app.tenant_id` set by the application
-- middleware on each request: SET LOCAL app.tenant_id = '<uuid>';
--
-- This means even if application code has a bug (missing WHERE clause),
-- the DB itself prevents cross-tenant data access.
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create app role for services (RLS enforced)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wid_app') THEN
    CREATE ROLE wid_app LOGIN PASSWORD 'wid_app_password';
  END IF;
END $$;

-- Grant usage
GRANT USAGE ON SCHEMA public TO wid_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO wid_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO wid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO wid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO wid_app;

-- Helper function to get current tenant from session
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
BEGIN
  RETURN NULLIF(current_setting('app.tenant_id', true), '')::UUID;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ── Enable RLS + create policies for each tenant-scoped table ──

-- Macro: For each table, enable RLS and create 4 policies (SELECT, INSERT, UPDATE, DELETE)
-- The owner (wid_user) bypasses RLS; wid_app is subject to RLS.

-- users
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_users_select ON users;
DROP POLICY IF EXISTS tenant_users_insert ON users;
DROP POLICY IF EXISTS tenant_users_update ON users;
DROP POLICY IF EXISTS tenant_users_delete ON users;
CREATE POLICY tenant_users_select ON users FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_users_insert ON users FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_users_update ON users FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_users_delete ON users FOR DELETE USING (tenant_id = current_tenant_id());

-- connectors
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_connectors_select ON connectors;
DROP POLICY IF EXISTS tenant_connectors_insert ON connectors;
DROP POLICY IF EXISTS tenant_connectors_update ON connectors;
DROP POLICY IF EXISTS tenant_connectors_delete ON connectors;
CREATE POLICY tenant_connectors_select ON connectors FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_connectors_insert ON connectors FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_connectors_update ON connectors FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_connectors_delete ON connectors FOR DELETE USING (tenant_id = current_tenant_id());

-- workloads
ALTER TABLE workloads ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_workloads_select ON workloads;
DROP POLICY IF EXISTS tenant_workloads_insert ON workloads;
DROP POLICY IF EXISTS tenant_workloads_update ON workloads;
DROP POLICY IF EXISTS tenant_workloads_delete ON workloads;
CREATE POLICY tenant_workloads_select ON workloads FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_workloads_insert ON workloads FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_workloads_update ON workloads FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_workloads_delete ON workloads FOR DELETE USING (tenant_id = current_tenant_id());

-- targets
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_targets_select ON targets;
DROP POLICY IF EXISTS tenant_targets_insert ON targets;
DROP POLICY IF EXISTS tenant_targets_update ON targets;
DROP POLICY IF EXISTS tenant_targets_delete ON targets;
CREATE POLICY tenant_targets_select ON targets FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_targets_insert ON targets FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_targets_update ON targets FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_targets_delete ON targets FOR DELETE USING (tenant_id = current_tenant_id());

-- discovery_scans
ALTER TABLE discovery_scans ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scans_select ON discovery_scans;
DROP POLICY IF EXISTS tenant_scans_insert ON discovery_scans;
DROP POLICY IF EXISTS tenant_scans_update ON discovery_scans;
DROP POLICY IF EXISTS tenant_scans_delete ON discovery_scans;
CREATE POLICY tenant_scans_select ON discovery_scans FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_scans_insert ON discovery_scans FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_scans_update ON discovery_scans FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_scans_delete ON discovery_scans FOR DELETE USING (tenant_id = current_tenant_id());

-- policies
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_policies_select ON policies;
DROP POLICY IF EXISTS tenant_policies_insert ON policies;
DROP POLICY IF EXISTS tenant_policies_update ON policies;
DROP POLICY IF EXISTS tenant_policies_delete ON policies;
CREATE POLICY tenant_policies_select ON policies FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_policies_insert ON policies FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_policies_update ON policies FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_policies_delete ON policies FOR DELETE USING (tenant_id = current_tenant_id());

-- policy_violations
ALTER TABLE policy_violations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_violations_select ON policy_violations;
DROP POLICY IF EXISTS tenant_violations_insert ON policy_violations;
DROP POLICY IF EXISTS tenant_violations_update ON policy_violations;
DROP POLICY IF EXISTS tenant_violations_delete ON policy_violations;
CREATE POLICY tenant_violations_select ON policy_violations FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_violations_insert ON policy_violations FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_violations_update ON policy_violations FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_violations_delete ON policy_violations FOR DELETE USING (tenant_id = current_tenant_id());

-- access_policies
ALTER TABLE access_policies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_access_policies_select ON access_policies;
DROP POLICY IF EXISTS tenant_access_policies_insert ON access_policies;
DROP POLICY IF EXISTS tenant_access_policies_update ON access_policies;
DROP POLICY IF EXISTS tenant_access_policies_delete ON access_policies;
CREATE POLICY tenant_access_policies_select ON access_policies FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_policies_insert ON access_policies FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_policies_update ON access_policies FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_policies_delete ON access_policies FOR DELETE USING (tenant_id = current_tenant_id());

-- access_decisions
ALTER TABLE access_decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_access_decisions_select ON access_decisions;
DROP POLICY IF EXISTS tenant_access_decisions_insert ON access_decisions;
DROP POLICY IF EXISTS tenant_access_decisions_update ON access_decisions;
DROP POLICY IF EXISTS tenant_access_decisions_delete ON access_decisions;
CREATE POLICY tenant_access_decisions_select ON access_decisions FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_decisions_insert ON access_decisions FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_decisions_update ON access_decisions FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_access_decisions_delete ON access_decisions FOR DELETE USING (tenant_id = current_tenant_id());

-- ext_authz_decisions (audit log — append-only for wid_app)
ALTER TABLE ext_authz_decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_authz_select ON ext_authz_decisions;
DROP POLICY IF EXISTS tenant_authz_insert ON ext_authz_decisions;
CREATE POLICY tenant_authz_select ON ext_authz_decisions FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_authz_insert ON ext_authz_decisions FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
-- No UPDATE/DELETE policies: audit log is append-only for app role

-- token_chain
ALTER TABLE token_chain ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_token_chain_select ON token_chain;
DROP POLICY IF EXISTS tenant_token_chain_insert ON token_chain;
DROP POLICY IF EXISTS tenant_token_chain_update ON token_chain;
DROP POLICY IF EXISTS tenant_token_chain_delete ON token_chain;
CREATE POLICY tenant_token_chain_select ON token_chain FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_token_chain_insert ON token_chain FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_token_chain_update ON token_chain FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_token_chain_delete ON token_chain FOR DELETE USING (tenant_id = current_tenant_id());

-- ai_request_events (audit log — append-only)
ALTER TABLE ai_request_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_ai_events_select ON ai_request_events;
DROP POLICY IF EXISTS tenant_ai_events_insert ON ai_request_events;
CREATE POLICY tenant_ai_events_select ON ai_request_events FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_ai_events_insert ON ai_request_events FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- identity_graph
ALTER TABLE identity_graph ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_graph_select ON identity_graph;
DROP POLICY IF EXISTS tenant_graph_insert ON identity_graph;
DROP POLICY IF EXISTS tenant_graph_update ON identity_graph;
DROP POLICY IF EXISTS tenant_graph_delete ON identity_graph;
CREATE POLICY tenant_graph_select ON identity_graph FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_graph_insert ON identity_graph FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_graph_update ON identity_graph FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_graph_delete ON identity_graph FOR DELETE USING (tenant_id = current_tenant_id());

-- remediation_intents
ALTER TABLE remediation_intents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_remediation_select ON remediation_intents;
DROP POLICY IF EXISTS tenant_remediation_insert ON remediation_intents;
DROP POLICY IF EXISTS tenant_remediation_update ON remediation_intents;
DROP POLICY IF EXISTS tenant_remediation_delete ON remediation_intents;
CREATE POLICY tenant_remediation_select ON remediation_intents FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_remediation_insert ON remediation_intents FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_remediation_update ON remediation_intents FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_remediation_delete ON remediation_intents FOR DELETE USING (tenant_id = current_tenant_id());

-- policy_snapshots (audit — append-only)
ALTER TABLE policy_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_snapshots_select ON policy_snapshots;
DROP POLICY IF EXISTS tenant_snapshots_insert ON policy_snapshots;
CREATE POLICY tenant_snapshots_select ON policy_snapshots FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_snapshots_insert ON policy_snapshots FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- mcp_tool_events (audit — append-only)
ALTER TABLE mcp_tool_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_mcp_events_select ON mcp_tool_events;
DROP POLICY IF EXISTS tenant_mcp_events_insert ON mcp_tool_events;
CREATE POLICY tenant_mcp_events_select ON mcp_tool_events FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_mcp_events_insert ON mcp_tool_events FOR INSERT WITH CHECK (tenant_id = current_tenant_id());

-- mcp_fingerprints
ALTER TABLE mcp_fingerprints ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_mcp_fp_select ON mcp_fingerprints;
DROP POLICY IF EXISTS tenant_mcp_fp_insert ON mcp_fingerprints;
DROP POLICY IF EXISTS tenant_mcp_fp_update ON mcp_fingerprints;
DROP POLICY IF EXISTS tenant_mcp_fp_delete ON mcp_fingerprints;
CREATE POLICY tenant_mcp_fp_select ON mcp_fingerprints FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_mcp_fp_insert ON mcp_fingerprints FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_mcp_fp_update ON mcp_fingerprints FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_mcp_fp_delete ON mcp_fingerprints FOR DELETE USING (tenant_id = current_tenant_id());

-- policy_templates — special: system templates (NULL tenant_id) visible to all
ALTER TABLE policy_templates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_templates_select ON policy_templates;
DROP POLICY IF EXISTS tenant_templates_insert ON policy_templates;
DROP POLICY IF EXISTS tenant_templates_update ON policy_templates;
DROP POLICY IF EXISTS tenant_templates_delete ON policy_templates;
CREATE POLICY tenant_templates_select ON policy_templates FOR SELECT
  USING (tenant_id IS NULL OR tenant_id = current_tenant_id());  -- system + own
CREATE POLICY tenant_templates_insert ON policy_templates FOR INSERT
  WITH CHECK (tenant_id = current_tenant_id());  -- can only create for own tenant
CREATE POLICY tenant_templates_update ON policy_templates FOR UPDATE
  USING (tenant_id = current_tenant_id())  -- can only update own (not system)
  WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_templates_delete ON policy_templates FOR DELETE
  USING (tenant_id = current_tenant_id());  -- can only delete own (not system)

-- tenants table — users can only see their own tenant
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_self_select ON tenants;
DROP POLICY IF EXISTS tenant_self_update ON tenants;
CREATE POLICY tenant_self_select ON tenants FOR SELECT USING (id = current_tenant_id());
CREATE POLICY tenant_self_update ON tenants FOR UPDATE USING (id = current_tenant_id()) WITH CHECK (id = current_tenant_id());
-- No INSERT/DELETE via app role — tenant creation is a system operation

-- tenant_invitations — scoped to own tenant
ALTER TABLE tenant_invitations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_invitations_select ON tenant_invitations;
DROP POLICY IF EXISTS tenant_invitations_insert ON tenant_invitations;
DROP POLICY IF EXISTS tenant_invitations_update ON tenant_invitations;
DROP POLICY IF EXISTS tenant_invitations_delete ON tenant_invitations;
CREATE POLICY tenant_invitations_select ON tenant_invitations FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY tenant_invitations_insert ON tenant_invitations FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_invitations_update ON tenant_invitations FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY tenant_invitations_delete ON tenant_invitations FOR DELETE USING (tenant_id = current_tenant_id());


-- ═══════════════════════════════════════════════════════════════════════════════
-- 6. AUDIT LOG — Tenant context on every decision
-- ═══════════════════════════════════════════════════════════════════════════════

-- Ensure audit events always record which tenant they belong to
-- (already handled by tenant_id column + RLS, but add a trigger for safety)

CREATE OR REPLACE FUNCTION set_tenant_on_insert() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.tenant_id IS NULL THEN
    NEW.tenant_id := current_tenant_id();
  END IF;
  IF NEW.tenant_id IS NULL THEN
    RAISE EXCEPTION 'tenant_id is required for table %', TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to audit tables (safety net)
DO $$
DECLARE
  t TEXT;
BEGIN
  FOR t IN SELECT unnest(ARRAY[
    'ext_authz_decisions', 'access_decisions', 'ai_request_events',
    'policy_snapshots', 'mcp_tool_events', 'policy_violations'
  ]) LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_set_tenant ON %I', t);
    EXECUTE format(
      'CREATE TRIGGER trg_set_tenant BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION set_tenant_on_insert()',
      t
    );
  END LOOP;
END $$;


-- ═══════════════════════════════════════════════════════════════════════════════
-- 7. TENANT USAGE TRACKING — For limits enforcement
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS tenant_usage (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    user_count INTEGER NOT NULL DEFAULT 0,
    workload_count INTEGER NOT NULL DEFAULT 0,
    connector_count INTEGER NOT NULL DEFAULT 0,
    policy_count INTEGER NOT NULL DEFAULT 0,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed usage for default tenant
INSERT INTO tenant_usage (tenant_id, user_count, workload_count, connector_count, policy_count)
SELECT
  '00000000-0000-0000-0000-000000000001',
  (SELECT COUNT(*) FROM users WHERE tenant_id = '00000000-0000-0000-0000-000000000001'),
  (SELECT COUNT(*) FROM workloads WHERE tenant_id = '00000000-0000-0000-0000-000000000001'),
  (SELECT COUNT(*) FROM connectors WHERE tenant_id = '00000000-0000-0000-0000-000000000001'),
  (SELECT COUNT(*) FROM policies WHERE tenant_id = '00000000-0000-0000-0000-000000000001')
ON CONFLICT (tenant_id) DO UPDATE SET
  user_count = EXCLUDED.user_count,
  workload_count = EXCLUDED.workload_count,
  connector_count = EXCLUDED.connector_count,
  policy_count = EXCLUDED.policy_count,
  last_updated = NOW();


COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════════
-- Migration 17 complete.
--
-- Next steps (application layer):
--   1. Switch from pg.Client to pg.Pool in all services
--   2. Add tenant-middleware.js (SET LOCAL app.tenant_id per request)
--   3. Add tenant_id to JWT claims
--   4. Scope in-memory caches by tenant_id
--   5. Add tenant onboarding + invitation endpoints
-- ═══════════════════════════════════════════════════════════════════════════════
