-- =============================================================================
-- Migration 18: Data Sovereignty — Region tagging for audit tables
-- =============================================================================
-- Adds data_region column to all audit tables and creates a unified view
-- for data sovereignty queries. Supports strict residency enforcement
-- where audit data must stay within designated regions.
-- =============================================================================

BEGIN;

-- ── Add data_region to ext_authz_decisions ──
ALTER TABLE ext_authz_decisions
  ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'us';

CREATE INDEX IF NOT EXISTS idx_ead_tenant_region
  ON ext_authz_decisions(tenant_id, data_region);

-- ── Add data_region to ai_request_events ──
ALTER TABLE ai_request_events
  ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'us';

CREATE INDEX IF NOT EXISTS idx_ai_req_tenant_region
  ON ai_request_events(tenant_id, data_region);

-- ── Add data_region to policy_snapshots ──
ALTER TABLE policy_snapshots
  ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'us';

CREATE INDEX IF NOT EXISTS idx_ps_tenant_region
  ON policy_snapshots(tenant_id, data_region);

-- ── Add data_region to mcp_tool_events ──
ALTER TABLE mcp_tool_events
  ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'us';

CREATE INDEX IF NOT EXISTS idx_mcp_evt_tenant_region
  ON mcp_tool_events(tenant_id, data_region);

-- ── Unified audit view for data sovereignty queries ──
CREATE OR REPLACE VIEW audit_events_by_region AS
  SELECT 'ext_authz' AS event_type, id, tenant_id, data_region, decision_id, created_at
    FROM ext_authz_decisions
  UNION ALL
  SELECT 'ai_request' AS event_type, id, tenant_id, data_region, decision_id, created_at
    FROM ai_request_events
  UNION ALL
  SELECT 'mcp_tool' AS event_type, id, tenant_id, data_region, decision_id, created_at
    FROM mcp_tool_events
  UNION ALL
  SELECT 'policy_snapshot' AS event_type, id, tenant_id, data_region, NULL AS decision_id, created_at
    FROM policy_snapshots;

COMMENT ON VIEW audit_events_by_region IS 'Unified audit view for data sovereignty — filter by tenant_id + data_region';

COMMIT;
