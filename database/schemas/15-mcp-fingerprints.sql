-- =============================================================================
-- MCP Server Capability Fingerprints — Drift detection for supply-chain safety
-- =============================================================================
-- Periodic re-probe of MCP servers stores fingerprints here.
-- When fingerprint changes (tools added/removed, descriptions changed),
-- drift_detected = TRUE and drift_details contains the diff.
-- =============================================================================

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
