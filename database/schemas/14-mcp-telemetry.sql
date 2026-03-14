-- =============================================================================
-- MCP Tool Invocation Telemetry — Runtime audit of MCP JSON-RPC traffic
-- =============================================================================
-- Captured by MCPInspector in the edge gateway data plane.
-- Zero customer data: tool argument values are redacted (keys only).
-- =============================================================================

CREATE TABLE IF NOT EXISTS mcp_tool_events (
    id                  SERIAL PRIMARY KEY,
    decision_id         VARCHAR(64),
    source_name         VARCHAR(255),
    source_principal    TEXT,
    destination_host    VARCHAR(255),
    jsonrpc_method      VARCHAR(100) NOT NULL,
    jsonrpc_id          VARCHAR(64),
    tool_name           VARCHAR(255),
    tool_arguments      JSONB DEFAULT '{}',   -- keys only, values redacted
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
