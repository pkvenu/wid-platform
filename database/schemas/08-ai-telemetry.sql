-- =============================================================================
-- 08: AI Telemetry — AI request events from edge gateway AIInspector
-- =============================================================================
-- Stores structured telemetry for LLM API calls detected by the AIInspector
-- in the edge gateway. Events arrive via the batch audit endpoint.
-- =============================================================================

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
);

CREATE INDEX IF NOT EXISTS idx_ai_req_provider ON ai_request_events(ai_provider);
CREATE INDEX IF NOT EXISTS idx_ai_req_source   ON ai_request_events(source_name);
CREATE INDEX IF NOT EXISTS idx_ai_req_created  ON ai_request_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_req_model    ON ai_request_events(ai_model);
CREATE INDEX IF NOT EXISTS idx_ai_req_decision ON ai_request_events(decision_id);

COMMENT ON TABLE ai_request_events IS 'AI/LLM API call telemetry detected by edge gateway AIInspector';

-- Response metadata columns (added for response capture)
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS response_status       INTEGER;
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS actual_input_tokens   INTEGER;
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS actual_output_tokens  INTEGER;
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS total_tokens          INTEGER;
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS estimated_cost_usd    NUMERIC(10,6);
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS finish_reason         VARCHAR(50);
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS provider_latency_ms   INTEGER;
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS provider_request_id   VARCHAR(255);
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS error_code            VARCHAR(50);
ALTER TABLE ai_request_events ADD COLUMN IF NOT EXISTS rate_limit_remaining  INTEGER;
