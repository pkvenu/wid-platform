-- ==============================================================================
-- Credential Usage Tracking - Audit Log for Proxy Access
-- ==============================================================================

CREATE TABLE IF NOT EXISTS credential_usage (
    id SERIAL PRIMARY KEY,
    
    -- Who accessed
    workload_id VARCHAR(255) NOT NULL,
    
    -- What they accessed
    target_api VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT,
    
    -- Result
    result VARCHAR(20) NOT NULL,  -- 'allowed' or 'denied'
    status_code INTEGER,
    
    -- When
    accessed_at TIMESTAMP DEFAULT NOW(),
    
    -- Additional context
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_credential_usage_workload ON credential_usage(workload_id);
CREATE INDEX IF NOT EXISTS idx_credential_usage_target ON credential_usage(target_api);
CREATE INDEX IF NOT EXISTS idx_credential_usage_time ON credential_usage(accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_usage_result ON credential_usage(result);

-- View: Proxy usage summary
CREATE OR REPLACE VIEW v_proxy_usage_summary AS
SELECT 
    workload_id,
    target_api,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE result = 'allowed') as allowed_requests,
    COUNT(*) FILTER (WHERE result = 'denied') as denied_requests,
    array_agg(DISTINCT method) as methods_used,
    MIN(accessed_at) as first_access,
    MAX(accessed_at) as last_access
FROM credential_usage
GROUP BY workload_id, target_api
ORDER BY total_requests DESC;
