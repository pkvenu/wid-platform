-- ==============================================================================
-- Workload Identity Defense (WID) Platform - Database Schema
-- ==============================================================================

-- Workload Registry
CREATE TABLE workloads (
    workload_id VARCHAR(255) PRIMARY KEY,
    workload_name VARCHAR(255) NOT NULL,
    spiffe_id VARCHAR(500) UNIQUE,
    namespace VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Policy Sync Log
CREATE TABLE policy_sync_log (
    id SERIAL PRIMARY KEY,
    policy_id VARCHAR(255),
    workload_id VARCHAR(255),
    action VARCHAR(50), -- create, update, delete
    external_sync_data JSONB,
    opa_data JSONB,
    sync_method VARCHAR(50),
    synced_at TIMESTAMP DEFAULT NOW(),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);

CREATE INDEX idx_policy_sync_workload ON policy_sync_log(workload_id);
CREATE INDEX idx_policy_sync_time ON policy_sync_log(synced_at DESC);

-- Token Exchange Log
CREATE TABLE token_exchanges (
    id SERIAL PRIMARY KEY,
    subject VARCHAR(255),
    audience VARCHAR(255),
    token_jti VARCHAR(255) UNIQUE,
    parent_jti VARCHAR(255),
    chain_depth INTEGER,
    scopes JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_token_subject ON token_exchanges(subject);
CREATE INDEX idx_token_jti ON token_exchanges(token_jti);

-- Credential Usage
CREATE TABLE credential_usage (
    id SERIAL PRIMARY KEY,
    workload_id VARCHAR(255),
    target_api VARCHAR(255),
    credential_type VARCHAR(100),
    retrieved_at TIMESTAMP DEFAULT NOW(),
    used_at TIMESTAMP
);

-- Views for analytics
CREATE OR REPLACE VIEW v_policy_sync_summary AS
SELECT 
    workload_id,
    COUNT(*) as total_syncs,
    COUNT(*) FILTER (WHERE success = true) as successful_syncs,
    MAX(synced_at) as last_sync
FROM policy_sync_log
GROUP BY workload_id;
