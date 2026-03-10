-- =============================================================================
-- Discovery Service Schema
-- Stores auto-discovered workloads and targets
-- Version: 1.0.0
-- =============================================================================

-- Workloads table - All discovered NHI (Non-Human Identities)
CREATE TABLE IF NOT EXISTS workloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity
    spiffe_id VARCHAR(512) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- kubernetes-deployment, kubernetes-statefulset, docker-container, etc.
    
    -- Location
    namespace VARCHAR(255),
    environment VARCHAR(50), -- production, staging, development
    
    -- Discovery metadata
    discovered_at TIMESTAMP DEFAULT NOW(),
    discovered_by VARCHAR(100), -- kubernetes, docker, manual
    last_seen TIMESTAMP DEFAULT NOW(),
    
    -- Verification
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    security_score INTEGER,
    
    -- Status
    status VARCHAR(50) DEFAULT 'pending', -- pending, active, inactive
    
    -- Metadata (stored as JSONB for flexibility)
    labels JSONB DEFAULT '{}'::jsonb,
    selectors JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Targets table - External services and APIs
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spiffe_id VARCHAR(512),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL, -- external-api, database, internal-service
    endpoint VARCHAR(512),
    discovered_at TIMESTAMP DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE,
    category VARCHAR(100), -- payment, database, ai, storage, version-control
    provider VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Discovery scans table - Track scan history and performance
CREATE TABLE IF NOT EXISTS discovery_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type VARCHAR(50) NOT NULL, -- kubernetes, docker, manual, full
    status VARCHAR(50) NOT NULL, -- running, completed, failed
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    workloads_discovered INTEGER DEFAULT 0,
    errors TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Workloads indexes
CREATE INDEX IF NOT EXISTS idx_workloads_spiffe_id ON workloads(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_workloads_status ON workloads(status);
CREATE INDEX IF NOT EXISTS idx_workloads_verified ON workloads(verified);
CREATE INDEX IF NOT EXISTS idx_workloads_namespace ON workloads(namespace);
CREATE INDEX IF NOT EXISTS idx_workloads_environment ON workloads(environment);
CREATE INDEX IF NOT EXISTS idx_workloads_last_seen ON workloads(last_seen);
CREATE INDEX IF NOT EXISTS idx_workloads_type ON workloads(type);

-- Targets indexes
CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name);
CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type);
CREATE INDEX IF NOT EXISTS idx_targets_verified ON targets(verified);

-- Discovery scans indexes
CREATE INDEX IF NOT EXISTS idx_discovery_scans_status ON discovery_scans(status);
CREATE INDEX IF NOT EXISTS idx_discovery_scans_started ON discovery_scans(started_at);

-- =============================================================================
-- Triggers
-- =============================================================================

-- Auto-update updated_at timestamp on workloads
CREATE OR REPLACE FUNCTION update_workload_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_workload_updated_at 
    BEFORE UPDATE ON workloads
    FOR EACH ROW 
    EXECUTE FUNCTION update_workload_updated_at();

-- =============================================================================
-- Seed Data - Common External Targets
-- =============================================================================

INSERT INTO targets (name, type, endpoint, category, provider, verified, metadata) VALUES
('github', 'external-api', 'https://api.github.com', 'version-control', 'GitHub', true, '{"description": "GitHub API", "docs": "https://docs.github.com/rest"}'::jsonb),
('stripe', 'external-api', 'https://api.stripe.com', 'payment', 'Stripe', true, '{"description": "Stripe Payment API", "docs": "https://stripe.com/docs/api"}'::jsonb),
('openai', 'external-api', 'https://api.openai.com', 'ai', 'OpenAI', true, '{"description": "OpenAI API", "docs": "https://platform.openai.com/docs"}'::jsonb),
('anthropic', 'external-api', 'https://api.anthropic.com', 'ai', 'Anthropic', true, '{"description": "Anthropic Claude API", "docs": "https://docs.anthropic.com"}'::jsonb),
('snowflake', 'external-api', 'https://snowflake.com', 'database', 'Snowflake', true, '{"description": "Snowflake Data Cloud"}'::jsonb),
('aws-s3', 'external-api', 'https://s3.amazonaws.com', 'storage', 'AWS', true, '{"description": "AWS S3 Object Storage"}'::jsonb),
('database', 'internal-service', 'postgres://localhost:5432', 'database', 'PostgreSQL', true, '{"description": "Internal PostgreSQL Database"}'::jsonb),
('redis', 'internal-service', 'redis://localhost:6379', 'cache', 'Redis', true, '{"description": "Internal Redis Cache"}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to get workload statistics
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
        COUNT(*)::BIGINT as total_workloads,
        COUNT(*) FILTER (WHERE verified = true)::BIGINT as verified_workloads,
        COUNT(*) FILTER (WHERE status = 'pending')::BIGINT as pending_workloads,
        COUNT(*) FILTER (WHERE status = 'active')::BIGINT as active_workloads,
        COUNT(*) FILTER (WHERE type LIKE 'kubernetes-%')::BIGINT as kubernetes_workloads,
        COUNT(*) FILTER (WHERE type = 'docker-container')::BIGINT as docker_workloads,
        ROUND(AVG(security_score), 2) as avg_security_score
    FROM workloads;
END;
$$ LANGUAGE plpgsql;

-- Function to get recent discovery scans
CREATE OR REPLACE FUNCTION get_recent_scans(limit_count INTEGER DEFAULT 10)
RETURNS TABLE(
    id UUID,
    scan_type VARCHAR,
    status VARCHAR,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    workloads_discovered INTEGER,
    duration_seconds NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ds.id,
        ds.scan_type,
        ds.status,
        ds.started_at,
        ds.completed_at,
        ds.workloads_discovered,
        EXTRACT(EPOCH FROM (ds.completed_at - ds.started_at))::NUMERIC as duration_seconds
    FROM discovery_scans ds
    ORDER BY ds.started_at DESC
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old inactive workloads
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

-- =============================================================================
-- Views for Common Queries
-- =============================================================================

-- View for active verified workloads (used in PolicyBuilderV2)
CREATE OR REPLACE VIEW active_workloads AS
SELECT 
    id,
    spiffe_id,
    name,
    type,
    namespace,
    environment,
    security_score,
    labels,
    metadata
FROM workloads
WHERE verified = true 
AND status = 'active'
ORDER BY name;

-- View for pending verification workloads
CREATE OR REPLACE VIEW pending_workloads AS
SELECT 
    id,
    spiffe_id,
    name,
    type,
    namespace,
    environment,
    discovered_at,
    last_seen,
    security_score
FROM workloads
WHERE status = 'pending'
ORDER BY discovered_at DESC;

-- View for workload discovery summary
CREATE OR REPLACE VIEW workload_summary AS
SELECT 
    environment,
    type,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE verified = true) as verified_count,
    ROUND(AVG(security_score), 2) as avg_security_score
FROM workloads
GROUP BY environment, type
ORDER BY environment, type;

-- =============================================================================
-- Comments for Documentation
-- =============================================================================

COMMENT ON TABLE workloads IS 'Stores all discovered non-human identities (workloads)';
COMMENT ON COLUMN workloads.spiffe_id IS 'Unique SPIFFE ID in format: spiffe://trust-domain/namespace/name';
COMMENT ON COLUMN workloads.security_score IS 'Calculated security score from 0-100 based on best practices';
COMMENT ON COLUMN workloads.labels IS 'Kubernetes labels or Docker labels as JSONB';
COMMENT ON COLUMN workloads.selectors IS 'SPIRE selectors used for workload attestation';

COMMENT ON TABLE targets IS 'Stores external services and APIs that workloads can access';
COMMENT ON TABLE discovery_scans IS 'Tracks discovery scan history and performance';

COMMENT ON FUNCTION get_workload_stats() IS 'Returns aggregate statistics about discovered workloads';
COMMENT ON FUNCTION get_recent_scans(INTEGER) IS 'Returns recent discovery scans with duration';
COMMENT ON FUNCTION cleanup_stale_workloads(INTEGER) IS 'Removes old inactive unverified workloads';

-- =============================================================================
-- Verification Queries
-- =============================================================================

-- Verify tables were created
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'workloads') THEN
        RAISE EXCEPTION 'workloads table was not created';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'targets') THEN
        RAISE EXCEPTION 'targets table was not created';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'discovery_scans') THEN
        RAISE EXCEPTION 'discovery_scans table was not created';
    END IF;
    
    RAISE NOTICE 'All discovery tables created successfully!';
END $$;

-- Show summary
SELECT 
    'Workloads' as table_name, 
    COUNT(*) as record_count 
FROM workloads
UNION ALL
SELECT 
    'Targets' as table_name, 
    COUNT(*) as record_count 
FROM targets
UNION ALL
SELECT 
    'Discovery Scans' as table_name, 
    COUNT(*) as record_count 
FROM discovery_scans;