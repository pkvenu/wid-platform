-- ==============================================================================
-- Token Chain Tracking - Complete OBO (On-Behalf-Of) Support
-- ==============================================================================

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
    issued_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    metadata JSONB,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_chain_jti ON token_chain(jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_parent ON token_chain(parent_jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_root ON token_chain(root_jti);
CREATE INDEX IF NOT EXISTS idx_token_chain_subject ON token_chain(subject);
CREATE INDEX IF NOT EXISTS idx_token_chain_actor ON token_chain(actor);

-- Get full token chain recursively
CREATE OR REPLACE FUNCTION get_token_chain(token_jti VARCHAR)
RETURNS TABLE (
    depth INTEGER,
    jti VARCHAR,
    subject VARCHAR,
    audience VARCHAR,
    actor VARCHAR,
    issued_at TIMESTAMP,
    expires_at TIMESTAMP,
    scopes JSONB
) AS $$
    WITH RECURSIVE chain AS (
        SELECT 
            0 as depth,
            t.jti,
            t.subject,
            t.audience,
            t.actor,
            t.issued_at,
            t.expires_at,
            t.scopes,
            t.parent_jti
        FROM token_chain t
        WHERE t.jti = token_jti
        
        UNION ALL
        
        SELECT 
            c.depth + 1,
            t.jti,
            t.subject,
            t.audience,
            t.actor,
            t.issued_at,
            t.expires_at,
            t.scopes,
            t.parent_jti
        FROM token_chain t
        JOIN chain c ON t.jti = c.parent_jti
    )
    SELECT depth, jti, subject, audience, actor, issued_at, expires_at, scopes
    FROM chain
    ORDER BY depth DESC;
$$ LANGUAGE sql;

-- Get token descendants
CREATE OR REPLACE FUNCTION get_token_descendants(token_jti VARCHAR)
RETURNS TABLE (
    depth INTEGER,
    jti VARCHAR,
    subject VARCHAR,
    audience VARCHAR,
    issued_at TIMESTAMP
) AS $$
    WITH RECURSIVE descendants AS (
        SELECT 
            0 as depth,
            t.jti,
            t.subject,
            t.audience,
            t.issued_at
        FROM token_chain t
        WHERE t.jti = token_jti
        
        UNION ALL
        
        SELECT 
            d.depth + 1,
            t.jti,
            t.subject,
            t.audience,
            t.issued_at
        FROM token_chain t
        JOIN descendants d ON t.parent_jti = d.jti
    )
    SELECT depth, jti, subject, audience, issued_at
    FROM descendants
    ORDER BY depth ASC;
$$ LANGUAGE sql;

-- Active chains view
CREATE OR REPLACE VIEW v_active_token_chains AS
SELECT 
    root_jti,
    actor,
    COUNT(*) as chain_length,
    MAX(chain_depth) as max_depth,
    MIN(issued_at) as chain_started,
    MAX(expires_at) as chain_expires,
    array_agg(DISTINCT subject) as subjects_in_chain
FROM token_chain
WHERE expires_at > NOW() AND revoked = FALSE
GROUP BY root_jti, actor
ORDER BY chain_started DESC;

-- Statistics view
CREATE OR REPLACE VIEW v_token_chain_stats AS
SELECT 
    subject,
    COUNT(DISTINCT jti) as total_tokens_issued,
    COUNT(DISTINCT root_jti) as unique_chains,
    AVG(chain_depth) as avg_chain_depth,
    MAX(chain_depth) as max_chain_depth,
    COUNT(*) FILTER (WHERE chain_depth = 0) as root_tokens,
    COUNT(*) FILTER (WHERE chain_depth > 0) as delegated_tokens
FROM token_chain
GROUP BY subject
ORDER BY total_tokens_issued DESC;
