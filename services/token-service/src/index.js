// =============================================================================
// Token Service with Trust Gate - Step 1 Implementation
// Mandatory policy evaluation before ANY token issuance
// =============================================================================

const express = require('express');
const { Client } = require('pg');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { buildNHIContext, ACTIONS, AUTH_METHODS, validateCapability } = require('./canonical-nhi-context');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@postgres:5432/workload_identity';
const OPA_URL = process.env.OPA_URL || 'http://opa:8181';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

let dbClient = null;

// =============================================================================
// Database Connection
// =============================================================================

async function initDatabase() {
  try {
    dbClient = new Client({ connectionString: DATABASE_URL });
    await dbClient.connect();
    console.log('✅ Connected to database');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1);
  }
}

// =============================================================================
// Step 1: Trust Gate - Token Exchange Endpoint
// =============================================================================

app.post('/v1/token/exchange', async (req, res) => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || generateRequestId();

  try {
    // ===========================================================================
    // STEP 1: Resolve Caller Identity
    // ===========================================================================

    const callerIdentity = await resolveCallerIdentity(req);

    if (!callerIdentity) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Could not resolve caller identity',
        request_id: requestId
      });
    }

    console.log(`[${requestId}] Caller identity resolved:`, {
      spiffe_id: callerIdentity.spiffe_id,
      name: callerIdentity.name
    });

    // ===========================================================================
    // STEP 2: Load Workload from Database
    // ===========================================================================

    const workload = await loadWorkload(callerIdentity);

    if (!workload) {
      await auditDecision({
        action: 'token_exchange',
        decision: 'denied',
        reason: 'Workload not found in database',
        source_principal: callerIdentity.spiffe_id,
        request_id: requestId
      });

      return res.status(404).json({
        error: 'Not Found',
        message: 'Workload not registered in identity platform',
        caller: callerIdentity.spiffe_id || callerIdentity.name,
        request_id: requestId
      });
    }

    // ===========================================================================
    // STEP 3: Build Canonical NHI Context
    // ===========================================================================

    const { audience, capability, resource, parent_jti, scopes } = req.body;

    if (!audience) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Missing required field: audience',
        request_id: requestId
      });
    }

    const requestedCapability = capability || 'token:exchange';
    const requestedScopes = scopes || [requestedCapability];

    // Validate capability
    try {
      validateCapability(requestedCapability, workload);
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid Capability',
        message: error.message,
        request_id: requestId
      });
    }

    // Build OPA input
    const opaInput = buildNHIContext(
      workload,
      {
        action: ACTIONS.TOKEN_EXCHANGE,
        capability: requestedCapability,
        audience,
        resource,
        auth_method: determineAuthMethod(req)
      },
      {
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        request_id: requestId,
        time: new Date().toISOString()
      }
    );

    console.log(`[${requestId}] OPA input built:`, {
      workload: opaInput.nhi.name,
      capability: opaInput.request.capability,
      audience: opaInput.request.audience
    });

    // ===========================================================================
    // STEP 4: Evaluate OPA Policy (THE TRUST GATE)
    // ===========================================================================

    const policyDecision = await evaluatePolicy(opaInput, requestId);

    if (!policyDecision.allowed) {
      // HARD DENY - Policy evaluation failed
      await auditDecision({
        action: 'token_exchange',
        decision: 'denied',
        reason: policyDecision.reason || 'Policy evaluation denied',
        source_principal: workload.spiffe_id,
        source_name: workload.name,
        destination_principal: audience,
        capability: requestedCapability,
        request_id: requestId,
        duration_ms: Date.now() - startTime,
      });

      console.warn(`[${requestId}] POLICY DENIED:`, {
        workload: workload.name,
        audience,
        reason: policyDecision.reason
      });

      return res.status(403).json({
        error: 'Forbidden',
        message: 'Policy evaluation denied access',
        reason: policyDecision.reason,
        workload: workload.spiffe_id || workload.name,
        audience,
        capability: requestedCapability,
        request_id: requestId
      });
    }

    console.log(`[${requestId}] POLICY ALLOWED:`, {
      workload: workload.name,
      audience
    });

    // ===========================================================================
    // STEP 5: Issue Token + Record OBO Chain
    // ===========================================================================

    const token = await issueToken({
      subject: workload.spiffe_id || workload.name,
      audience,
      capability: requestedCapability,
      scopes: requestedScopes,
      workload,
      parent_jti: parent_jti || null,
      request_id: requestId
    });

    // ===========================================================================
    // STEP 6: Audit Success
    // ===========================================================================

    await auditDecision({
      action: 'token_exchange',
      decision: 'allowed',
      reason: 'Policy evaluation passed',
      source_principal: workload.spiffe_id,
      source_name: workload.name,
      destination_principal: audience,
      capability: requestedCapability,
      token_jti: token.jti,
      request_id: requestId,
      duration_ms: Date.now() - startTime,
    });

    // ===========================================================================
    // STEP 7: Return Token
    // ===========================================================================

    res.json({
      access_token: token.token,
      token_type: 'Bearer',
      expires_in: token.expires_in,
      scope: token.scope,
      token_jti: token.jti,
      root_jti: token.root_jti,
      chain_depth: token.chain_depth,
      capability: requestedCapability,
      policy_decision: {
        allowed: true,
        reason: policyDecision.reason
      },
      request_id: requestId
    });

  } catch (error) {
    console.error(`[${requestId}] ❌ Token exchange error:`, error);
    
    await auditLog({
      action: 'token_exchange',
      decision: 'error',
      reason: error.message,
      request_id: requestId,
      duration_ms: Date.now() - startTime
    });
    
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Token exchange failed',
      request_id: requestId
    });
  }
});

// =============================================================================
// Helper Functions
// =============================================================================

async function resolveCallerIdentity(req) {
  // Option 1: Extract from mTLS certificate
  const clientCert = req.socket.getPeerCertificate?.();
  if (clientCert && clientCert.subject) {
    const spiffeId = extractSpiffeIdFromCert(clientCert);
    if (spiffeId) {
      return { spiffe_id: spiffeId, auth_method: 'mtls' };
    }
  }
  
  // Option 2: Extract from JWT bearer token
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const claims = await verifyJWT(token);
    if (claims) {
      return { 
        spiffe_id: claims.sub,
        name: claims.name,
        auth_method: 'oidc'
      };
    }
  }
  
  // Option 3: For testing - accept explicit subject in body
  if (req.body.subject) {
    return {
      spiffe_id: req.body.subject,
      name: req.body.subject,
      auth_method: 'api_key'
    };
  }
  
  return null;
}

async function loadWorkload(identity) {
  const result = await dbClient.query(`
    SELECT 
      id, spiffe_id, name, type, namespace, environment,
      trust_domain, issuer, cluster_id, cloud_provider, region, account_id,
      category, subcategory, is_ai_agent, is_mcp_server,
      verified, security_score, status,
      labels, selectors, metadata
    FROM workloads
    WHERE spiffe_id = $1 OR name = $1
    LIMIT 1
  `, [identity.spiffe_id || identity.name]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  return result.rows[0];
}

async function evaluatePolicy(opaInput, requestId) {
  try {
    const response = await axios.post(
      `${OPA_URL}/v1/data/workload/allow`,
      { input: opaInput },
      { 
        headers: { 
          'Content-Type': 'application/json',
          'X-Request-ID': requestId
        },
        timeout: 5000 
      }
    );
    
    const allowed = response.data.result === true;
    
    let reason = 'Policy evaluation passed';
    
    if (!allowed) {
      // Try to get denial reason from OPA
      try {
        const reasonResponse = await axios.post(
          `${OPA_URL}/v1/data/workload/deny_reason`,
          { input: opaInput },
          { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
        );
        
        reason = reasonResponse.data.result || 'Policy evaluation denied';
      } catch {
        reason = 'Policy evaluation denied';
      }
    }
    
    return {
      allowed,
      reason,
      decision: response.data,
      evaluated_at: new Date().toISOString()
    };
    
  } catch (error) {
    console.error(`[${requestId}] ❌ OPA evaluation failed:`, error.message);
    
    // FAIL CLOSED: If OPA is unavailable, DENY access
    return {
      allowed: false,
      reason: `Policy evaluation error: ${error.message}`,
      error: true,
      evaluated_at: new Date().toISOString()
    };
  }
}

async function issueToken({ subject, audience, capability, scopes, workload, parent_jti, request_id }) {
  const jti = generateJTI();
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 3600; // 1 hour
  const expiresAt = new Date((now + expiresIn) * 1000);

  // Resolve OBO chain: look up parent to determine root_jti and chain_depth
  let rootJti = jti;
  let chainDepth = 0;
  let actor = null;

  if (parent_jti) {
    try {
      const parentRow = await dbClient.query(
        'SELECT root_jti, chain_depth, subject FROM token_chain WHERE jti = $1 AND revoked = FALSE AND expires_at > NOW()',
        [parent_jti]
      );
      if (parentRow.rows.length > 0) {
        const parent = parentRow.rows[0];
        rootJti = parent.root_jti;
        chainDepth = parent.chain_depth + 1;
        actor = parent.subject; // the parent's subject becomes this token's actor
      } else {
        // Parent not found or expired — treat as new root but log warning
        console.warn(`[${request_id}] OBO parent_jti ${parent_jti} not found or expired, starting new chain`);
        rootJti = jti;
        chainDepth = 0;
      }
    } catch (err) {
      console.error(`[${request_id}] Failed to resolve parent chain:`, err.message);
    }
  }

  const payload = {
    jti,
    iss: 'workload-identity-platform',
    sub: subject,
    aud: audience,
    iat: now,
    exp: now + expiresIn,
    scope: scopes || [capability],
    capability,
    // OBO chain metadata (RFC 8693 act claim)
    ...(actor ? { act: { sub: actor } } : {}),
    chain_depth: chainDepth,
    root_jti: rootJti,
    nhi: {
      type: workload.is_ai_agent ? 'ai_agent' : 'workload',
      verified: workload.verified,
      security_score: workload.security_score,
      environment: workload.environment
    },
    request_id
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256'
  });

  // Record in token_chain table for OBO tracking
  try {
    await dbClient.query(`
      INSERT INTO token_chain (
        jti, parent_jti, root_jti, chain_depth,
        subject, audience, actor, scopes,
        expires_at, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
      jti,
      parent_jti || null,
      rootJti,
      chainDepth,
      subject,
      audience,
      actor,
      JSON.stringify(scopes || [capability]),
      expiresAt,
      JSON.stringify({
        workload_name: workload.name,
        workload_type: workload.is_ai_agent ? 'ai_agent' : 'workload',
        capability,
        request_id,
      })
    ]);
  } catch (err) {
    // Non-fatal: token is still issued even if chain recording fails
    console.error(`[${request_id}] Failed to record token chain:`, err.message);
  }

  return {
    token,
    jti,
    root_jti: rootJti,
    chain_depth: chainDepth,
    expires_in: expiresIn,
    scope: scopes || [capability]
  };
}

// Write to ext_authz_decisions table — this is what the Access Events page reads
async function auditDecision(entry) {
  try {
    const decisionId = `dec_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    await dbClient.query(`
      INSERT INTO ext_authz_decisions (
        decision_id, source_principal, destination_principal,
        source_name, destination_name,
        method, path_pattern, verdict,
        adapter_mode, latency_ms,
        token_jti, root_jti, chain_depth,
        enforcement_action, enforcement_detail,
        source_type, token_context
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
    `, [
      decisionId,
      entry.source_principal || null,
      entry.destination_principal || null,
      entry.source_name || null,
      entry.destination_principal || null,
      'POST',
      '/v1/token/exchange',
      entry.decision === 'allowed' ? 'allow' : 'deny',
      'token-service',
      entry.duration_ms || 0,
      entry.token_jti || null,
      null, // root_jti set by token chain
      0,
      entry.action || 'token_exchange',
      entry.reason || null,
      'workload',
      JSON.stringify({
        capability: entry.capability,
        request_id: entry.request_id,
      })
    ]);
  } catch (error) {
    console.error('Failed to write access decision:', error.message);
  }
}

function determineAuthMethod(req) {
  const clientCert = req.socket.getPeerCertificate?.();
  if (clientCert && clientCert.subject) {
    return AUTH_METHODS.MTLS;
  }
  
  if (req.headers.authorization?.startsWith('Bearer ')) {
    return AUTH_METHODS.OIDC;
  }
  
  return AUTH_METHODS.API_KEY;
}

function generateRequestId() {
  return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function generateJTI() {
  return `jti-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function extractSpiffeIdFromCert(cert) {
  if (cert.subjectaltname) {
    const match = cert.subjectaltname.match(/URI:spiffe:\/\/[^,]+/);
    if (match) {
      return match[0].replace('URI:', '');
    }
  }
  return null;
}

async function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// =============================================================================
// Token Validation (called by edge-gateway inbound proxy)
// =============================================================================

app.post('/v1/token/validate', async (req, res) => {
  const { token_jti } = req.body;
  if (!token_jti) {
    return res.status(400).json({ valid: false, error: 'Missing token_jti' });
  }
  try {
    const result = await dbClient.query(
      'SELECT jti, subject, audience, scopes, chain_depth, revoked, expires_at FROM token_chain WHERE jti = $1',
      [token_jti]
    );
    if (result.rows.length === 0) {
      return res.json({ valid: false, reason: 'Token not found' });
    }
    const row = result.rows[0];
    if (row.revoked) {
      return res.json({ valid: false, reason: 'Token revoked' });
    }
    if (new Date(row.expires_at) < new Date()) {
      return res.json({ valid: false, reason: 'Token expired' });
    }
    return res.json({
      valid: true,
      subject: row.subject,
      audience: row.audience,
      scopes: row.scopes,
      chain_depth: row.chain_depth,
    });
  } catch (err) {
    console.error('Token validation error:', err.message);
    return res.json({ valid: false, reason: 'Validation error' });
  }
});

// =============================================================================
// Token Chain Query API (for UC4: OBO/Blended Identity visibility)
// =============================================================================

// Get full chain for a token (walk up to root)
app.get('/v1/tokens/chain/:jti', async (req, res) => {
  try {
    const result = await dbClient.query('SELECT * FROM get_token_chain($1)', [req.params.jti]);
    res.json({ chain: result.rows, total: result.rows.length });
  } catch (err) {
    console.error('Chain query error:', err.message);
    res.status(500).json({ error: 'Failed to query chain' });
  }
});

// Get all descendants of a token (walk down from root)
app.get('/v1/tokens/descendants/:jti', async (req, res) => {
  try {
    const result = await dbClient.query('SELECT * FROM get_token_descendants($1)', [req.params.jti]);
    res.json({ descendants: result.rows, total: result.rows.length });
  } catch (err) {
    console.error('Descendants query error:', err.message);
    res.status(500).json({ error: 'Failed to query descendants' });
  }
});

// Active chains summary
app.get('/v1/tokens/chains/active', async (req, res) => {
  try {
    const result = await dbClient.query('SELECT * FROM v_active_token_chains LIMIT 100');
    res.json({ chains: result.rows, total: result.rows.length });
  } catch (err) {
    console.error('Active chains query error:', err.message);
    res.status(500).json({ error: 'Failed to query active chains' });
  }
});

// Token chain stats per subject
app.get('/v1/tokens/chains/stats', async (req, res) => {
  try {
    const result = await dbClient.query('SELECT * FROM v_token_chain_stats LIMIT 100');
    res.json({ stats: result.rows });
  } catch (err) {
    console.error('Chain stats query error:', err.message);
    res.status(500).json({ error: 'Failed to query chain stats' });
  }
});

// Revoke a token and all its descendants
app.post('/v1/tokens/revoke', async (req, res) => {
  const { jti } = req.body;
  if (!jti) return res.status(400).json({ error: 'Missing jti' });
  try {
    // Revoke this token and all descendants
    const result = await dbClient.query(`
      UPDATE token_chain SET revoked = TRUE, revoked_at = NOW()
      WHERE jti IN (SELECT d.jti FROM get_token_descendants($1) d)
        AND revoked = FALSE
    `, [jti]);
    res.json({ revoked: result.rowCount, jti });
  } catch (err) {
    console.error('Revoke error:', err.message);
    res.status(500).json({ error: 'Failed to revoke tokens' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// =============================================================================
// Server Startup
// =============================================================================

(async () => {
  await initDatabase();
  
  app.listen(PORT, () => {
    console.log(`✅ Token service running on port ${PORT}`);
    console.log(`🔒 Trust gate enabled - all requests require OPA approval`);
  });
})();

module.exports = app;
