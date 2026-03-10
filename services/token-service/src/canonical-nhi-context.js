// =============================================================================
// Canonical NHI Context - Step 0 Complete Implementation
// Implements the exact specification for OPA input contract
// =============================================================================

/**
 * Canonical NHI Context Object
 * This is the SINGLE source of truth for all authorization decisions
 */

// =============================================================================
// NHI Type Enumeration
// =============================================================================

const NHI_TYPES = {
  WORKLOAD: 'workload',           // Standard microservice/container
  AGENT: 'agent',                 // Generic agent
  AI_AGENT: 'ai_agent',           // AI/LLM agent
  INTEGRATION: 'integration',     // Third-party integration
  INFRA_IDENTITY: 'infra_identity' // Infrastructure component
};

// =============================================================================
// Action Enumeration
// =============================================================================

const ACTIONS = {
  TOKEN_EXCHANGE: 'token_exchange',
  TOKEN_ISSUE: 'token_issue',
  CREDENTIAL_ISSUE: 'credential_issue',
  SECRET_READ: 'secret_read',
  API_INVOKE: 'api_invoke'
};

// =============================================================================
// Capability Taxonomy (Complete as per spec)
// =============================================================================

const CAPABILITIES = {
  // Token operations
  'token:exchange': {
    description: 'Exchange one token for another (RFC 8693)',
    actions: ['token_exchange'],
    risk_level: 'medium'
  },
  'token:issue': {
    description: 'Issue new tokens',
    actions: ['token_issue'],
    risk_level: 'high',
    requires_elevated: true
  },

  // Credential operations
  'credential:issue:aws': {
    description: 'Issue AWS temporary credentials',
    actions: ['credential_issue'],
    provider: 'aws',
    risk_level: 'high'
  },
  'credential:issue:gcp': {
    description: 'Issue GCP access tokens',
    actions: ['credential_issue'],
    provider: 'gcp',
    risk_level: 'high'
  },
  'credential:issue:azure': {
    description: 'Issue Azure tokens',
    actions: ['credential_issue'],
    provider: 'azure',
    risk_level: 'high'
  },
  'credential:issue:vault': {
    description: 'Issue Vault tokens/secrets',
    actions: ['credential_issue'],
    provider: 'vault',
    risk_level: 'high'
  },

  // Secret operations
  'secret:read': {
    description: 'Read secrets from secret stores',
    actions: ['secret_read'],
    risk_level: 'medium'
  },
  'secret:write': {
    description: 'Write secrets to secret stores',
    actions: ['secret_write'],
    risk_level: 'high'
  },

  // API operations
  'api:invoke': {
    description: 'Invoke API endpoints',
    actions: ['api_invoke'],
    risk_level: 'low'
  },

  // AI-specific capabilities
  'model:invoke': {
    description: 'Invoke AI models',
    actions: ['api_invoke'],
    requires_ai_agent: true,
    risk_level: 'medium'
  },
  'model:train': {
    description: 'Train or fine-tune models',
    actions: ['api_invoke'],
    requires_ai_agent: true,
    risk_level: 'high'
  },

  // MCP-specific capabilities
  'mcp:connect': {
    description: 'Connect to MCP servers',
    actions: ['api_invoke'],
    requires_mcp_server: true,
    risk_level: 'low'
  },
  'mcp:query': {
    description: 'Query MCP resources',
    actions: ['api_invoke'],
    requires_mcp_server: true,
    risk_level: 'low'
  },
  'mcp:execute': {
    description: 'Execute via MCP',
    actions: ['api_invoke'],
    requires_mcp_server: true,
    risk_level: 'high'
  }
};

// =============================================================================
// Auth Method Enumeration
// =============================================================================

const AUTH_METHODS = {
  MTLS: 'mtls',
  OIDC: 'oidc',
  API_KEY: 'api_key',
  SPIFFE_SVID: 'spiffe_svid',
  IAM_ROLE: 'iam_role'
};

// =============================================================================
// Canonical NHI Context Builder
// =============================================================================

/**
 * Build canonical NHI context from workload database record
 * This is the SINGLE function that creates the OPA input
 */
function buildNHIContext(workload, request, context = {}) {
  // Validate required fields
  if (!workload) {
    throw new Error('Workload is required');
  }

  if (!request || !request.action) {
    throw new Error('Request action is required');
  }

  // Determine NHI type
  const nhiType = determineNHIType(workload);

  // Build canonical NHI object
  const nhi = {
    // Core identity
    id: workload.id,
    type: nhiType,
    name: workload.name,
    namespace: workload.namespace,
    environment: workload.environment,
    
    // SPIFFE identity
    spiffe_id: workload.spiffe_id || null,
    trust_domain: workload.trust_domain || extractTrustDomain(workload.spiffe_id),
    issuer: workload.issuer || 'unknown',
    
    // Attributes
    labels: workload.labels || {},
    selectors: workload.selectors || {},
    
    // State
    verified: workload.verified || false,
    security_score: workload.security_score || 0,
    
    // Type-specific flags
    is_ai_agent: workload.is_ai_agent || false,
    is_mcp_server: workload.is_mcp_server || false,
    
    // Cloud provider context
    cloud_provider: workload.cloud_provider || null,
    region: workload.region || null,
    account_id: workload.account_id || null
  };

  // Build canonical request object
  const requestContext = {
    action: request.action,
    capability: request.capability,
    audience: request.audience || null,
    resource: request.resource || null,
    auth_method: request.auth_method || 'api_key',
    time: context.time || new Date().toISOString(),
    ip: context.ip_address || null,
    network: context.network || null,
    request_id: context.request_id || null,
    user_agent: context.user_agent || null
  };

  // Build complete OPA input
  const opaInput = {
    nhi,
    request: requestContext
  };

  return opaInput;
}

/**
 * Determine NHI type from workload attributes
 */
function determineNHIType(workload) {
  if (workload.is_ai_agent) {
    return NHI_TYPES.AI_AGENT;
  }
  
  if (workload.is_mcp_server) {
    return NHI_TYPES.AGENT;
  }
  
  if (workload.category === 'integration') {
    return NHI_TYPES.INTEGRATION;
  }
  
  if (workload.type?.includes('infra') || 
      workload.category === 'infrastructure') {
    return NHI_TYPES.INFRA_IDENTITY;
  }
  
  return NHI_TYPES.WORKLOAD;
}

/**
 * Extract trust domain from SPIFFE ID
 */
function extractTrustDomain(spiffeId) {
  if (!spiffeId || !spiffeId.startsWith('spiffe://')) {
    return null;
  }
  
  const parts = spiffeId.replace('spiffe://', '').split('/');
  return parts[0];
}

/**
 * Validate capability exists and is allowed for workload type
 */
function validateCapability(capability, nhi) {
  const cap = CAPABILITIES[capability];
  
  if (!cap) {
    throw new Error(`Unknown capability: ${capability}`);
  }
  
  // Check AI agent requirement
  if (cap.requires_ai_agent && !nhi.is_ai_agent) {
    throw new Error(`Capability ${capability} requires AI agent`);
  }
  
  // Check MCP server requirement
  if (cap.requires_mcp_server && !nhi.is_mcp_server) {
    throw new Error(`Capability ${capability} requires MCP server`);
  }
  
  // Check elevated requirement
  if (cap.requires_elevated && nhi.security_score < 90) {
    throw new Error(`Capability ${capability} requires security score >= 90`);
  }
  
  return cap;
}

/**
 * Resolve action from capability
 */
function resolveActionFromCapability(capability) {
  const cap = CAPABILITIES[capability];
  
  if (!cap) {
    throw new Error(`Unknown capability: ${capability}`);
  }
  
  return cap.actions[0];
}

// =============================================================================
// Exports
// =============================================================================

module.exports = {
  // Types
  NHI_TYPES,
  ACTIONS,
  CAPABILITIES,
  AUTH_METHODS,
  
  // Core functions
  buildNHIContext,
  validateCapability,
  resolveActionFromCapability,
  
  // Utilities
  determineNHIType,
  extractTrustDomain
};
