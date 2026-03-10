// =============================================================================
// Shared Categorization Logic
// Used by graph-routes.js (Step 4 enrichment) and discovery scanners
// to maintain consistent category/subcategory across all workloads.
// =============================================================================

/**
 * AI Agent Provider Detection
 */
const AI_PROVIDERS = {
  'anthropic-claude': /claude|anthropic/i,
  'openai-gpt': /gpt|openai/i,
  'google-gemini': /gemini|palm|google-ai/i,
  'meta-llama': /llama|meta-ai/i,
  'mistral-ai': /mistral/i,
  'cohere-ai': /cohere/i,
  'aws-bedrock': /bedrock/i,
  'azure-openai': /azure.*openai/i
};

/**
 * MCP Server Type Detection
 */
const MCP_TYPES = {
  'github': /github/i,
  'gitlab': /gitlab/i,
  'postgres': /postgres|postgresql/i,
  'mysql': /mysql/i,
  'sqlite': /sqlite/i,
  'filesystem': /filesystem|fs-mcp/i,
  'slack': /slack/i,
  'browser': /puppeteer|browser/i,
  'memory': /memory/i,
  'fetch': /fetch|http-mcp/i
};

/**
 * Category Detection Patterns — ordered by specificity (most specific first)
 * Keys must match what the frontend enrichment.js / Workloads.jsx expects.
 */
const CATEGORY_PATTERNS = [
  // AI & Agents — check before generic service patterns
  { category: 'AI & Agents',   subcategory: 'AI Agent',       pattern: /agent|a2a|llm|ai[-_]?worker/i },
  { category: 'AI & Agents',   subcategory: 'MCP Server',     pattern: /mcp[-_]?server|modelcontextprotocol/i },
  { category: 'AI & Agents',   subcategory: 'AI Provider',    pattern: /openai|anthropic|gemini|bedrock/i },
  // Platform services
  { category: 'Platform',      subcategory: 'Auth Service',   pattern: /auth|token[-_]?service|credential[-_]?broker|oauth/i },
  { category: 'Platform',      subcategory: 'Policy Engine',  pattern: /policy[-_]?(engine|service)|opa|rego/i },
  { category: 'Platform',      subcategory: 'Discovery Service', pattern: /discovery[-_]?service/i },
  { category: 'Platform',      subcategory: 'Credential Broker', pattern: /credential[-_]?(broker|vault|manager)/i },
  // CI/CD
  { category: 'CI/CD',         subcategory: 'Deployment',     pattern: /web[-_]?(ui|frontend|app)|deploy|cicd|pipeline/i },
  // Data
  { category: 'Data',          subcategory: 'Data Pipeline',  pattern: /data[-_]?pipeline|etl|kafka|spark|flink/i },
  { category: 'Data',          subcategory: 'Database',       pattern: /database|db|postgres|mysql|mongo|redis/i },
  { category: 'Data',          subcategory: 'Cache',          pattern: /cache|memcached/i },
  // Infrastructure
  { category: 'Infrastructure', subcategory: 'API Gateway',   pattern: /gateway|proxy|ingress|envoy|nginx/i },
  { category: 'Infrastructure', subcategory: 'Service Mesh',  pattern: /mesh|spire|spiffe|consul/i },
  { category: 'Infrastructure', subcategory: 'Monitoring',    pattern: /monitor|metrics|prometheus|grafana|datadog/i },
  // Services (External / Federated)
  { category: 'Services',      subcategory: 'Federated (acme-corp)', pattern: /acme[-_]corp|federated/i },
  { category: 'Services',      subcategory: 'Worker',         pattern: /worker|job|batch|queue|cron/i },
  // Microservice (default for generic service names)
  { category: 'Microservice',  subcategory: 'Service',        pattern: /service|api|backend|server/i },
];

/**
 * Detect category and subcategory for a workload based on its name, type, and metadata.
 * Returns { category, subcategory } — does NOT mutate the workload.
 *
 * @param {Object} workload - Workload DB row or node object
 * @returns {{ category: string, subcategory: string }}
 */
function detectCategory(workload) {
  // If already set in DB, respect it (only fill in blanks)
  if (workload.category && workload.subcategory) {
    return { category: workload.category, subcategory: workload.subcategory };
  }

  const name = (workload.name || workload.label || '').toLowerCase();
  const type = (workload.type || '').toLowerCase();
  const meta = typeof workload.metadata === 'object' ? (workload.metadata || {}) : {};

  // Type-based overrides take precedence
  if (type === 'a2a-agent' || workload.is_ai_agent) {
    return { category: 'AI & Agents', subcategory: detectAISubcategory(name, meta) };
  }
  if (type === 'mcp-server' || workload.is_mcp_server) {
    return { category: 'AI & Agents', subcategory: 'MCP Server' };
  }
  if (type === 'credential') {
    return { category: 'Credentials', subcategory: meta.credential_type || 'API Key' };
  }
  if (type === 'external-resource') {
    return { category: 'Resources', subcategory: meta.provider || 'External API' };
  }
  if (type === 'service-account') {
    return { category: 'Identity', subcategory: 'Service Account' };
  }

  // Name-pattern matching
  const existing = workload.category;
  for (const { category, subcategory, pattern } of CATEGORY_PATTERNS) {
    if (pattern.test(name)) {
      return {
        category: existing || category,
        subcategory: workload.subcategory || subcategory,
      };
    }
  }

  // Default
  return {
    category: existing || 'Microservice',
    subcategory: workload.subcategory || 'Service',
  };
}

/**
 * Detect AI subcategory from name and metadata
 */
function detectAISubcategory(name, meta) {
  for (const [id, pattern] of Object.entries(AI_PROVIDERS)) {
    if (pattern.test(name) || (meta.model && pattern.test(meta.model))) {
      return `AI Agent (${id.split('-')[0]})`;
    }
  }
  if (meta.scope_ceiling || meta.human_in_loop !== undefined) return 'Governed AI Agent';
  return 'AI Agent';
}

module.exports = {
  AI_PROVIDERS,
  MCP_TYPES,
  CATEGORY_PATTERNS,
  detectCategory,
  detectAISubcategory,
};
