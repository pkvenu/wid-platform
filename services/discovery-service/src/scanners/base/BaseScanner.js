// =============================================================================
// Base Scanner - Abstract Interface for All Cloud/Platform Scanners
// =============================================================================

class BaseScanner {
  constructor(config = {}) {
    this.config = config;
    this.name = this.constructor.name;
    this.provider = 'unknown';
    this.enabled = config.enabled !== false;
  }

  // ==========================================================================
  // ABSTRACT METHODS - Must be implemented by child classes
  // ==========================================================================

  /**
   * Main discovery method - finds all workloads
   * @returns {Promise<Array>} Array of discovered workloads
   */
  async discover() {
    throw new Error(`${this.name} must implement discover()`);
  }

  /**
   * Get scanner metadata
   * @returns {Object} Scanner information
   */
  getMetadata() {
    return {
      name: this.name,
      provider: this.provider,
      version: this.version || '1.0.0',
      enabled: this.enabled,
      capabilities: this.getCapabilities()
    };
  }

  /**
   * Get scanner capabilities
   * @returns {Array<string>} List of capabilities
   */
  getCapabilities() {
    return ['discover'];
  }

  // ==========================================================================
  // OPTIONAL METHODS - Can be overridden by child classes
  // ==========================================================================

  /**
   * Validate scanner configuration
   * @returns {Promise<boolean>} True if configuration is valid
   */
  async validate() {
    return true;
  }

  /**
   * Health check for the scanner
   * @returns {Promise<Object>} Health status
   */
  async healthCheck() {
    try {
      await this.validate();
      return {
        scanner: this.name,
        status: 'healthy',
        enabled: this.enabled
      };
    } catch (error) {
      return {
        scanner: this.name,
        status: 'unhealthy',
        enabled: this.enabled,
        error: error.message
      };
    }
  }

  // ==========================================================================
  // HELPER METHODS - Available to all scanners
  // ==========================================================================

  /**
   * Categorize a workload based on tags/metadata
   */
  categorizeWorkload(tags, resource) {
    const isAI = this.isAIAgent(tags, resource);
    const isMCP = this.isMCPServer(tags, resource);

    // Dual-identity workloads get the combined category
    if (isAI && isMCP) return 'ai-agent';
    if (isAI) return 'ai-agent';
    if (isMCP) return 'mcp-server';

    const category = tags.category || tags.Category;
    if (category) return category;

    const name = this.getResourceName(resource).toLowerCase();
    if (/api|service/.test(name)) return 'microservice';
    if (/worker|job|batch/.test(name)) return 'worker';
    if (/bot/.test(name)) return 'agent';
    if (/gateway|proxy/.test(name)) return 'api-gateway';
    if (/monitor|metrics|logs/.test(name)) return 'monitoring';

    return 'unknown';
  }

  /**
   * Determine workload subcategory.
   * Returns 'mcp-ai-agent' for dual-identity workloads (both AI agent + MCP server).
   */
  determineSubcategory(tags, resource) {
    const isAI = this.isAIAgent(tags, resource);
    const isMCP = this.isMCPServer(tags, resource);

    if (isAI && isMCP) return 'mcp-ai-agent';
    if (isAI) return this.detectAIProvider(tags, resource);
    if (isMCP) return this.detectMCPType(tags, resource);

    return tags.subcategory || null;
  }

  /**
   * Detect if workload is an AI agent.
   *
   * Checks three layers:
   *   1. Static tags set at deploy time (ai-agent, a2a-agent, ai-provider)
   *   2. Runtime-detected flags from protocol scanner (is_ai_agent, a2a_detected)
   *   3. Name-based heuristics as a fallback
   */
  isAIAgent(tags, resource) {
    // --- Layer 1: Static deploy-time tags ---
    if (tags['ai-agent'] === 'true' || tags['ai_agent'] === 'true') return true;
    if (tags['a2a-agent'] === 'true' || tags['a2a_agent'] === 'true') return true;
    if (tags['ai-provider'] || tags['ai_provider']) return true;

    // --- Layer 2: Runtime detection flags (set by protocol scanner / DB) ---
    if (tags['is_ai_agent'] === 'true' || tags['is_ai_agent'] === true) return true;
    if (tags['a2a_detected'] === 'true' || tags['a2a_detected'] === true) return true;
    if (resource.is_ai_agent === true) return true;
    if (resource.a2a_detected === true) return true;
    if (resource.protocols?.a2a) return true;

    // --- Layer 3: Name-based heuristic fallback ---
    const name = this.getResourceName(resource).toLowerCase();
    const aiPatterns = /claude|gpt|gemini|llama|mistral|cohere|bedrock|anthropic|openai|ai-agent|a2a-agent/i;
    return aiPatterns.test(name);
  }

  /**
   * Detect AI provider from tags or name.
   */
  detectAIProvider(tags, resource) {
    const provider = tags['ai-provider'] || tags['ai_provider'];
    if (provider) return `${provider.toLowerCase()}-ai`;

    const name = this.getResourceName(resource).toLowerCase();

    if (/claude|anthropic/.test(name)) return 'anthropic-claude';
    if (/gpt|openai/.test(name)) return 'openai-gpt';
    if (/gemini|palm|google/.test(name)) return 'google-gemini';
    if (/llama|meta/.test(name)) return 'meta-llama';
    if (/mistral/.test(name)) return 'mistral-ai';
    if (/cohere/.test(name)) return 'cohere-ai';
    if (/bedrock/.test(name)) return 'aws-bedrock';

    return 'unknown-ai';
  }

  /**
   * Detect if workload is an MCP server.
   *
   * Checks static tags, runtime flags, and name patterns.
   */
  isMCPServer(tags, resource) {
    // Static tags
    if (tags['mcp-server'] === 'true' || tags['mcp_server'] === 'true') return true;
    if (tags['mcp-type'] || tags['mcp_type']) return true;

    // Runtime detection flags (set by protocol scanner / DB)
    if (tags['is_mcp_server'] === 'true' || tags['is_mcp_server'] === true) return true;
    if (resource.is_mcp_server === true) return true;
    if (resource.protocols?.mcp) return true;

    // Name-based fallback
    const name = this.getResourceName(resource).toLowerCase();
    return /mcp-|mcp_|mcp\./.test(name);
  }

  /**
   * Detect MCP server type
   */
  detectMCPType(tags, resource) {
    const mcpType = tags['mcp-type'] || tags['mcp_type'];
    if (mcpType) return mcpType;

    const name = this.getResourceName(resource).toLowerCase();

    if (/github/.test(name)) return 'github';
    if (/gitlab/.test(name)) return 'gitlab';
    if (/postgres|postgresql/.test(name)) return 'postgres';
    if (/mysql/.test(name)) return 'mysql';
    if (/sqlite/.test(name)) return 'sqlite';
    if (/filesystem|fs/.test(name)) return 'filesystem';
    if (/slack/.test(name)) return 'slack';
    if (/puppeteer|browser/.test(name)) return 'browser';
    if (/memory/.test(name)) return 'memory';
    if (/fetch|http/.test(name)) return 'fetch';

    return 'unknown-mcp';
  }

  // NOTE: Shadow/Zombie/Rogue classification is now centralized in
  // classifyWorkload() (discovery-service/src/index.js).
  // These methods are kept as stubs for backward compatibility with scanners
  // that still call them. The values are overridden by classifyWorkload()
  // in saveWorkload() before DB persistence.

  isShadowService() { return false; }
  calculateShadowScore() { return 0; }
  getShadowReasons() { return []; }
  calculateShadowDetails() { return { is_shadow: false, score: 0, reasons: [] }; }

  /**
   * Calculate security score
   */
  calculateSecurityScore(workload) {
    let score = 50; // Base score

    // Has owner
    if (workload.owner) score += 15;

    // Has team
    if (workload.team) score += 10;

    // Has environment tag
    if (workload.environment && workload.environment !== 'unknown') score += 10;

    // Not a shadow service
    if (!workload.is_shadow) score += 15;

    // Production environment
    if (workload.environment === 'production') score += 10;

    // Has verified identity
    if (workload.verified) score += 20;

    // High trust level
    if (workload.trust_level === 'high' || workload.trust_level === 'very-high') {
      score += 10;
    }

    return Math.min(100, score);
  }

  /**
   * Get resource name from various formats
   */
  getResourceName(resource) {
    return resource.name ||
           resource.Name ||
           resource.FunctionName ||
           resource.InstanceId ||
           resource.id ||
           'unknown';
  }

  /**
   * Parse tags from various cloud provider formats
   */
  parseTags(tags) {
    if (!tags) return {};

    // AWS format: array of {Key, Value}
    if (Array.isArray(tags)) {
      return tags.reduce((acc, tag) => {
        acc[tag.Key || tag.key] = tag.Value || tag.value;
        return acc;
      }, {});
    }

    // GCP/Azure format: object
    return tags;
  }

  /**
   * Generate SPIFFE ID
   */
  generateSpiffeId(trustDomain, provider, type, name) {
    return `spiffe://${trustDomain}/${provider}/${type}/${name}`;
  }

  /**
   * Rate-limited API call helper — prevents SDK throttling
   * @param {Function} fn - Async function to call
   * @param {number} delayMs - Delay before calling (default 200ms)
   */
  async throttledCall(fn, delayMs = 200) {
    await new Promise(r => setTimeout(r, delayMs));
    return fn();
  }

  /**
   * Pagination helper — handles AWS NextToken/Marker patterns
   * @param {Function} callFn - Async function(token) that returns a page
   * @param {string} resultKey - Key in response containing the items array
   * @param {string} tokenKey - Key in response containing the next page token
   * @param {string} requestTokenKey - Key in request for the page token
   */
  async paginateAll(callFn, resultKey, tokenKey = 'NextToken', requestTokenKey = 'NextToken') {
    const all = [];
    let token = undefined;
    do {
      const result = await callFn(token);
      all.push(...(result[resultKey] || []));
      token = result[tokenKey];
    } while (token);
    return all;
  }

  /**
   * Log discovery progress
   */
  log(message, level = 'info') {
    const prefix = {
      info: '  ℹ️ ',
      success: '  ✓',
      error: '  ✗',
      warn: '  ⚠️ '
    }[level] || '  ';

    console.log(`${prefix} ${message}`);
  }
}

module.exports = BaseScanner;