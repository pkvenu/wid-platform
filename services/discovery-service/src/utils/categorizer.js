// =============================================================================
// Shared Categorization Logic
// Used by all scanners to maintain consistency
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
 * Category Detection Patterns
 */
const CATEGORY_PATTERNS = {
  'microservice': /api|service|backend|frontend/i,
  'worker': /worker|job|batch|queue|cron/i,
  'agent': /bot|agent|automation/i,
  'api-gateway': /gateway|proxy|ingress/i,
  'monitoring': /monitor|metrics|prometheus|grafana|logs/i,
  'database': /database|db|postgres|mysql|mongo/i,
  'cache': /cache|redis|memcached/i,
  'messaging': /queue|kafka|rabbitmq|sqs|sns/i
};

module.exports = {
  AI_PROVIDERS,
  MCP_TYPES,
  CATEGORY_PATTERNS
};
