const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  detectCategory,
  detectAISubcategory,
  AI_PROVIDERS,
  MCP_TYPES,
  CATEGORY_PATTERNS,
} = require('../src/graph/categorizer');

// =============================================================================
// detectCategory()
// =============================================================================

describe('detectCategory', () => {
  it('should passthrough existing category and subcategory', () => {
    const result = detectCategory({ category: 'Custom', subcategory: 'Widget' });
    assert.deepEqual(result, { category: 'Custom', subcategory: 'Widget' });
  });

  it('should detect a2a-agent type as AI & Agents', () => {
    const result = detectCategory({ name: 'billing-bot', type: 'a2a-agent' });
    assert.equal(result.category, 'AI & Agents');
  });

  it('should detect is_ai_agent flag as AI & Agents', () => {
    const result = detectCategory({ name: 'my-service', is_ai_agent: true });
    assert.equal(result.category, 'AI & Agents');
  });

  it('should detect mcp-server type as AI & Agents / MCP Server', () => {
    const result = detectCategory({ name: 'fs-server', type: 'mcp-server' });
    assert.deepEqual(result, { category: 'AI & Agents', subcategory: 'MCP Server' });
  });

  it('should detect credential type as Credentials', () => {
    const result = detectCategory({ name: 'stripe-key', type: 'credential', metadata: { credential_type: 'API Key' } });
    assert.equal(result.category, 'Credentials');
  });

  it('should detect service-account type as Identity', () => {
    const result = detectCategory({ name: 'sa-compute', type: 'service-account' });
    assert.deepEqual(result, { category: 'Identity', subcategory: 'Service Account' });
  });

  it('should detect agent name pattern as AI & Agents', () => {
    const result = detectCategory({ name: 'code-review-agent', type: '' });
    assert.equal(result.category, 'AI & Agents');
  });

  it('should detect database name pattern as Data', () => {
    const result = detectCategory({ name: 'user-database', type: '' });
    assert.equal(result.category, 'Data');
  });

  it('should detect gateway name pattern as Infrastructure', () => {
    const result = detectCategory({ name: 'api-gateway', type: '' });
    assert.equal(result.category, 'Infrastructure');
  });

  it('should default to Microservice / Service for unknown names', () => {
    const result = detectCategory({ name: 'xyz-unknown-thing', type: '' });
    assert.deepEqual(result, { category: 'Microservice', subcategory: 'Service' });
  });

  it('should preserve existing category but fill in subcategory from pattern', () => {
    const result = detectCategory({ name: 'my-agent', category: 'Custom' });
    assert.equal(result.category, 'Custom');
    assert.equal(result.subcategory, 'AI Agent');
  });
});

// =============================================================================
// detectAISubcategory()
// =============================================================================

describe('detectAISubcategory', () => {
  it('should detect claude as anthropic', () => {
    const result = detectAISubcategory('claude-assistant', {});
    assert.equal(result, 'AI Agent (anthropic)');
  });

  it('should detect gpt as openai', () => {
    const result = detectAISubcategory('gpt-4-agent', {});
    assert.equal(result, 'AI Agent (openai)');
  });

  it('should detect gemini as google', () => {
    const result = detectAISubcategory('gemini-pro', {});
    assert.equal(result, 'AI Agent (google)');
  });

  it('should detect model in metadata', () => {
    const result = detectAISubcategory('my-agent', { model: 'claude-3-sonnet' });
    assert.equal(result, 'AI Agent (anthropic)');
  });

  it('should return Governed AI Agent when scope_ceiling present', () => {
    const result = detectAISubcategory('generic-agent', { scope_ceiling: 'read-only' });
    assert.equal(result, 'Governed AI Agent');
  });

  it('should return Governed AI Agent when human_in_loop is defined', () => {
    const result = detectAISubcategory('generic-agent', { human_in_loop: true });
    assert.equal(result, 'Governed AI Agent');
  });

  it('should return default AI Agent for unrecognized names', () => {
    const result = detectAISubcategory('custom-bot', {});
    assert.equal(result, 'AI Agent');
  });
});

// =============================================================================
// Constants
// =============================================================================

describe('AI_PROVIDERS', () => {
  it('should have 8 providers', () => {
    assert.equal(Object.keys(AI_PROVIDERS).length, 8);
  });
});

describe('MCP_TYPES', () => {
  it('should have 10 types', () => {
    assert.equal(Object.keys(MCP_TYPES).length, 10);
  });
});

describe('CATEGORY_PATTERNS', () => {
  it('should be ordered with AI & Agents first', () => {
    assert.equal(CATEGORY_PATTERNS[0].category, 'AI & Agents');
  });

  it('should end with Microservice as catch-all', () => {
    const last = CATEGORY_PATTERNS[CATEGORY_PATTERNS.length - 1];
    assert.equal(last.category, 'Microservice');
  });
});
