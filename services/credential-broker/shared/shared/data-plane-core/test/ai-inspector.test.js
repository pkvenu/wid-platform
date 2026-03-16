// =============================================================================
// AI Inspector — Test Suite
// =============================================================================

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('stream');

const { AIInspector } = require('../src/ai-inspector');

// ── Mock AuditBuffer ─────────────────────────────────────────────────────────

function createMockAuditBuffer() {
  const entries = [];
  return {
    push(entry) { entries.push(entry); },
    getEntries() { return entries; },
    flush() {},
    getStats() { return { pending: entries.length, flushed: 0, failed: 0 }; },
  };
}

// ── Helper: create a readable stream from a string ───────────────────────────

function stringToStream(str) {
  const readable = new Readable();
  readable.push(Buffer.from(str));
  readable.push(null);
  return readable;
}


// =============================================================================
// detectAIEndpoint
// =============================================================================

describe('AIInspector.detectAIEndpoint', () => {
  let inspector;

  beforeEach(() => {
    inspector = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/test-agent',
    });
  });

  it('detects OpenAI by exact host', () => {
    const match = inspector.detectAIEndpoint('api.openai.com');
    assert.deepEqual(match, { provider: 'openai', label: 'OpenAI' });
  });

  it('detects Anthropic by exact host', () => {
    const match = inspector.detectAIEndpoint('api.anthropic.com');
    assert.deepEqual(match, { provider: 'anthropic', label: 'Anthropic' });
  });

  it('detects Google AI by exact host', () => {
    const match = inspector.detectAIEndpoint('generativelanguage.googleapis.com');
    assert.deepEqual(match, { provider: 'google_ai', label: 'Google AI' });
  });

  it('detects Groq by exact host', () => {
    const match = inspector.detectAIEndpoint('api.groq.com');
    assert.deepEqual(match, { provider: 'groq', label: 'Groq' });
  });

  it('strips port before matching', () => {
    const match = inspector.detectAIEndpoint('api.openai.com:443');
    assert.deepEqual(match, { provider: 'openai', label: 'OpenAI' });
  });

  it('is case-insensitive', () => {
    const match = inspector.detectAIEndpoint('API.OpenAI.COM');
    assert.deepEqual(match, { provider: 'openai', label: 'OpenAI' });
  });

  it('detects Azure OpenAI by dynamic pattern', () => {
    const match = inspector.detectAIEndpoint('mycompany.openai.azure.com');
    assert.equal(match.provider, 'azure_openai');
    assert.equal(match.label, 'Azure OpenAI');
  });

  it('detects AWS Bedrock by dynamic pattern', () => {
    const match = inspector.detectAIEndpoint('bedrock-runtime.us-east-1.amazonaws.com');
    assert.equal(match.provider, 'aws_bedrock');
    assert.equal(match.label, 'AWS Bedrock');
  });

  it('detects AWS SageMaker by dynamic pattern', () => {
    const match = inspector.detectAIEndpoint('runtime.sagemaker.us-west-2.amazonaws.com');
    assert.equal(match.provider, 'aws_sagemaker');
    assert.equal(match.label, 'AWS SageMaker');
  });

  it('returns null for non-AI hosts', () => {
    assert.equal(inspector.detectAIEndpoint('api.stripe.com'), null);
    assert.equal(inspector.detectAIEndpoint('google.com'), null);
    assert.equal(inspector.detectAIEndpoint('internal-service:8080'), null);
  });

  it('returns null for empty/null host', () => {
    assert.equal(inspector.detectAIEndpoint(''), null);
    assert.equal(inspector.detectAIEndpoint(null), null);
    assert.equal(inspector.detectAIEndpoint(undefined), null);
  });

  it('returns null when disabled', () => {
    const disabled = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test',
      spiffeId: 'spiffe://test',
      enabled: false,
    });
    assert.equal(disabled.detectAIEndpoint('api.openai.com'), null);
  });
});


// =============================================================================
// _extractFields
// =============================================================================

describe('AIInspector._extractFields', () => {
  let inspector;

  beforeEach(() => {
    inspector = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/test-agent',
    });
  });

  it('extracts OpenAI chat completion fields', () => {
    const fields = inspector._extractFields({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: 'Hello!' },
      ],
      temperature: 0.7,
      max_tokens: 4096,
      stream: false,
    }, 'openai');

    assert.equal(fields.model, 'gpt-4o');
    assert.equal(fields.operation, 'chat');
    assert.equal(fields.messageCount, 2);
    assert.equal(fields.hasSystemPrompt, true);
    assert.equal(fields.temperature, 0.7);
    assert.equal(fields.maxTokens, 4096);
    assert.equal(fields.stream, false);
  });

  it('extracts tools / function calling', () => {
    const fields = inspector._extractFields({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Check balance' }],
      tools: [
        { function: { name: 'get_balance', description: 'Get account balance' } },
        { function: { name: 'send_payment', description: 'Send payment' } },
      ],
    }, 'openai');

    assert.equal(fields.toolCount, 2);
    assert.deepEqual(fields.toolNames, ['get_balance', 'send_payment']);
  });

  it('handles legacy functions format', () => {
    const fields = inspector._extractFields({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: 'Hello' }],
      functions: [
        { name: 'search', description: 'Search the web' },
      ],
    }, 'openai');

    assert.equal(fields.toolCount, 1);
    assert.deepEqual(fields.toolNames, ['search']);
  });

  it('extracts Anthropic-specific fields', () => {
    const fields = inspector._extractFields({
      model: 'claude-sonnet-4-20250514',
      messages: [{ role: 'user', content: 'Hello!' }],
      system: 'You are a helpful assistant.',
      max_tokens: 1024,
    }, 'anthropic');

    assert.equal(fields.model, 'claude-sonnet-4-20250514');
    assert.equal(fields.hasSystemPrompt, true);
    assert.equal(fields.maxTokens, 1024);
  });

  it('extracts Bedrock-specific fields', () => {
    const fields = inspector._extractFields({
      modelId: 'anthropic.claude-v2',
      anthropic_version: 'bedrock-2023-05-31',
      messages: [{ role: 'user', content: 'Hello' }],
      max_tokens: 512,
    }, 'aws_bedrock');

    assert.equal(fields.model, 'anthropic.claude-v2');
    assert.equal(fields.operation, 'chat');
  });

  it('detects embeddings operation', () => {
    const fields = inspector._extractFields({
      model: 'text-embedding-ada-002',
      input: 'Hello world',
      encoding_format: 'float',
    }, 'openai');

    assert.equal(fields.operation, 'embeddings');
  });

  it('detects completions operation', () => {
    const fields = inspector._extractFields({
      model: 'gpt-3.5-turbo-instruct',
      prompt: 'Say hello',
    }, 'openai');

    assert.equal(fields.operation, 'completions');
  });

  it('detects images operation', () => {
    const fields = inspector._extractFields({
      model: 'dall-e-3',
      image: 'base64...',
    }, 'openai');

    assert.equal(fields.operation, 'images');
  });

  it('handles body with no messages or tools', () => {
    const fields = inspector._extractFields({
      model: 'gpt-4o',
    }, 'openai');

    assert.equal(fields.model, 'gpt-4o');
    assert.equal(fields.toolCount, 0);
    assert.deepEqual(fields.toolNames, []);
    assert.equal(fields.messageCount, 0);
    assert.equal(fields.hasSystemPrompt, false);
  });

  it('extracts streaming flag', () => {
    const fields = inspector._extractFields({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
    }, 'openai');

    assert.equal(fields.stream, true);
  });

  it('handles max_completion_tokens (OpenAI newer format)', () => {
    const fields = inspector._extractFields({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hi' }],
      max_completion_tokens: 2048,
    }, 'openai');

    assert.equal(fields.maxTokens, 2048);
  });
});


// =============================================================================
// _estimateTokens
// =============================================================================

describe('AIInspector._estimateTokens', () => {
  let inspector;

  beforeEach(() => {
    inspector = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test-agent',
      spiffeId: 'spiffe://test',
    });
  });

  it('estimates tokens from string content', () => {
    const tokens = inspector._estimateTokens([
      { role: 'user', content: 'Hello world!' }, // 12 chars -> 3 tokens
    ]);
    assert.equal(tokens, Math.ceil(12 / 4));
  });

  it('estimates tokens from array content (multimodal)', () => {
    const tokens = inspector._estimateTokens([
      {
        role: 'user',
        content: [
          { text: 'Describe this image' },         // 19 chars
          { type: 'image_url', image_url: { url: 'data:...' } }, // 340 chars equiv
        ],
      },
    ]);
    assert.equal(tokens, Math.ceil((19 + 340) / 4));
  });

  it('returns 0 for empty messages', () => {
    assert.equal(inspector._estimateTokens([]), 0);
    assert.equal(inspector._estimateTokens(null), 0);
    assert.equal(inspector._estimateTokens(undefined), 0);
  });

  it('handles messages with no content', () => {
    assert.equal(inspector._estimateTokens([{ role: 'assistant' }]), 0);
  });

  it('counts multiple messages', () => {
    const tokens = inspector._estimateTokens([
      { role: 'system', content: 'Be helpful' },   // 10 chars
      { role: 'user', content: 'Hello' },           // 5 chars
      { role: 'assistant', content: 'Hi there!' },  // 9 chars
    ]);
    assert.equal(tokens, Math.ceil(24 / 4));
  });
});


// =============================================================================
// teeRequest + _processBody (integration)
// =============================================================================

describe('AIInspector.teeRequest', () => {
  it('collects body and emits telemetry event', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'billing-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/billing-agent',
    });

    const body = JSON.stringify({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are a billing assistant.' },
        { role: 'user', content: 'Check my balance' },
      ],
      tools: [
        { function: { name: 'get_balance' } },
        { function: { name: 'send_invoice' } },
        { function: { name: 'check_status' } },
      ],
      temperature: 0.7,
      max_tokens: 4096,
      stream: false,
    });

    const aiMatch = { provider: 'openai', label: 'OpenAI' };
    const stream = stringToStream(body);
    const tee = inspector.teeRequest(
      stream, aiMatch, 'api.openai.com', 'POST',
      '/v1/chat/completions', 'dec_test123',
    );

    // Pipe stream into tee and wait for completion
    await new Promise((resolve) => {
      stream.pipe(tee);
      tee.on('end', resolve);
    });

    // Allow async _processBody to complete
    await new Promise(r => setTimeout(r, 10));

    const entries = auditBuffer.getEntries();
    assert.equal(entries.length, 1);

    const event = entries[0];
    assert.equal(event.event_type, 'ai_request');
    assert.equal(event.decision_id, 'dec_test123');
    assert.equal(event.source_name, 'billing-agent');
    assert.equal(event.destination_host, 'api.openai.com');
    assert.equal(event.method, 'POST');
    assert.equal(event.path_pattern, '/v1/chat/completions');

    // AI-specific fields
    assert.equal(event.ai.provider, 'openai');
    assert.equal(event.ai.provider_label, 'OpenAI');
    assert.equal(event.ai.model, 'gpt-4o');
    assert.equal(event.ai.operation, 'chat');
    assert.equal(event.ai.tool_count, 3);
    assert.deepEqual(event.ai.tool_names, ['get_balance', 'send_invoice', 'check_status']);
    assert.equal(event.ai.message_count, 2);
    assert.equal(event.ai.has_system_prompt, true);
    assert.ok(event.ai.estimated_input_tokens > 0);
    assert.equal(event.ai.stream, false);
    assert.equal(event.ai.temperature, 0.7);
    assert.equal(event.ai.max_tokens, 4096);

    assert.equal(event.truncated, false);
    assert.ok(event.body_bytes > 0);
    assert.ok(event.timestamp);
  });

  it('handles non-JSON body without crashing', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'test-agent',
      spiffeId: 'spiffe://test',
    });

    const stream = stringToStream('this is not json');
    const aiMatch = { provider: 'openai', label: 'OpenAI' };
    const tee = inspector.teeRequest(
      stream, aiMatch, 'api.openai.com', 'POST', '/v1/chat/completions', 'dec_1',
    );

    await new Promise((resolve) => {
      stream.pipe(tee);
      tee.on('end', resolve);
    });
    await new Promise(r => setTimeout(r, 10));

    assert.equal(auditBuffer.getEntries().length, 0);
    assert.equal(inspector.stats.parseFailed, 1);
  });

  it('handles empty body', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'test-agent',
      spiffeId: 'spiffe://test',
    });

    const stream = stringToStream('');
    const aiMatch = { provider: 'openai', label: 'OpenAI' };
    const tee = inspector.teeRequest(
      stream, aiMatch, 'api.openai.com', 'POST', '/v1/chat/completions', 'dec_1',
    );

    await new Promise((resolve) => {
      stream.pipe(tee);
      tee.on('end', resolve);
    });
    await new Promise(r => setTimeout(r, 10));

    assert.equal(auditBuffer.getEntries().length, 0);
  });

  it('respects maxBodyBytes truncation', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'test-agent',
      spiffeId: 'spiffe://test',
      maxBodyBytes: 32, // Very small limit
    });

    // Body larger than 32 bytes — will be truncated and fail JSON parse
    const body = JSON.stringify({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'This is a long message that exceeds the limit.' }],
    });
    const stream = stringToStream(body);
    const aiMatch = { provider: 'openai', label: 'OpenAI' };
    const tee = inspector.teeRequest(
      stream, aiMatch, 'api.openai.com', 'POST', '/v1/chat/completions', 'dec_1',
    );

    await new Promise((resolve) => {
      stream.pipe(tee);
      tee.on('end', resolve);
    });
    await new Promise(r => setTimeout(r, 10));

    // Truncated JSON won't parse — parseFailed increments
    assert.equal(inspector.stats.parseFailed, 1);
  });
});


// =============================================================================
// getStats
// =============================================================================

describe('AIInspector.getStats', () => {
  it('returns initial stats', () => {
    const inspector = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test',
      spiffeId: 'spiffe://test',
    });

    const stats = inspector.getStats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.inspected, 0);
    assert.equal(stats.parseFailed, 0);
    assert.deepEqual(stats.byProvider, {});
  });

  it('tracks inspected count and provider breakdown', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'test',
      spiffeId: 'spiffe://test',
    });

    // Simulate two processed bodies
    inspector._processBody(
      Buffer.from(JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] })),
      { provider: 'openai', label: 'OpenAI' },
      { destHost: 'api.openai.com', method: 'POST', path: '/v1/chat/completions', decisionId: 'dec_1', truncated: false, totalBytes: 50 },
    );

    inspector._processBody(
      Buffer.from(JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'hi' }] })),
      { provider: 'anthropic', label: 'Anthropic' },
      { destHost: 'api.anthropic.com', method: 'POST', path: '/v1/messages', decisionId: 'dec_2', truncated: false, totalBytes: 60 },
    );

    const stats = inspector.getStats();
    assert.equal(stats.inspected, 2);
    assert.equal(stats.byProvider.openai, 1);
    assert.equal(stats.byProvider.anthropic, 1);
  });

  it('returns a copy of byProvider (not a reference)', () => {
    const inspector = new AIInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test',
      spiffeId: 'spiffe://test',
    });

    const stats1 = inspector.getStats();
    stats1.byProvider.openai = 999;

    const stats2 = inspector.getStats();
    assert.equal(stats2.byProvider.openai, undefined);
  });
});


// =============================================================================
// Telemetry Event Schema Validation
// =============================================================================

describe('Telemetry event schema', () => {
  it('emitted event has all required fields', async () => {
    const auditBuffer = createMockAuditBuffer();
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'billing-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/billing-agent',
    });

    inspector._processBody(
      Buffer.from(JSON.stringify({
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: 'You are helpful.' },
          { role: 'user', content: 'Hello' },
        ],
        tools: [{ function: { name: 'search' } }],
        temperature: 0.5,
        max_tokens: 2048,
        stream: true,
      })),
      { provider: 'openai', label: 'OpenAI' },
      {
        destHost: 'api.openai.com',
        method: 'POST',
        path: '/v1/chat/completions',
        decisionId: 'dec_abc123',
        truncated: false,
        totalBytes: 200,
      },
    );

    const event = auditBuffer.getEntries()[0];

    // Top-level fields
    assert.equal(event.event_type, 'ai_request');
    assert.equal(typeof event.decision_id, 'string');
    assert.equal(typeof event.source_name, 'string');
    assert.equal(typeof event.source_principal, 'string');
    assert.equal(typeof event.destination_host, 'string');
    assert.equal(typeof event.method, 'string');
    assert.equal(typeof event.path_pattern, 'string');
    assert.equal(typeof event.truncated, 'boolean');
    assert.equal(typeof event.body_bytes, 'number');
    assert.equal(typeof event.timestamp, 'string');

    // AI sub-object
    assert.equal(typeof event.ai, 'object');
    assert.equal(typeof event.ai.provider, 'string');
    assert.equal(typeof event.ai.provider_label, 'string');
    assert.equal(typeof event.ai.model, 'string');
    assert.equal(typeof event.ai.operation, 'string');
    assert.equal(typeof event.ai.tool_count, 'number');
    assert.ok(Array.isArray(event.ai.tool_names));
    assert.equal(typeof event.ai.message_count, 'number');
    assert.equal(typeof event.ai.has_system_prompt, 'boolean');
    assert.equal(typeof event.ai.estimated_input_tokens, 'number');
    assert.equal(typeof event.ai.stream, 'boolean');
    // temperature and max_tokens can be number or null
    assert.ok(event.ai.temperature === null || typeof event.ai.temperature === 'number');
    assert.ok(event.ai.max_tokens === null || typeof event.ai.max_tokens === 'number');
  });
});
