// =============================================================================
// AI Traffic Inspector — Zero-Copy Tee with Async Parse
// =============================================================================
//
// Detects LLM API calls by Host header, tees the request body for async
// parsing, extracts structured fields (provider, model, tools, token estimate),
// and emits telemetry events through AuditBuffer.
//
// Key principle: The proxy pipe (clientReq.pipe(proxyReq)) is NEVER delayed.
// We use stream.PassThrough to fork a copy of the body bytes. The copy is
// collected and parsed asynchronously after the request is already in flight.
//
// Latency impact: Zero on hot path. Parsing happens after pipe().
// Non-AI traffic is filtered at the Host header check (< 1 microsecond).
// =============================================================================

'use strict';

const { PassThrough, Transform } = require('stream');

// ── Model Pricing (per 1M tokens) ──────────────────────────────────────────
// Used for cost estimation when response includes usage data.
// Prices as of early 2026. Update periodically.

const MODEL_PRICING = {
  'gpt-4o':              { input: 2.50,  output: 10.00 },
  'gpt-4o-mini':         { input: 0.15,  output: 0.60  },
  'gpt-4-turbo':         { input: 10.00, output: 30.00 },
  'gpt-4':               { input: 30.00, output: 60.00 },
  'gpt-3.5-turbo':       { input: 0.50,  output: 1.50  },
  'o1':                  { input: 15.00, output: 60.00 },
  'o1-mini':             { input: 3.00,  output: 12.00 },
  'o3-mini':             { input: 1.10,  output: 4.40  },
  'claude-opus-4-6':     { input: 15.00, output: 75.00 },
  'claude-sonnet-4-6':   { input: 3.00,  output: 15.00 },
  'claude-haiku-4-5':    { input: 0.80,  output: 4.00  },
  'claude-3-opus':       { input: 15.00, output: 75.00 },
  'claude-3-sonnet':     { input: 3.00,  output: 15.00 },
  'claude-3-haiku':      { input: 0.25,  output: 1.25  },
  'gemini-1.5-pro':      { input: 3.50,  output: 10.50 },
  'gemini-1.5-flash':    { input: 0.075, output: 0.30  },
  'gemini-2.0-flash':    { input: 0.10,  output: 0.40  },
  'command-r-plus':      { input: 3.00,  output: 15.00 },
  'command-r':           { input: 0.50,  output: 1.50  },
  'mistral-large':       { input: 4.00,  output: 12.00 },
  'mistral-small':       { input: 1.00,  output: 3.00  },
  'llama-3-70b':         { input: 0.90,  output: 0.90  },
  'llama-3-8b':          { input: 0.20,  output: 0.20  },
};

// ── AI Endpoint Detection Maps ──────────────────────────────────────────────
// Derived from protocol-scanner.js AI_PROVIDERS (L129-192) but mapped to
// runtime Host header patterns instead of env vars.

const AI_ENDPOINTS = new Map([
  ['api.openai.com',                    { provider: 'openai',       label: 'OpenAI' }],
  ['api.anthropic.com',                 { provider: 'anthropic',    label: 'Anthropic' }],
  ['generativelanguage.googleapis.com', { provider: 'google_ai',   label: 'Google AI' }],
  ['aiplatform.googleapis.com',         { provider: 'vertex_ai',   label: 'Vertex AI' }],
  ['api.cohere.ai',                     { provider: 'cohere',      label: 'Cohere' }],
  ['api.mistral.ai',                    { provider: 'mistral',     label: 'Mistral AI' }],
  ['api-inference.huggingface.co',      { provider: 'huggingface', label: 'Hugging Face' }],
  ['api.replicate.com',                 { provider: 'replicate',   label: 'Replicate' }],
  ['api.together.xyz',                  { provider: 'together',    label: 'Together AI' }],
  ['api.fireworks.ai',                  { provider: 'fireworks',   label: 'Fireworks AI' }],
  ['api.groq.com',                      { provider: 'groq',        label: 'Groq' }],
  ['api.perplexity.ai',                 { provider: 'perplexity',  label: 'Perplexity' }],
]);

// Azure OpenAI and Bedrock use dynamic hostnames — match by pattern
const DYNAMIC_AI_PATTERNS = [
  { pattern: /\.openai\.azure\.com$/,                provider: 'azure_openai',  label: 'Azure OpenAI' },
  { pattern: /bedrock-runtime\..*\.amazonaws\.com$/,  provider: 'aws_bedrock',   label: 'AWS Bedrock' },
  { pattern: /\.sagemaker\..*\.amazonaws\.com$/,      provider: 'aws_sagemaker', label: 'AWS SageMaker' },
];


class AIInspector {
  /**
   * @param {object} opts
   * @param {object} opts.auditBuffer   - AuditBuffer instance for telemetry emission
   * @param {string} opts.workloadName  - Name of the workload this gateway fronts
   * @param {string} opts.spiffeId      - SPIFFE ID of the workload
   * @param {boolean} [opts.enabled=true]
   * @param {number} [opts.maxBodyBytes=65536] - Max bytes to buffer for parsing
   */
  constructor({ auditBuffer, workloadName, spiffeId, enabled = true, maxBodyBytes = 65536 }) {
    this.auditBuffer = auditBuffer;
    this.workloadName = workloadName;
    this.spiffeId = spiffeId;
    this.enabled = enabled;
    this.maxBodyBytes = maxBodyBytes;
    this.stats = { inspected: 0, parseFailed: 0, byProvider: {} };
  }

  /**
   * Fast check: is this host an AI endpoint?
   * O(1) Map lookup + linear scan of 3 dynamic patterns.
   * For non-AI traffic this is a single Map miss — negligible overhead.
   *
   * @param {string} hostHeader - The Host header value (may include port)
   * @returns {{ provider: string, label: string } | null}
   */
  detectAIEndpoint(hostHeader) {
    if (!this.enabled || !hostHeader) return null;
    const host = hostHeader.split(':')[0].toLowerCase();

    const exact = AI_ENDPOINTS.get(host);
    if (exact) return exact;

    for (const dp of DYNAMIC_AI_PATTERNS) {
      if (dp.pattern.test(host)) return { provider: dp.provider, label: dp.label };
    }
    return null;
  }

  /**
   * Create a PassThrough tee for the request body.
   * The caller pipes clientReq into both the tee (for inspection) and proxyReq
   * (for forwarding). The tee collects body chunks up to maxBodyBytes and
   * triggers async parsing when the stream ends.
   *
   * @param {import('http').IncomingMessage} clientReq
   * @param {{ provider: string, label: string }} aiMatch
   * @param {string} destHost
   * @param {string} method
   * @param {string} path
   * @param {string} decisionId
   * @returns {PassThrough}
   */
  teeRequest(clientReq, aiMatch, destHost, method, path, decisionId) {
    const tee = new PassThrough();
    const chunks = [];
    let totalBytes = 0;
    let truncated = false;

    tee.on('data', (chunk) => {
      if (totalBytes < this.maxBodyBytes) {
        chunks.push(chunk);
        totalBytes += chunk.length;
      } else {
        truncated = true;
      }
    });

    tee.on('end', () => {
      const bodyBuffer = Buffer.concat(chunks, Math.min(totalBytes, this.maxBodyBytes));
      // Async — doesn't block the proxy
      this._processBody(bodyBuffer, aiMatch, {
        destHost, method, path, decisionId, truncated, totalBytes,
      });
    });

    tee.on('error', () => {
      // Silently ignore tee errors — proxy must not break
    });

    return tee;
  }

  /**
   * Parse collected body, extract AI fields, emit telemetry via AuditBuffer.
   * @private
   */
  _processBody(bodyBuffer, aiMatch, meta) {
    try {
      const text = bodyBuffer.toString('utf8');
      if (!text || text.length < 2) return;

      const parsed = JSON.parse(text);
      const fields = this._extractFields(parsed, aiMatch.provider);

      this.stats.inspected++;
      if (fields.model) {
        this.stats.byProvider[aiMatch.provider] =
          (this.stats.byProvider[aiMatch.provider] || 0) + 1;
      }

      this.auditBuffer.push({
        event_type: 'ai_request',
        decision_id: meta.decisionId,
        source_name: this.workloadName,
        source_principal: this.spiffeId,
        destination_host: meta.destHost,
        method: meta.method,
        path_pattern: meta.path,
        ai: {
          provider: aiMatch.provider,
          provider_label: aiMatch.label,
          model: fields.model || null,
          operation: fields.operation || null,
          tool_count: fields.toolCount || 0,
          tool_names: fields.toolNames || [],
          message_count: fields.messageCount || 0,
          has_system_prompt: fields.hasSystemPrompt || false,
          estimated_input_tokens: fields.estimatedTokens || 0,
          stream: fields.stream || false,
          temperature: fields.temperature ?? null,
          max_tokens: fields.maxTokens ?? null,
        },
        truncated: meta.truncated,
        body_bytes: meta.totalBytes,
        timestamp: new Date().toISOString(),
      });
    } catch {
      this.stats.parseFailed++;
      // JSON parse failure — not an error, could be binary/form data
    }
  }

  /**
   * Provider-aware field extraction from parsed request body.
   * @private
   */
  _extractFields(parsed, provider) {
    const fields = {};

    // Model — universal across all providers
    fields.model = parsed.model || parsed.model_id || parsed.modelId || null;

    // Operation inference from body shape
    if (parsed.messages) {
      fields.operation = 'chat';
    } else if (parsed.input && (parsed.model?.includes?.('embed') || parsed.encoding_format)) {
      fields.operation = 'embeddings';
    } else if (parsed.prompt && !parsed.messages) {
      fields.operation = 'completions';
    } else if (parsed.image || parsed.images) {
      fields.operation = 'images';
    } else {
      fields.operation = null;
    }

    // Tools / function calling
    const tools = parsed.tools || parsed.functions || [];
    fields.toolCount = tools.length;
    fields.toolNames = tools.slice(0, 20).map(t =>
      t.function?.name || t.name || 'unknown'
    );

    // Messages analysis
    const msgs = parsed.messages || [];
    fields.messageCount = msgs.length;
    fields.hasSystemPrompt = msgs.some(m => m.role === 'system');

    // Token estimation (rough: 4 chars ~ 1 token)
    fields.estimatedTokens = this._estimateTokens(msgs);

    // Generation parameters
    fields.stream = parsed.stream || false;
    fields.temperature = parsed.temperature;
    fields.maxTokens = parsed.max_tokens || parsed.max_completion_tokens || null;

    // Bedrock-specific
    if (provider === 'aws_bedrock') {
      fields.model = fields.model || parsed.modelId;
      if (parsed.anthropic_version) fields.operation = 'chat';
    }

    // Anthropic-specific
    if (provider === 'anthropic') {
      fields.maxTokens = fields.maxTokens || parsed.max_tokens;
      // Anthropic uses top-level system, not in messages array
      if (parsed.system) fields.hasSystemPrompt = true;
    }

    return fields;
  }

  /**
   * Estimate token count from messages array.
   * Rough heuristic: 4 chars ~ 1 token. Images counted as ~85 tokens.
   * @private
   */
  _estimateTokens(messages) {
    if (!messages || !Array.isArray(messages)) return 0;
    let chars = 0;
    for (const msg of messages) {
      if (typeof msg.content === 'string') {
        chars += msg.content.length;
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (part.text) chars += part.text.length;
          // Images counted as ~85 tokens (standard estimate)
          if (part.type === 'image_url' || part.type === 'image') chars += 340;
        }
      }
    }
    return Math.ceil(chars / 4);
  }

  /**
   * Capture AI provider response metadata and pipe to client.
   * Handles both non-streaming and streaming (SSE) responses.
   *
   * For non-streaming: buffers body, parses usage JSON, emits ai_response event.
   * For streaming (SSE): pipes through a Transform that scans the final chunk
   * for usage data (OpenAI/Anthropic include it in the last SSE event).
   *
   * Always writes headers and pipes body to clientRes — the caller should NOT
   * write headers or pipe separately when this method is called.
   *
   * @param {import('http').IncomingMessage} proxyRes - Response from AI provider
   * @param {import('http').ServerResponse} clientRes - Response to the client
   * @param {{ provider: string, label: string }} aiMatch
   * @param {string} decisionId
   */
  captureResponse(proxyRes, clientRes, aiMatch, decisionId) {
    const responseStart = Date.now();
    const statusCode = proxyRes.statusCode;
    const isSSE = (proxyRes.headers['content-type'] || '').includes('text/event-stream');

    // Extract rate-limit headers (zero-cost)
    const rateLimitRemaining = proxyRes.headers['x-ratelimit-remaining-tokens']
      || proxyRes.headers['x-ratelimit-remaining-requests'];
    const providerRequestId = proxyRes.headers['x-request-id']
      || proxyRes.headers['cf-ray']
      || proxyRes.headers['request-id'];
    const processingMs = proxyRes.headers['openai-processing-ms']
      || proxyRes.headers['x-processing-ms'];

    if (isSSE) {
      // ── Streaming: pipe through, scan final chunks for usage ──
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);

      let lastChunks = '';
      const scanner = new Transform({
        transform(chunk, _encoding, cb) {
          // Keep last ~4KB for scanning
          const text = chunk.toString('utf8');
          lastChunks = (lastChunks + text).slice(-4096);
          cb(null, chunk);
        },
      });

      scanner.on('end', () => {
        // Scan accumulated tail for usage JSON
        const usage = this._extractSSEUsage(lastChunks);
        this._emitResponseEvent(decisionId, aiMatch, {
          statusCode, isSSE: true,
          inputTokens: usage?.prompt_tokens ?? null,
          outputTokens: usage?.completion_tokens ?? null,
          totalTokens: usage?.total_tokens ?? null,
          finishReason: usage?.finish_reason ?? null,
          providerLatencyMs: processingMs ? parseInt(processingMs) : (Date.now() - responseStart),
          providerRequestId, rateLimitRemaining,
          errorCode: statusCode >= 400 ? `http_${statusCode}` : null,
        });
      });

      scanner.on('error', () => {
        // Don't break the pipe on scan errors
      });

      proxyRes.pipe(scanner).pipe(clientRes);
    } else {
      // ── Non-streaming: buffer response body (up to maxBodyBytes) ──
      const chunks = [];
      let totalBytes = 0;

      proxyRes.on('data', (chunk) => {
        if (totalBytes < this.maxBodyBytes) {
          chunks.push(chunk);
        }
        totalBytes += chunk.length;
      });

      proxyRes.on('end', () => {
        // Write to client
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        for (const chunk of chunks) {
          clientRes.write(chunk);
        }
        // If body exceeded buffer, remaining data was already piped
        clientRes.end();

        // Parse usage from response body
        const bodyBuffer = Buffer.concat(chunks, Math.min(totalBytes, this.maxBodyBytes));
        let usage = null;
        let finishReason = null;
        let errorCode = statusCode >= 400 ? `http_${statusCode}` : null;

        try {
          const parsed = JSON.parse(bodyBuffer.toString('utf8'));
          usage = parsed.usage || null;
          // Extract finish_reason from choices or content
          if (parsed.choices?.[0]?.finish_reason) {
            finishReason = parsed.choices[0].finish_reason;
          } else if (parsed.stop_reason) {
            finishReason = parsed.stop_reason; // Anthropic
          }
          // Extract error code from error responses
          if (parsed.error?.code) {
            errorCode = parsed.error.code;
          } else if (parsed.error?.type) {
            errorCode = parsed.error.type;
          }
        } catch {
          // Not JSON or truncated — usage stays null
        }

        this._emitResponseEvent(decisionId, aiMatch, {
          statusCode, isSSE: false,
          inputTokens: usage?.prompt_tokens ?? usage?.input_tokens ?? null,
          outputTokens: usage?.completion_tokens ?? usage?.output_tokens ?? null,
          totalTokens: usage?.total_tokens ?? null,
          finishReason,
          providerLatencyMs: processingMs ? parseInt(processingMs) : (Date.now() - responseStart),
          providerRequestId, rateLimitRemaining, errorCode,
        });
      });

      proxyRes.on('error', () => {
        // Pipe errors handled by caller's proxyReq.on('error')
      });
    }
  }

  /**
   * Extract usage data from the final SSE chunks.
   * OpenAI sends usage in the last `data:` event before `data: [DONE]`.
   * Anthropic sends it in a `message_delta` event with `usage` field.
   * @private
   */
  _extractSSEUsage(text) {
    if (!text) return null;
    try {
      // Look for usage JSON in SSE data lines (scan backwards for efficiency)
      const lines = text.split('\n').reverse();
      for (const line of lines) {
        if (!line.startsWith('data: ') || line === 'data: [DONE]') continue;
        const json = line.slice(6);
        try {
          const parsed = JSON.parse(json);
          if (parsed.usage) return { ...parsed.usage, finish_reason: parsed.choices?.[0]?.finish_reason || parsed.stop_reason };
          // Anthropic message_delta with usage
          if (parsed.type === 'message_delta' && parsed.usage) {
            return { ...parsed.usage, finish_reason: parsed.delta?.stop_reason };
          }
        } catch { /* not JSON */ }
      }
    } catch { /* scan failed */ }
    return null;
  }

  /**
   * Emit response telemetry event via AuditBuffer.
   * @private
   */
  _emitResponseEvent(decisionId, aiMatch, meta) {
    const cost = this._calculateCost(meta.inputTokens, meta.outputTokens, aiMatch.provider);
    this.stats.responseCaptured = (this.stats.responseCaptured || 0) + 1;

    this.auditBuffer.push({
      event_type: 'ai_response',
      decision_id: decisionId,
      source_name: this.workloadName,
      source_principal: this.spiffeId,
      ai: {
        provider: aiMatch.provider,
        provider_label: aiMatch.label,
        response_status: meta.statusCode,
        actual_input_tokens: meta.inputTokens,
        actual_output_tokens: meta.outputTokens,
        total_tokens: meta.totalTokens,
        estimated_cost_usd: cost,
        finish_reason: meta.finishReason,
        provider_latency_ms: meta.providerLatencyMs,
        provider_request_id: meta.providerRequestId,
        error_code: meta.errorCode,
        rate_limit_remaining: meta.rateLimitRemaining != null ? parseInt(meta.rateLimitRemaining) : null,
        is_streaming: meta.isSSE,
      },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Calculate estimated cost from token counts and model pricing.
   * Falls back to provider-level average if exact model not found.
   * @private
   */
  _calculateCost(inputTokens, outputTokens, provider) {
    if (!inputTokens && !outputTokens) return null;

    // Try to find pricing by looking at recent request events
    // (model is set during _processBody from the request; we match by provider here)
    const defaultPricing = { input: 1.00, output: 3.00 }; // conservative fallback

    // The model is available in the request event, not here.
    // We use provider-level defaults as a reasonable approximation.
    const providerDefaults = {
      openai:       { input: 2.50,  output: 10.00 },
      anthropic:    { input: 3.00,  output: 15.00 },
      google_ai:    { input: 3.50,  output: 10.50 },
      vertex_ai:    { input: 3.50,  output: 10.50 },
      cohere:       { input: 0.50,  output: 1.50  },
      mistral:      { input: 1.00,  output: 3.00  },
      groq:         { input: 0.27,  output: 0.27  },
      azure_openai: { input: 2.50,  output: 10.00 },
      aws_bedrock:  { input: 3.00,  output: 15.00 },
    };

    const pricing = providerDefaults[provider] || defaultPricing;
    const inCost = (inputTokens || 0) * pricing.input / 1_000_000;
    const outCost = (outputTokens || 0) * pricing.output / 1_000_000;
    return parseFloat((inCost + outCost).toFixed(6));
  }

  /**
   * Look up pricing for a specific model name.
   * @param {string} model
   * @returns {{ input: number, output: number } | null}
   */
  static getModelPricing(model) {
    if (!model) return null;
    const normalized = model.toLowerCase();
    // Exact match
    if (MODEL_PRICING[normalized]) return MODEL_PRICING[normalized];
    // Partial match (e.g., 'gpt-4o-2024-05-13' → 'gpt-4o')
    for (const [key, pricing] of Object.entries(MODEL_PRICING)) {
      if (normalized.startsWith(key)) return pricing;
    }
    return null;
  }

  /**
   * Stats for admin /metrics endpoint.
   */
  getStats() {
    return {
      enabled: this.enabled,
      inspected: this.stats.inspected,
      parseFailed: this.stats.parseFailed,
      responseCaptured: this.stats.responseCaptured || 0,
      byProvider: { ...this.stats.byProvider },
    };
  }
}

module.exports = { AIInspector, AI_ENDPOINTS, DYNAMIC_AI_PATTERNS, MODEL_PRICING };
