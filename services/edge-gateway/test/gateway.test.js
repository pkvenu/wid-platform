// =============================================================================
// Edge Gateway — Test Suite
// =============================================================================
// Shared classes (PolicyCache, CircuitBreaker, sanitization, etc.) are tested
// in shared/data-plane-core/test/core.test.js (72 tests).
//
// This file tests GATEWAY-SPECIFIC logic:
//   1. CONFIG defaults and structure
//   2. isPlatformTraffic, resolveMode, resolveFailBehavior
//   3. Outbound proxy integration (mock policy + token + backend)
//   4. Shared core smoke tests (verify imports work)
// =============================================================================

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

// Shared core
const {
  PolicyCache, CredentialBuffer, CircuitBreaker,
  MetricsCollector, AuditBuffer, AIInspector,
  sanitizeHeaders, sanitizePath, extractWorkloadName, buildAuditEntry,
  generateIptablesScript, setLogLevel,
} = require('@wid/core');

// Gateway-specific
const {
  CONFIG, isPlatformTraffic, resolveMode, resolveFailBehavior,
} = require('../src/gateway.js');

setLogLevel('error'); // quiet during tests


// =============================================================================
// Gateway-Specific Tests
// =============================================================================

describe('CONFIG', () => {
  it('has required fields', () => {
    assert.ok(CONFIG.outboundPort);
    assert.ok(CONFIG.inboundPort);
    assert.ok(CONFIG.adminPort);
    assert.ok(CONFIG.appPort);
    assert.ok(CONFIG.policyServiceUrl);
    assert.ok(CONFIG.tokenServiceUrl);
    assert.ok(CONFIG.defaultMode);
    assert.ok(CONFIG.failBehavior);
    assert.ok(Array.isArray(CONFIG.platformPorts));
    assert.ok(Array.isArray(CONFIG.platformHosts));
  });

  it('defaults to audit mode', () => {
    assert.equal(CONFIG.defaultMode, 'audit');
  });

  it('defaults to fail-open', () => {
    assert.equal(CONFIG.failBehavior, 'open');
  });
});

describe('isPlatformTraffic', () => {
  it('bypasses platform ports', () => {
    assert.equal(isPlatformTraffic('anything', 3001), true);
    assert.equal(isPlatformTraffic('anything', 8200), true);
    assert.equal(isPlatformTraffic('anything', 8181), true);
  });

  it('bypasses localhost', () => {
    assert.equal(isPlatformTraffic('localhost', 9999), true);
    assert.equal(isPlatformTraffic('127.0.0.1', 9999), true);
  });

  it('bypasses platform hosts', () => {
    assert.equal(isPlatformTraffic('policy-engine', 9999), true);
    assert.equal(isPlatformTraffic('token-service', 9999), true);
    assert.equal(isPlatformTraffic('vault', 9999), true);
  });

  it('allows non-platform traffic', () => {
    assert.equal(isPlatformTraffic('api.stripe.com', 443), false);
    assert.equal(isPlatformTraffic('external-api', 8080), false);
  });
});

describe('resolveMode', () => {
  it('returns default mode when no override', () => {
    const originalMode = CONFIG.defaultMode;
    CONFIG.defaultMode = 'audit';
    assert.equal(resolveMode('test-workload'), 'audit');
    CONFIG.defaultMode = originalMode;
  });
});

describe('resolveFailBehavior', () => {
  it('returns default fail behavior when no override', () => {
    const originalFail = CONFIG.failBehavior;
    CONFIG.failBehavior = 'open';
    assert.equal(resolveFailBehavior('test-workload'), 'open');
    CONFIG.failBehavior = originalFail;
  });
});


// =============================================================================
// Shared Core Smoke Tests
// =============================================================================

describe('Shared core smoke tests', () => {
  it('PolicyCache works via @wid/core', () => {
    const cache = new PolicyCache({ ttlMs: 1000 });
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/'), { verdict: 'allow' });
  });

  it('CircuitBreaker works via @wid/core', () => {
    const cb = new CircuitBreaker({ threshold: 3, cooldownMs: 100 });
    assert.equal(cb.isOpen(), false);
    cb.recordFailure(); cb.recordFailure(); cb.recordFailure();
    assert.equal(cb.isOpen(), true);
  });

  it('sanitizePath works via @wid/core', () => {
    assert.equal(sanitizePath('/users/12345?q=secret'), '/users/{id}');
  });

  it('sanitizeHeaders strips sensitive data via @wid/core', () => {
    const result = sanitizeHeaders({ Authorization: 'Bearer secret', 'Content-Type': 'json' });
    assert.equal(result['authorization'], undefined);
    assert.equal(result['content-type'], 'json');
  });

  it('buildAuditEntry produces structured entry via @wid/core', () => {
    const entry = buildAuditEntry('d1', 'spiffe://c/ns/p/sa/fe', 'spiffe://c/ns/p/sa/be', 'GET', '/api', 'allow', {}, 5, false);
    assert.equal(entry.source_name, 'fe');
    assert.equal(entry.destination_name, 'be');
    assert.equal(entry.verdict, 'allow');
  });

  it('generateIptablesScript produces valid script via @wid/core', () => {
    const script = generateIptablesScript({ outboundPort: 15001, inboundPort: 15006, gatewayUid: 1337 });
    assert.ok(script.includes('#!/bin/bash'));
    assert.ok(script.includes('15001'));
    assert.ok(script.includes('1337'));
  });

  it('MetricsCollector tracks decisions via @wid/core', () => {
    const m = new MetricsCollector();
    m.record('allow', 10);
    m.record('deny', 20);
    const s = m.getSnapshot();
    assert.equal(s.counters.total, 2);
  });
});


// =============================================================================
// Integration: Outbound Proxy
// =============================================================================

describe('Outbound Proxy Integration', () => {
  let mockPolicyServer, mockTokenServer, mockBackend;
  let policyPort, tokenPort, backendPort;

  beforeEach(async () => {
    mockPolicyServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        const data = JSON.parse(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          decision: 'granted', verdict: 'granted',
          matched_policy: 'test-allow', decision_id: data.decision_id,
        }));
      });
    });

    mockTokenServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token_jti: 'tok_test_123', root_jti: 'root_test_123', chain_depth: 1, ttl: 300 }));
    });

    mockBackend = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        service: 'mock-backend',
        receivedHeaders: {
          'x-wid-decision-id': req.headers['x-wid-decision-id'],
          'x-wid-token-jti': req.headers['x-wid-token-jti'],
          'x-wid-client': req.headers['x-wid-client'],
          'x-wid-mode': req.headers['x-wid-mode'],
        },
      }));
    });

    await new Promise(r => mockPolicyServer.listen(0, r));
    await new Promise(r => mockTokenServer.listen(0, r));
    await new Promise(r => mockBackend.listen(0, r));

    policyPort = mockPolicyServer.address().port;
    tokenPort = mockTokenServer.address().port;
    backendPort = mockBackend.address().port;

    CONFIG.policyServiceUrl = `http://127.0.0.1:${policyPort}`;
    CONFIG.tokenServiceUrl = `http://127.0.0.1:${tokenPort}`;
    CONFIG.cpTimeoutMs = 2000;
    CONFIG.tokenTimeoutMs = 2000;
  });

  afterEach(() => {
    mockPolicyServer.close();
    mockTokenServer.close();
    mockBackend.close();
  });

  it('mock backend receives WID headers', async () => {
    const res = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1', port: backendPort, path: '/data',
        method: 'GET', headers: { 'x-wid-decision-id': 'dec_test', 'x-wid-token-jti': 'tok_test' },
      }, (res) => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => resolve(JSON.parse(body)));
      });
      req.on('error', reject);
      req.end();
    });

    assert.equal(res.service, 'mock-backend');
    assert.equal(res.receivedHeaders['x-wid-decision-id'], 'dec_test');
    assert.equal(res.receivedHeaders['x-wid-token-jti'], 'tok_test');
  });

  it('mock policy engine returns grant decisions', async () => {
    const res = await new Promise((resolve, reject) => {
      const data = JSON.stringify({ source_principal: 'test', destination_principal: 'test', method: 'GET', path_pattern: '/', decision_id: 'dec_1' });
      const req = http.request({
        hostname: '127.0.0.1', port: policyPort, path: '/api/v1/access/evaluate/principal',
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
      }, (res) => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => resolve(JSON.parse(body)));
      });
      req.on('error', reject);
      req.write(data);
      req.end();
    });

    assert.equal(res.decision, 'granted');
    assert.equal(res.matched_policy, 'test-allow');
  });

  it('mock token service returns JIT tokens', async () => {
    const res = await new Promise((resolve, reject) => {
      const data = JSON.stringify({ subject: 'test', audience: 'test' });
      const req = http.request({
        hostname: '127.0.0.1', port: tokenPort, path: '/v1/token/exchange',
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
      }, (res) => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => resolve(JSON.parse(body)));
      });
      req.on('error', reject);
      req.write(data);
      req.end();
    });

    assert.equal(res.token_jti, 'tok_test_123');
    assert.equal(res.chain_depth, 1);
  });
});


// =============================================================================
// AI Inspector Integration
// =============================================================================

describe('AIInspector integration via @wid/core', () => {
  it('AIInspector is exported from @wid/core', () => {
    assert.ok(AIInspector);
    assert.equal(typeof AIInspector, 'function');
  });

  it('can instantiate with AuditBuffer and detect AI endpoints', () => {
    const auditBuffer = new AuditBuffer({ flushIntervalMs: 0 });
    const inspector = new AIInspector({
      auditBuffer,
      workloadName: 'test-gw',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/test-gw',
    });

    assert.ok(inspector.detectAIEndpoint('api.openai.com'));
    assert.ok(inspector.detectAIEndpoint('api.anthropic.com'));
    assert.equal(inspector.detectAIEndpoint('api.stripe.com'), null);
    auditBuffer.destroy();
  });

  it('emits ai_request telemetry to AuditBuffer', () => {
    const entries = [];
    const mockBuffer = {
      push(entry) { entries.push(entry); },
      flush() {},
      getStats() { return { pending: entries.length }; },
      destroy() {},
    };

    const inspector = new AIInspector({
      auditBuffer: mockBuffer,
      workloadName: 'billing-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/billing-agent',
    });

    // Simulate body processing directly
    inspector._processBody(
      Buffer.from(JSON.stringify({
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: 'You are a billing assistant.' },
          { role: 'user', content: 'Check my balance' },
        ],
        tools: [
          { function: { name: 'get_balance' } },
          { function: { name: 'send_invoice' } },
        ],
      })),
      { provider: 'openai', label: 'OpenAI' },
      { destHost: 'api.openai.com', method: 'POST', path: '/v1/chat/completions', decisionId: 'dec_test', truncated: false, totalBytes: 200 },
    );

    assert.equal(entries.length, 1);
    assert.equal(entries[0].event_type, 'ai_request');
    assert.equal(entries[0].ai.provider, 'openai');
    assert.equal(entries[0].ai.model, 'gpt-4o');
    assert.equal(entries[0].ai.tool_count, 2);
    assert.deepEqual(entries[0].ai.tool_names, ['get_balance', 'send_invoice']);
    assert.equal(entries[0].ai.has_system_prompt, true);
    assert.equal(entries[0].ai.message_count, 2);
  });

  it('getStats returns correct shape', () => {
    const inspector = new AIInspector({
      auditBuffer: new AuditBuffer({ flushIntervalMs: 0 }),
      workloadName: 'test',
      spiffeId: 'spiffe://test',
    });

    const stats = inspector.getStats();
    assert.equal(typeof stats.enabled, 'boolean');
    assert.equal(typeof stats.inspected, 'number');
    assert.equal(typeof stats.parseFailed, 'number');
    assert.equal(typeof stats.byProvider, 'object');
  });
});
