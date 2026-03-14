// =============================================================================
// Workload Identity Platform — Shared Data Plane Core
// =============================================================================
//
// This module contains ALL shared logic used by both deployment modes:
//   1. ext-authz-adapter  (cloud / mesh — hooks into Envoy via gRPC)
//   2. edge-gateway       (on-prem / non-mesh — standalone transparent proxy)
//
// By extracting shared logic here, we guarantee:
//   - Identical policy evaluation semantics in both modes
//   - Identical data sanitization (zero customer data guarantee)
//   - Identical caching, circuit breaking, and credential buffering
//   - Identical metrics and audit trail format
//   - One place to fix bugs, one place to add features
//
// NEITHER adapter.js NOR gateway.js should duplicate any of these classes.
// =============================================================================

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

// ── Utility ──────────────────────────────────────────────────────────────────

function parseJSON(str, fallback) {
  if (str === null || str === undefined) return fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
let _logLevel = LOG_LEVELS[process.env.LOG_LEVEL || 'info'] || 1;
let _structuredLogs = process.env.STRUCTURED_LOGS === 'true';

function log(level, msg, meta = {}) {
  if (LOG_LEVELS[level] < _logLevel) return;
  const icons = { debug: '🔍', info: 'ℹ️', warn: '⚠️', error: '❌' };
  if (_structuredLogs) {
    console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }));
  } else {
    const extra = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
    console.log(`${icons[level] || ''} [${level}] ${msg}${extra}`);
  }
}

function setLogLevel(level) {
  if (LOG_LEVELS[level] !== undefined) _logLevel = LOG_LEVELS[level];
}

function setStructuredLogs(enabled) {
  _structuredLogs = enabled;
}

// ── HTTP Client ──────────────────────────────────────────────────────────────

function httpRequest(url, method = 'GET', body = null, timeoutMs = 300) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: timeoutMs,
    };
    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers }); }
        catch { resolve({ status: res.statusCode, data, headers: res.headers }); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${url}`)); });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ── Policy Cache (LRU + TTL) ─────────────────────────────────────────────────

class PolicyCache {
  constructor({ ttlMs = 30000, maxEntries = 10000, enabled = true } = {}) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.enabled = enabled;
    this.cache = new Map();
    this.stats = { hits: 0, misses: 0, evictions: 0 };
  }

  _key(source, dest, method, path) {
    return `${source}|${dest}|${method}|${this._normalizePath(path)}`;
  }

  _normalizePath(rawPath) {
    if (!rawPath) return '/';
    return rawPath
      .split('?')[0]
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/{uuid}')
      .replace(/\/\d{4,}/g, '/{id}')
      .replace(/\/[A-Za-z0-9_-]{20,}/g, '/{token}')
      .replace(/\/v\d+\//g, (m) => m);
  }

  get(source, dest, method, path) {
    if (!this.enabled) return null;
    const key = this._key(source, dest, method, path);
    const entry = this.cache.get(key);
    if (!entry) { this.stats.misses++; return null; }
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }
    this.stats.hits++;
    // LRU: move to end
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.decision;
  }

  set(source, dest, method, path, decision) {
    if (!this.enabled) return;
    const key = this._key(source, dest, method, path);
    // Evict LRU if full
    if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
      this.stats.evictions++;
    }
    this.cache.set(key, { decision, expiresAt: Date.now() + this.ttlMs });
  }

  clear() {
    this.cache.clear();
  }

  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      size: this.cache.size,
      hitRate: total > 0 ? (this.stats.hits / total * 100).toFixed(1) + '%' : '0%',
    };
  }
}

// ── Credential Buffer ────────────────────────────────────────────────────────

class CredentialBuffer {
  constructor({ ttlMs = 300000, enabled = true } = {}) {
    this.ttlMs = ttlMs;
    this.enabled = enabled;
    this.buffer = new Map();
    this.stats = { hits: 0, misses: 0 };
  }

  _key(source, dest) { return `${source}→${dest}`; }

  get(source, dest) {
    if (!this.enabled) return null;
    const entry = this.buffer.get(this._key(source, dest));
    if (!entry) { this.stats.misses++; return null; }
    const now = Date.now();
    if (now > entry.bufferExpiry || (entry.tokenExpiry && now > entry.tokenExpiry)) {
      this.buffer.delete(this._key(source, dest));
      this.stats.misses++;
      return null;
    }
    this.stats.hits++;
    return entry.credential;
  }

  set(source, dest, credential) {
    if (!this.enabled) return;
    const tokenExpiry = credential.expires_at
      ? new Date(credential.expires_at).getTime()
      : null;
    this.buffer.set(this._key(source, dest), {
      credential,
      bufferExpiry: Date.now() + this.ttlMs,
      tokenExpiry,
    });
  }

  getStats() {
    return { ...this.stats, size: this.buffer.size };
  }
}

// ── Circuit Breaker ──────────────────────────────────────────────────────────

class CircuitBreaker {
  constructor({ threshold = 5, cooldownMs = 10000, name = 'default' } = {}) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
    this.name = name;
    this.state = 'closed';
    this.failures = 0;
    this.lastFailure = 0;
    this.trippedCount = 0;
  }

  isOpen() {
    if (this.state === 'closed') return false;
    if (this.state === 'open' && Date.now() - this.lastFailure > this.cooldownMs) {
      this.state = 'half-open';
      return false; // allow one probe
    }
    return this.state === 'open';
  }

  recordSuccess() {
    if (this.state === 'half-open') {
      this.state = 'closed';
      this.failures = 0;
      log('info', `Circuit breaker ${this.name} recovered → closed`);
    }
  }

  recordFailure() {
    this.failures++;
    this.lastFailure = Date.now();
    if (this.state === 'half-open') {
      this.state = 'open';
      this.trippedCount++;
      log('warn', `Circuit breaker ${this.name} re-tripped → open`);
      return;
    }
    if (this.failures >= this.threshold && this.state === 'closed') {
      this.state = 'open';
      this.trippedCount++;
      log('warn', `Circuit breaker ${this.name} tripped → open (${this.failures} failures)`);
    }
  }

  getState() {
    // Re-check half-open transition
    if (this.state === 'open' && Date.now() - this.lastFailure > this.cooldownMs) {
      this.state = 'half-open';
    }
    return {
      state: this.state,
      failures: this.failures,
      tripped: this.trippedCount,
    };
  }
}

// ── Rate Limiter (per-principal sliding window) ──────────────────────────────

class RateLimiter {
  constructor({ windowMs = 60000, maxRequests = 1000, enabled = false } = {}) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.enabled = enabled;
    this.windows = new Map();
  }

  isAllowed(principal) {
    if (!this.enabled) return true;
    const now = Date.now();
    const key = principal || 'unknown';
    let window = this.windows.get(key);
    if (!window || now > window.resetAt) {
      window = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, window);
    }
    window.count++;
    return window.count <= this.maxRequests;
  }
}

// ── Metrics Collector ────────────────────────────────────────────────────────

class MetricsCollector {
  constructor() {
    this.counters = { total: 0, allowed: 0, denied: 0, errors: 0, cached: 0 };
    this.latencies = [];
    this.maxLatencies = 10000;
  }

  record(verdict, latencyMs) {
    this.counters.total++;
    if (verdict === 'allowed' || verdict === 'allow') this.counters.allowed++;
    else if (verdict === 'denied' || verdict === 'deny') this.counters.denied++;
    else this.counters.errors++;
    this.latencies.push(latencyMs);
    if (this.latencies.length > this.maxLatencies) {
      this.latencies = this.latencies.slice(-this.maxLatencies);
    }
  }

  recordCacheHit() { this.counters.cached++; }

  percentile(p) {
    if (this.latencies.length === 0) return 0;
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const idx = Math.ceil(sorted.length * p / 100) - 1;
    return sorted[Math.max(0, idx)];
  }

  getSnapshot() {
    return {
      counters: { ...this.counters },
      latency: {
        p50: this.percentile(50),
        p95: this.percentile(95),
        p99: this.percentile(99),
        count: this.latencies.length,
      },
    };
  }

  toPrometheus(prefix = 'wid') {
    const lines = [];
    for (const [name, val] of Object.entries(this.counters)) {
      lines.push(`# TYPE ${prefix}_extauthz_${name}_total counter`);
      lines.push(`${prefix}_extauthz_${name}_total ${val}`);
    }
    for (const p of [50, 95, 99]) {
      lines.push(`# TYPE ${prefix}_extauthz_latency_p${p} gauge`);
      lines.push(`${prefix}_extauthz_latency_p${p} ${this.percentile(p)}`);
    }
    return lines.join('\n');
  }
}

// ── Audit Buffer (batch flush) ───────────────────────────────────────────────

class AuditBuffer {
  constructor({ flushIntervalMs = 5000, batchSize = 50, endpoint = null } = {}) {
    this.buffer = [];
    this.batchSize = batchSize;
    this.endpoint = endpoint;
    this.stats = { flushed: 0, failed: 0 };

    if (endpoint && flushIntervalMs > 0) {
      this._timer = setInterval(() => this.flush(), flushIntervalMs);
      if (this._timer.unref) this._timer.unref();
    }
  }

  push(entry) {
    this.buffer.push(entry);
    if (this.buffer.length >= this.batchSize) this.flush();
  }

  async flush() {
    if (this.buffer.length === 0 || !this.endpoint) return;
    const batch = this.buffer.splice(0, this.batchSize);
    try {
      await httpRequest(this.endpoint, 'POST', { decisions: batch }, 2000);
      this.stats.flushed += batch.length;
    } catch (e) {
      this.stats.failed += batch.length;
      log('debug', `Audit flush failed: ${e.message}`);
    }
  }

  getStats() {
    return { pending: this.buffer.length, ...this.stats };
  }

  destroy() {
    if (this._timer) clearInterval(this._timer);
  }
}

// ── Data Sanitization (ZERO customer data guarantee) ─────────────────────────

const SENSITIVE_HEADERS = new Set([
  'authorization', 'cookie', 'set-cookie', 'x-api-key',
  'x-user-id', 'x-account-id', 'x-tenant-id', 'x-customer-id',
  'x-session-id', 'x-trace-id', 'x-b3-traceid', 'x-b3-spanid',
  'x-b3-parentspanid', 'x-b3-sampled', 'x-b3-flags',
  'proxy-authorization', 'x-forwarded-for', 'x-real-ip',
  'x-csrf-token', 'x-xsrf-token',
]);

const SAFE_HEADERS = new Set([
  'content-type', 'accept', 'accept-encoding', 'accept-language',
  'user-agent', 'x-request-id', 'x-envoy-peer-metadata',
  'x-envoy-peer-metadata-id',
]);

function sanitizeHeaders(headers) {
  if (!headers) return {};
  const result = {};
  for (const [key, val] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (SENSITIVE_HEADERS.has(lower)) continue;
    if (typeof val === 'string' && val.length > 256) continue;
    if (SAFE_HEADERS.has(lower) || lower.startsWith('x-envoy-')) {
      result[lower] = val;
    }
    // All other headers are dropped (allowlist only)
  }
  return result;
}

function sanitizePath(rawPath) {
  if (!rawPath) return '/';
  return rawPath
    .split('?')[0] // strip query string ALWAYS
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/{uuid}')
    .replace(/\/\d{4,}/g, '/{id}')
    .replace(/\/[A-Za-z0-9_-]{20,}/g, '/{token}')
    .replace(/\/v\d+\//g, (m) => m); // preserve version prefixes
}

function extractWorkloadName(principal) {
  if (!principal || principal === 'unknown') return 'unknown';
  const parts = principal.split('/');
  return parts[parts.length - 1] || 'unknown';
}

function extractNamespace(principal) {
  if (!principal) return 'unknown';
  const match = principal.match(/\/ns\/([^/]+)/);
  return match ? match[1] : 'unknown';
}

// ── Audit Entry Builder ──────────────────────────────────────────────────────

function buildAuditEntry(decisionId, source, dest, method, path, verdict, decision, latencyMs, cached) {
  return {
    decision_id: decisionId,
    source_principal: source || 'unknown',
    destination_principal: dest || 'unknown',
    source_name: extractWorkloadName(source),
    destination_name: extractWorkloadName(dest),
    method: method || 'UNKNOWN',
    path_pattern: sanitizePath(path),
    verdict,
    mode: decision?.mode || 'audit',
    policy_name: decision?.policy_name || null,
    token_jti: decision?.token_jti || null,
    root_jti: decision?.root_jti || null,
    chain_depth: decision?.chain_depth || 0,
    latency_ms: Math.round(latencyMs),
    adapter_mode: decision?.adapter_mode || 'unknown',
    cached: !!cached,
    timestamp: new Date().toISOString(),
  };
}

// ── Admin Server Factory ─────────────────────────────────────────────────────
// Creates the standard admin HTTP server used by both deployment modes.
// Both ext-authz-adapter and edge-gateway expose identical admin APIs.

function createAdminServer({ config, policyCache, credBuffer, policyBreaker, tokenBreaker, metrics, auditBuffer, mode }) {
  const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0];
    res.setHeader('Content-Type', 'application/json');

    if (url === '/healthz' && req.method === 'GET') {
      res.writeHead(200);
      return res.end(JSON.stringify({
        status: 'healthy',
        service: mode === 'adapter' ? 'ext-authz-adapter' : 'edge-gateway',
        mode: config.deployMode || 'local',
        version: config.version || '1.0.0',
        instance: config.instanceId || 'unknown',
        uptime: process.uptime(),
      }));
    }

    if (url === '/readyz' && req.method === 'GET') {
      const policyState = policyBreaker?.getState?.()?.state || 'closed';
      const tokenState = tokenBreaker?.getState?.()?.state || 'closed';
      const ready = policyState !== 'open' || config.failBehavior === 'open';
      res.writeHead(ready ? 200 : 503);
      return res.end(JSON.stringify({
        ready,
        policyBreaker: policyState,
        tokenBreaker: tokenState,
      }));
    }

    if (url === '/config' && req.method === 'GET') {
      res.writeHead(200);
      return res.end(JSON.stringify({
        mode: config.deployMode || 'local',
        defaultMode: config.defaultMode,
        failBehavior: config.failBehavior,
        cacheEnabled: config.cacheEnabled,
        cacheTtlMs: config.cacheTtlMs,
        credentialBufferEnabled: config.credBufferEnabled,
        cpTimeoutMs: config.cpTimeoutMs,
        maxChainDepth: config.maxChainDepth,
        workloadOverrides: config.workloadOverrides || {},
      }));
    }

    if (url === '/metrics' && req.method === 'GET') {
      const snapshot = metrics.getSnapshot();
      res.writeHead(200);
      return res.end(JSON.stringify({
        decisions: snapshot,
        cache: policyCache.getStats(),
        credentialBuffer: credBuffer.getStats(),
        breakers: {
          policy: policyBreaker?.getState?.() || {},
          token: tokenBreaker?.getState?.() || {},
        },
        audit: auditBuffer.getStats(),
      }));
    }

    if (url === '/metrics/prometheus' && req.method === 'GET') {
      res.setHeader('Content-Type', 'text/plain');
      res.writeHead(200);
      return res.end(metrics.toPrometheus());
    }

    if (url === '/cache/clear' && req.method === 'POST') {
      policyCache.clear();
      res.writeHead(200);
      return res.end(JSON.stringify({ cleared: true }));
    }

    if (url === '/mode' && req.method === 'PUT') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        try {
          const { mode: newMode } = JSON.parse(body);
          if (['audit', 'enforce', 'passthrough'].includes(newMode)) {
            config.defaultMode = newMode;
            log('info', `Mode switched to: ${newMode}`);
            res.writeHead(200);
            return res.end(JSON.stringify({ mode: newMode }));
          }
          res.writeHead(400);
          return res.end(JSON.stringify({ error: 'Invalid mode' }));
        } catch {
          res.writeHead(400);
          return res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  return server;
}

// ── iptables Script Generator (for edge-gateway) ────────────────────────────

function generateIptablesScript(config) {
  const outPort = config.outboundPort || 15001;
  const inPort = config.inboundPort || 15006;
  const uid = config.gatewayUid || 1337;
  const excludePorts = [
    config.policyServicePort || 3001,
    config.tokenServicePort || 3000,
    config.brokerPort || 3002,
    config.adminPort || 15000,
    53,   // DNS
    5432, // postgres
    8200, // vault
  ];

  const excludeRules = excludePorts
    .map(p => `iptables -t nat -A WID_OUTPUT -p tcp --dport ${p} -j RETURN`)
    .join('\n');

  return `#!/bin/bash
set -e

# Workload Identity Platform — iptables transparent redirect
# Generated by edge-gateway

# Skip traffic from the gateway itself (avoid loops)
iptables -t nat -N WID_OUTPUT 2>/dev/null || iptables -t nat -F WID_OUTPUT
iptables -t nat -A WID_OUTPUT -m owner --uid-owner ${uid} -j RETURN

# Skip platform service ports
${excludeRules}

# Skip localhost-to-localhost
iptables -t nat -A WID_OUTPUT -o lo -j RETURN

# Redirect all other outbound TCP to gateway
iptables -t nat -A WID_OUTPUT -p tcp -j REDIRECT --to-port ${outPort}
iptables -t nat -A OUTPUT -p tcp -j WID_OUTPUT

# Inbound: redirect all incoming TCP to gateway
iptables -t nat -N WID_INPUT 2>/dev/null || iptables -t nat -F WID_INPUT
iptables -t nat -A WID_INPUT -p tcp --dport ${inPort} -j RETURN
iptables -t nat -A WID_INPUT -p tcp -j REDIRECT --to-port ${inPort}
iptables -t nat -A PREROUTING -p tcp -j WID_INPUT

echo "✅ iptables rules applied (outbound→:${outPort}, inbound→:${inPort})"
`;
}

// ── AI Inspection ────────────────────────────────────────────────────────────

const { AIInspector } = require('./ai-inspector');
const { MCPInspector } = require('./mcp-inspector');

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Utilities
  parseJSON,
  log,
  setLogLevel,
  setStructuredLogs,
  httpRequest,
  LOG_LEVELS,

  // Core classes
  PolicyCache,
  CredentialBuffer,
  CircuitBreaker,
  RateLimiter,
  MetricsCollector,
  AuditBuffer,
  AIInspector,
  MCPInspector,

  // Sanitization
  SENSITIVE_HEADERS,
  SAFE_HEADERS,
  sanitizeHeaders,
  sanitizePath,
  extractWorkloadName,
  extractNamespace,

  // Audit
  buildAuditEntry,

  // Admin
  createAdminServer,

  // Infrastructure
  generateIptablesScript,
};
