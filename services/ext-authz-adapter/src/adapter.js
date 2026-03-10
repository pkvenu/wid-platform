// =============================================================================
// ext_authz gRPC Adapter — Cloud / Mesh Deployment Mode
// =============================================================================
//
// Hooks into Envoy's ext_authz filter via gRPC. Envoy calls this adapter
// on every request; adapter evaluates policy, exchanges tokens, injects
// credentials, and returns allow/deny to Envoy.
//
// Shared core (PolicyCache, CircuitBreaker, sanitization, etc.) imported
// from @wid/core — same code runs in edge-gateway for on-prem.
//
// =============================================================================

'use strict';

const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const crypto = require('crypto');
const http = require('http');
const path = require('path');

// ── Shared Core (same code used by edge-gateway) ──
const {
  parseJSON, log, setLogLevel, setStructuredLogs, httpRequest,
  PolicyCache, CredentialBuffer, CircuitBreaker, RateLimiter,
  MetricsCollector, AuditBuffer,
  sanitizePath, extractWorkloadName, extractNamespace, buildAuditEntry,
} = require('@wid/core');


// ── Mode Detection ──
const DEPLOY_MODE = process.env.DEPLOY_MODE || 'local';

// =============================================================================
// Configuration
// =============================================================================

const CONFIG = {
  mode: DEPLOY_MODE,
  version: process.env.APP_VERSION || '1.0.0',
  instanceId: `adapter-${crypto.randomBytes(4).toString('hex')}`,

  grpcPort:  parseInt(process.env.GRPC_PORT)  || 9191,
  adminPort: parseInt(process.env.ADMIN_PORT) || 8080,

  // Control plane
  policyServiceUrl: process.env.POLICY_SERVICE_URL || (DEPLOY_MODE === 'aws'
    ? 'http://policy-engine.wid-system.svc.cluster.local:3001' : 'http://policy-engine:3001'),
  tokenServiceUrl: process.env.TOKEN_SERVICE_URL || (DEPLOY_MODE === 'aws'
    ? 'http://token-service.wid-system.svc.cluster.local:3000' : 'http://token-service:3000'),
  brokerUrl: process.env.BROKER_URL || (DEPLOY_MODE === 'aws'
    ? 'http://credential-broker.wid-system.svc.cluster.local:3002' : 'http://credential-broker:3002'),

  // Cache
  cacheEnabled:    process.env.CACHE_ENABLED !== 'false',
  cacheTtlMs:      parseInt(process.env.CACHE_TTL_MS)       || 30000,
  cacheMaxEntries: parseInt(process.env.CACHE_MAX_ENTRIES)   || 10000,

  // Credential buffer
  credBufferEnabled: process.env.CRED_BUFFER_ENABLED !== 'false',
  credBufferTtlMs:   parseInt(process.env.CRED_BUFFER_TTL_MS) || 300000,

  // Behavior
  defaultMode:          process.env.DEFAULT_MODE          || 'audit',
  defaultFailBehavior:  process.env.DEFAULT_FAIL_BEHAVIOR || 'open',
  controlPlaneTimeoutMs: parseInt(process.env.CP_TIMEOUT_MS)    || 300,
  tokenExchangeTimeoutMs: parseInt(process.env.TOKEN_TIMEOUT_MS) || 500,
  maxChainDepth:        parseInt(process.env.MAX_CHAIN_DEPTH)   || 10,

  // Per-workload overrides
  workloadOverrides: parseJSON(process.env.WORKLOAD_OVERRIDES, {}),

  // Platform headers to strip on egress
  platformHeaders: [
    'x-wid-decision-id', 'x-wid-verdict', 'x-wid-token-jti',
    'x-wid-root-jti', 'x-wid-chain-depth', 'x-wid-cache',
    'x-wid-latency-ms', 'x-wid-mode', 'x-wid-internal-only',
  ],

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',
  structuredLogs: process.env.STRUCTURED_LOGS !== 'false',

  // Rate limiting
  rateLimitEnabled:    process.env.RATE_LIMIT_ENABLED === 'true',
  rateLimitWindowMs:   parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX)      || 10000,

  // AWS
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    cloudwatchEnabled: process.env.CW_ENABLED === 'true',
    xrayEnabled: process.env.XRAY_ENABLED === 'true',
  },

  startupDelayMs: parseInt(process.env.STARTUP_DELAY_MS) || 0,
};

setLogLevel(CONFIG.logLevel);
setStructuredLogs(CONFIG.structuredLogs);


// =============================================================================
// gRPC Check Handler
// =============================================================================

function createCheckHandler(deps) {
  const { cache, credBuffer, policyBreaker, tokenBreaker, rateLimiter, metrics, auditBuffer } = deps;

  return async function check(call, callback) {
    const start = process.hrtime.bigint();
    const decisionId = `dec_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;

    try {
      const attrs = (call.request?.attributes) || {};
      const source = attrs.source || {};
      const dest = attrs.destination || {};
      const httpReq = (attrs.request || {}).http || {};

      const sourcePrincipal = source.principal || 'unknown';
      const destPrincipal = dest.principal || 'unknown';
      const method = (httpReq.method || 'GET').toUpperCase();
      const rawPath = httpReq.path || '/';
      const host = (httpReq.host || '').split(':')[0];
      const safePath = sanitizePath(rawPath);

      log('debug', 'Check', { decisionId, src: sourcePrincipal, dst: destPrincipal, method, path: safePath });

      // Rate limiting
      if (CONFIG.rateLimitEnabled && !rateLimiter.isAllowed(sourcePrincipal)) {
        return respondDeny(callback, decisionId, start, 429, 'Rate limited', 'rate-limit');
      }

      // Per-workload behavior
      const destOverride = CONFIG.workloadOverrides[destPrincipal] || {};
      const srcOverride = CONFIG.workloadOverrides[sourcePrincipal] || {};
      const effectiveMode = destOverride.mode || srcOverride.mode || CONFIG.defaultMode;
      const effectiveFailBehavior = destOverride.fail || srcOverride.fail || CONFIG.defaultFailBehavior;

      // Passthrough
      if (effectiveMode === 'passthrough') {
        metrics.record('allow', latencyMs(start));
        return respondAllow(callback, decisionId, start, { mode: 'passthrough' });
      }

      // Cache check
      if (CONFIG.cacheEnabled) {
        const cached = cache.get(sourcePrincipal, destPrincipal, method, rawPath);
        if (cached) {
          const lMs = latencyMs(start);
          metrics.record(cached.verdict, lMs);
          metrics.recordCacheHit();

          if (effectiveMode === 'audit' && cached.verdict === 'deny') {
            auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'audit-deny', cached, lMs, true));
            return respondAllow(callback, decisionId, start, { mode: 'audit', shadowVerdict: 'deny', cached: true });
          }
          if (cached.verdict === 'allow') {
            auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'allow', cached, lMs, true));
            return respondAllow(callback, decisionId, start, {
              tokenJti: cached.token_jti, rootJti: cached.root_jti,
              chainDepth: cached.chain_depth, cached: true, mode: effectiveMode,
            });
          }
          auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'deny', cached, lMs, true));
          return respondDeny(callback, decisionId, start, 403, 'Policy denied', cached.policy_name);
        }
      }

      // Circuit breaker
      if (policyBreaker.isOpen()) {
        log('warn', 'Policy circuit breaker OPEN', { decisionId });
        return handleFailBehavior(callback, decisionId, start, effectiveFailBehavior, effectiveMode,
          metrics, auditBuffer, sourcePrincipal, destPrincipal, method, safePath, credBuffer);
      }

      // Policy evaluation (ZERO customer data sent)
      let decision;
      try {
        const evalPayload = {
          source_principal: sourcePrincipal,
          destination_principal: destPrincipal,
          source_name: extractWorkloadName(sourcePrincipal),
          destination_name: extractWorkloadName(destPrincipal),
          source_namespace: extractNamespace(sourcePrincipal),
          destination_namespace: extractNamespace(destPrincipal),
          source_labels: filterSafeLabels(source.labels),
          destination_labels: filterSafeLabels(dest.labels),
          method, path_pattern: safePath, host,
          timestamp: new Date().toISOString(),
          decision_id: decisionId,
          adapter_mode: CONFIG.mode,
        };

        const policyRes = await httpRequest(
          `${CONFIG.policyServiceUrl}/api/v1/access/evaluate/principal`,
          'POST', evalPayload, CONFIG.controlPlaneTimeoutMs,
        );
        policyBreaker.recordSuccess();

        decision = {
          verdict: (policyRes.data?.verdict === 'granted' || policyRes.data?.allowed) ? 'allow' : 'deny',
          policy_name: policyRes.data?.policy_name || policyRes.data?.matched_policy || null,
          scopes: policyRes.data?.scopes || [],
          ttl: Math.min(policyRes.data?.ttl || 300, 600),
          mode: policyRes.data?.mode || effectiveMode,
        };
      } catch (e) {
        policyBreaker.recordFailure();
        log('warn', 'Policy engine call failed', { decisionId, error: e.message });
        return handleFailBehavior(callback, decisionId, start, effectiveFailBehavior, effectiveMode,
          metrics, auditBuffer, sourcePrincipal, destPrincipal, method, safePath, credBuffer);
      }

      // Token exchange
      let tokenJti = null, rootJti = null, chainDepth = 0;
      if (decision.verdict === 'allow' && !tokenBreaker.isOpen()) {
        try {
          const incomingJti = (httpReq.headers || {})['x-wid-token-jti'] || null;
          const tokenRes = await httpRequest(
            `${CONFIG.tokenServiceUrl}/v1/token/exchange`, 'POST', {
              subject: sourcePrincipal, audience: destPrincipal,
              scopes: decision.scopes, parent_jti: incomingJti,
              token_type: 'ephemeral', ttl: decision.ttl,
              metadata: { adapter: 'ext-authz', decision_id: decisionId },
            }, CONFIG.tokenExchangeTimeoutMs,
          );
          tokenBreaker.recordSuccess();
          if (tokenRes.status < 300 && tokenRes.data?.token_jti) {
            tokenJti = tokenRes.data.token_jti;
            rootJti = tokenRes.data.root_jti;
            chainDepth = tokenRes.data.chain_depth || 0;
            if (CONFIG.credBufferEnabled) {
              credBuffer.set(sourcePrincipal, destPrincipal, {
                token_jti: tokenJti, root_jti: rootJti, chain_depth: chainDepth,
                expires_at: tokenRes.data.expires_at,
              });
            }
          }
        } catch (e) {
          tokenBreaker.recordFailure();
          log('debug', 'Token exchange failed (non-fatal)', { decisionId, error: e.message });
          if (CONFIG.credBufferEnabled) {
            const buffered = credBuffer.get(sourcePrincipal, destPrincipal);
            if (buffered) { tokenJti = buffered.token_jti; rootJti = buffered.root_jti; chainDepth = buffered.chain_depth; }
          }
        }
      }

      // Chain depth guard
      if (chainDepth > CONFIG.maxChainDepth) {
        const lMs = latencyMs(start);
        metrics.record('deny', lMs);
        auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'deny', { policy_name: 'chain-depth-limit' }, lMs, false));
        return respondDeny(callback, decisionId, start, 403, 'Chain depth exceeded', 'chain-depth-limit');
      }

      const fullDecision = { ...decision, token_jti: tokenJti, root_jti: rootJti, chain_depth: chainDepth };
      if (CONFIG.cacheEnabled) cache.set(sourcePrincipal, destPrincipal, method, rawPath, fullDecision);

      const lMs = latencyMs(start);

      if (effectiveMode === 'audit' && decision.verdict === 'deny') {
        metrics.record('deny', lMs);
        auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'audit-deny', fullDecision, lMs, false));
        return respondAllow(callback, decisionId, start, { mode: 'audit', shadowVerdict: 'deny', tokenJti, rootJti, chainDepth });
      }
      if (decision.verdict === 'allow') {
        metrics.record('allow', lMs);
        auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'allow', fullDecision, lMs, false));
        return respondAllow(callback, decisionId, start, { tokenJti, rootJti, chainDepth, mode: effectiveMode });
      }
      metrics.record('deny', lMs);
      auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, safePath, 'deny', fullDecision, lMs, false));
      return respondDeny(callback, decisionId, start, 403, 'Policy denied', decision.policy_name);

    } catch (e) {
      log('error', 'Unhandled error in Check', { decisionId, error: e.message });
      return respondAllow(callback, decisionId, start, { mode: 'error-fallback' });
    }
  };
}


// =============================================================================
// gRPC Response Builders
// =============================================================================

function respondAllow(callback, decisionId, start, opts = {}) {
  const lMs = latencyMs(start);
  const headers = [
    hdr('x-wid-decision-id', decisionId),
    hdr('x-wid-verdict', opts.shadowVerdict ? 'audit-allowed' : 'allowed'),
    hdr('x-wid-latency-ms', String(lMs)),
    hdr('x-wid-mode', opts.mode || CONFIG.defaultMode),
  ];
  if (opts.tokenJti) {
    headers.push(hdr('x-wid-token-jti', opts.tokenJti));
    headers.push(hdr('x-wid-root-jti', opts.rootJti || opts.tokenJti));
    headers.push(hdr('x-wid-chain-depth', String(opts.chainDepth || 0)));
  }
  if (opts.cached) headers.push(hdr('x-wid-cache', 'hit'));
  if (opts.shadowVerdict) headers.push(hdr('x-wid-shadow-verdict', opts.shadowVerdict));

  callback(null, {
    status: { code: 0 },
    ok_response: { headers, headers_to_remove: CONFIG.platformHeaders },
  });
}

function respondDeny(callback, decisionId, start, httpCode, message, policyName) {
  callback(null, {
    status: { code: 7 },
    denied_response: {
      status: { code: httpCode },
      headers: [
        hdr('x-wid-decision-id', decisionId), hdr('x-wid-verdict', 'denied'),
        hdr('x-wid-latency-ms', String(latencyMs(start))), hdr('content-type', 'application/json'),
      ],
      body: JSON.stringify({ error: 'Access denied by workload identity policy', decision_id: decisionId }),
    },
  });
}

function handleFailBehavior(callback, decisionId, start, failBehavior, mode, metrics, auditBuffer, source, dest, method, path, credBuffer) {
  const lMs = latencyMs(start);
  if (mode === 'audit') {
    metrics.record('deny', lMs);
    auditBuffer.push(buildAuditEntry(decisionId, source, dest, method, path, 'fail-open-audit', {}, lMs, false));
    return respondAllow(callback, decisionId, start, { mode: 'audit' });
  }
  if (failBehavior === 'closed') {
    metrics.record('deny', lMs);
    auditBuffer.push(buildAuditEntry(decisionId, source, dest, method, path, 'fail-closed', {}, lMs, false));
    callback(null, {
      status: { code: 14 },
      denied_response: {
        status: { code: 503 },
        headers: [hdr('x-wid-decision-id', decisionId), hdr('x-wid-verdict', 'fail-closed'), hdr('content-type', 'application/json'), hdr('retry-after', '5')],
        body: JSON.stringify({ error: 'Policy engine temporarily unavailable', decision_id: decisionId }),
      },
    });
  } else {
    let tokenJti = null, rootJti = null, chainDepth = 0;
    if (CONFIG.credBufferEnabled) {
      const buffered = credBuffer.get(source, dest);
      if (buffered) { tokenJti = buffered.token_jti; rootJti = buffered.root_jti; chainDepth = buffered.chain_depth; }
    }
    metrics.record('allow', lMs);
    auditBuffer.push(buildAuditEntry(decisionId, source, dest, method, path, 'fail-open', {}, lMs, false));
    respondAllow(callback, decisionId, start, { mode: 'fail-open', tokenJti, rootJti, chainDepth });
  }
}


// =============================================================================
// Helpers
// =============================================================================

function hdr(key, value) { return { header: { key, value } }; }
function latencyMs(start) { return Number((process.hrtime.bigint() - start) / 1000000n); }

function filterSafeLabels(labels) {
  if (!labels) return {};
  const safe = {};
  for (const key of ['app', 'version', 'env', 'environment', 'team', 'tier', 'service']) {
    if (labels[key]) safe[key] = labels[key];
  }
  return safe;
}


// =============================================================================
// Admin HTTP Server
// =============================================================================

function createAdminServer(deps) {
  const { cache, credBuffer, policyBreaker, tokenBreaker, metrics, auditBuffer } = deps;
  return http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (req.url === '/healthz' || req.url === '/health') {
      return res.end(JSON.stringify({ status: 'healthy', service: 'ext-authz-adapter', mode: CONFIG.mode, version: CONFIG.version, instance: CONFIG.instanceId, uptime: Math.round(process.uptime()) }));
    }
    if (req.url === '/readyz' || req.url === '/ready') {
      const ready = !policyBreaker.isOpen();
      res.statusCode = ready ? 200 : 503;
      return res.end(JSON.stringify({ ready, policyBreaker: policyBreaker.getState(), tokenBreaker: tokenBreaker.getState() }));
    }
    if (req.url === '/metrics') {
      return res.end(JSON.stringify({ decisions: metrics.getSnapshot(), cache: cache.getStats(), credentialBuffer: credBuffer.getStats(), breakers: { policy: policyBreaker.getState(), token: tokenBreaker.getState() }, audit: auditBuffer.getStats(), config: { mode: CONFIG.mode, defaultMode: CONFIG.defaultMode, failBehavior: CONFIG.defaultFailBehavior } }));
    }
    if (req.url === '/metrics/prometheus') { res.setHeader('Content-Type', 'text/plain'); return res.end(metrics.toPrometheus()); }
    if (req.url === '/cache/clear' && req.method === 'POST') { cache.clear(); return res.end(JSON.stringify({ status: 'cleared' })); }
    if (req.url === '/config') {
      return res.end(JSON.stringify({ mode: CONFIG.mode, defaultMode: CONFIG.defaultMode, failBehavior: CONFIG.defaultFailBehavior, cacheEnabled: CONFIG.cacheEnabled, credBufferEnabled: CONFIG.credBufferEnabled, policyServiceUrl: CONFIG.policyServiceUrl, tokenServiceUrl: CONFIG.tokenServiceUrl }));
    }
    if (req.url === '/mode' && req.method === 'PUT') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const { mode } = JSON.parse(body);
          if (['enforce', 'audit', 'passthrough'].includes(mode)) { CONFIG.defaultMode = mode; res.end(JSON.stringify({ status: 'ok', mode })); }
          else { res.statusCode = 400; res.end(JSON.stringify({ error: 'Invalid mode' })); }
        } catch { res.statusCode = 400; res.end(JSON.stringify({ error: 'Invalid JSON' })); }
      });
      return;
    }
    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
  });
}


// =============================================================================
// Proto — loaded from proto/ directory (must match Envoy's field numbers exactly)
// =============================================================================


// =============================================================================
// Main
// =============================================================================

async function main() {
  log('info', '═══════════════════════════════════════════════════════');
  log('info', '  ext_authz Adapter — Workload Identity Platform');
  log('info', `  Mode: ${CONFIG.mode.toUpperCase()} | gRPC: :${CONFIG.grpcPort} | Admin: :${CONFIG.adminPort}`);
  log('info', `  Default: ${CONFIG.defaultMode} | Fail: ${CONFIG.defaultFailBehavior} | Cache: ${CONFIG.cacheEnabled ? 'ON' : 'OFF'}`);
  log('info', `  Policy: ${CONFIG.policyServiceUrl}`);
  log('info', `  Token:  ${CONFIG.tokenServiceUrl}`);
  log('info', '═══════════════════════════════════════════════════════');

  if (CONFIG.startupDelayMs > 0) await new Promise(r => setTimeout(r, CONFIG.startupDelayMs));

  const cache = new PolicyCache({ ttlMs: CONFIG.cacheTtlMs, maxEntries: CONFIG.cacheMaxEntries, enabled: CONFIG.cacheEnabled });
  const credBuffer = new CredentialBuffer({ ttlMs: CONFIG.credBufferTtlMs, enabled: CONFIG.credBufferEnabled });
  const policyBreaker = new CircuitBreaker({ threshold: 5, cooldownMs: 10000, name: 'policy-engine' });
  const tokenBreaker = new CircuitBreaker({ threshold: 3, cooldownMs: 5000, name: 'token-service' });
  const rateLimiter = new RateLimiter({ windowMs: CONFIG.rateLimitWindowMs, maxRequests: CONFIG.rateLimitMaxRequests, enabled: CONFIG.rateLimitEnabled });
  const metrics = new MetricsCollector();
  const auditBuffer = new AuditBuffer({ flushIntervalMs: 5000, batchSize: 50, endpoint: `${CONFIG.policyServiceUrl}/api/v1/access/decisions/batch` });

  const deps = { cache, credBuffer, policyBreaker, tokenBreaker, rateLimiter, metrics, auditBuffer };

  // Load proto files (must match Envoy's ext_authz field numbers exactly)
  const protoDir = path.join(__dirname, '..', 'proto');

  const packageDefinition = protoLoader.loadSync(path.join(protoDir, 'ext_authz.proto'), {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
    includeDirs: [protoDir],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition);

  // Ensure the Check method is registered under the fully-qualified gRPC path.
  // Envoy calls /envoy.service.auth.v3.Authorization/Check — if proto-loader
  // registers it as just /Authorization/Check, every call returns UNIMPLEMENTED.
  const serviceDef = proto.envoy.service.auth.v3.Authorization.service;
  const EXPECTED_PATH = '/envoy.service.auth.v3.Authorization/Check';
  if (serviceDef.Check && serviceDef.Check.path !== EXPECTED_PATH) {
    log('warn', `Fixing gRPC path: ${serviceDef.Check.path} → ${EXPECTED_PATH}`);
    serviceDef.Check.path = EXPECTED_PATH;
  }

  const grpcServer = new grpc.Server({ 'grpc.max_concurrent_streams': 1000, 'grpc.keepalive_time_ms': 30000 });
  grpcServer.addService(serviceDef, { Check: createCheckHandler(deps) });

  await new Promise((resolve, reject) => {
    grpcServer.bindAsync(`0.0.0.0:${CONFIG.grpcPort}`, grpc.ServerCredentials.createInsecure(), (err, port) => {
      if (err) return reject(err);
      log('info', `gRPC ext_authz listening on :${port}`);
      resolve(port);
    });
  });

  const adminServer = createAdminServer(deps);
  adminServer.listen(CONFIG.adminPort, '0.0.0.0', () => log('info', `Admin API listening on :${CONFIG.adminPort}`));

  const shutdown = async (signal) => {
    log('info', `${signal} received, shutting down...`);
    await auditBuffer.flush();
    auditBuffer.destroy();
    grpcServer.tryShutdown(() => adminServer.close(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  log('info', 'Adapter fully initialized');
}

module.exports = { CONFIG, createCheckHandler, respondAllow, respondDeny, handleFailBehavior, filterSafeLabels, hdr, latencyMs };

if (require.main === module) {
  main().catch(e => { log('error', 'Fatal: ' + e.message); process.exit(1); });
}
