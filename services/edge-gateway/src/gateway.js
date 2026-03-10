// =============================================================================
// Edge Gateway — On-Prem / Non-Mesh Deployment Mode
// =============================================================================
//
// Transparent HTTP proxy that intercepts outbound traffic via iptables,
// evaluates policy, exchanges tokens, injects credentials, and proxies
// the request to its real destination. The app never changes.
//
// Shared core (PolicyCache, CircuitBreaker, sanitization, etc.) imported
// from @wid/core — same code runs in ext-authz-adapter for cloud/mesh.
//
// =============================================================================

'use strict';

const http = require('http');
const crypto = require('crypto');

// ── Shared Core (same code used by ext-authz-adapter) ──
const {
  parseJSON, log, setLogLevel, setStructuredLogs, httpRequest,
  PolicyCache, CredentialBuffer, CircuitBreaker,
  MetricsCollector, AuditBuffer, AIInspector,
  sanitizePath, extractWorkloadName, buildAuditEntry,
  generateIptablesScript,
} = require('@wid/core');


// =============================================================================
// Configuration
// =============================================================================

const CONFIG = {
  // Proxy ports
  outboundPort: parseInt(process.env.OUTBOUND_PORT) || 15001,
  inboundPort:  parseInt(process.env.INBOUND_PORT)  || 15006,
  adminPort:    parseInt(process.env.ADMIN_PORT)     || 15000,
  appPort:      parseInt(process.env.APP_PORT)       || 8080,
  appHost:      process.env.APP_HOST                || '127.0.0.1',

  // Identity
  workloadName: process.env.WORKLOAD_NAME || 'unknown',
  spiffeId:     process.env.SPIFFE_ID     || null,
  namespace:    process.env.WORKLOAD_NS   || 'default',
  trustDomain:  process.env.TRUST_DOMAIN  || 'cluster.local',
  instanceId:   `gw-${crypto.randomBytes(4).toString('hex')}`,

  // Control plane
  policyServiceUrl: process.env.POLICY_SERVICE_URL || 'http://policy-engine:3001',
  tokenServiceUrl:  process.env.TOKEN_SERVICE_URL  || 'http://token-service:3000',
  brokerUrl:        process.env.BROKER_URL          || 'http://credential-broker:3002',

  // Behavior
  defaultMode:    process.env.DEFAULT_MODE    || 'audit',
  failBehavior:   process.env.FAIL_BEHAVIOR   || 'open',
  cpTimeoutMs:    parseInt(process.env.CP_TIMEOUT_MS)    || 300,
  tokenTimeoutMs: parseInt(process.env.TOKEN_TIMEOUT_MS) || 500,
  proxyTimeoutMs: parseInt(process.env.PROXY_TIMEOUT_MS) || 30000,
  maxChainDepth:  parseInt(process.env.MAX_CHAIN_DEPTH)  || 10,

  // Cache
  cacheEnabled:    process.env.CACHE_ENABLED !== 'false',
  cacheTtlMs:      parseInt(process.env.CACHE_TTL_MS)      || 30000,
  cacheMaxEntries: parseInt(process.env.CACHE_MAX_ENTRIES)  || 10000,

  // Credential buffer
  credBufferEnabled: process.env.CRED_BUFFER_ENABLED !== 'false',
  credBufferTtlMs:   parseInt(process.env.CRED_BUFFER_TTL_MS) || 300000,

  // Per-workload overrides
  workloadOverrides: parseJSON(process.env.WORKLOAD_OVERRIDES, {}),

  // Platform traffic to bypass (direct passthrough)
  platformPorts: [3000, 3001, 3002, 3003, 3004, 8200, 8181, 15000],
  platformHosts: ['policy-engine', 'token-service', 'credential-broker', 'vault', 'opa', 'postgres'],

  // AI Inspection
  aiInspectionEnabled: process.env.AI_INSPECTION_ENABLED !== 'false',
  aiInspectionMaxBodyBytes: parseInt(process.env.AI_INSPECTION_MAX_BODY_BYTES) || 65536,

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',
  structuredLogs: process.env.STRUCTURED_LOGS === 'true',
};

setLogLevel(CONFIG.logLevel);
setStructuredLogs(CONFIG.structuredLogs);


// =============================================================================
// Outbound Proxy — Intercepts app→external traffic
// =============================================================================

function createOutboundProxy(deps) {
  const { policyCache, credBuffer, policyBreaker, tokenBreaker, metrics, auditBuffer, aiInspector } = deps;

  return http.createServer(async (req, res) => {
    const start = Date.now();
    const decisionId = `dec_${crypto.randomBytes(6).toString('hex')}`;
    const hostHeader = req.headers.host || 'unknown';
    let [destHost, destPortStr] = hostHeader.split(':');
    let destPort = parseInt(destPortStr) || 80;

    // Docker mode: when accessed via mapped port, Host is localhost — use APP_HOST instead
    if ((destHost === 'localhost' || destHost === '127.0.0.1') && CONFIG.appHost !== '127.0.0.1') {
      destHost = CONFIG.appHost;
      destPort = CONFIG.appPort;
    }

    // Bypass platform traffic
    if (isPlatformTraffic(destHost, destPort)) {
      return proxyPassthrough(req, res, destHost, destPort);
    }

    // Passthrough mode
    const mode = resolveMode(CONFIG.workloadName);
    if (mode === 'passthrough') {
      metrics.record('allow', Date.now() - start);
      return proxyPassthrough(req, res, destHost, destPort);
    }

    const method = req.method || 'GET';
    const rawPath = req.url || '/';
    const sourcePrincipal = CONFIG.spiffeId || `spiffe://${CONFIG.trustDomain}/ns/${CONFIG.namespace}/sa/${CONFIG.workloadName}`;
    const destPrincipal = `spiffe://${CONFIG.trustDomain}/ns/default/sa/${destHost}`;

    log('debug', `Outbound: ${method} ${destHost}:${destPort}${sanitizePath(rawPath)}`, { decisionId });

    // Chain depth guard
    const chainDepth = parseInt(req.headers['x-wid-chain-depth'] || '0');
    if (chainDepth >= CONFIG.maxChainDepth) {
      metrics.record('deny', Date.now() - start);
      res.writeHead(403, { 'Content-Type': 'application/json', 'x-wid-decision-id': decisionId });
      return res.end(JSON.stringify({ error: 'Chain depth exceeded', decision_id: decisionId }));
    }

    // Cache check
    const cached = policyCache.get(sourcePrincipal, destPrincipal, method, rawPath);
    if (cached) {
      metrics.record('allow', Date.now() - start);
      metrics.recordCacheHit();
      auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'allow', cached, Date.now() - start, true));
      return proxyWithHeaders(req, res, destHost, destPort, decisionId, start, cached.tokenData, chainDepth, aiInspector);
    }

    // Policy evaluation
    let policyResult = null;
    let policyError = false;

    if (policyBreaker.isOpen()) {
      policyError = true;
    } else {
      try {
        const evalRes = await httpRequest(
          `${CONFIG.policyServiceUrl}/api/v1/access/evaluate/principal`,
          'POST', {
            source_principal: sourcePrincipal,
            destination_principal: destPrincipal,
            source_name: CONFIG.workloadName,
            destination_name: destHost,
            method, path_pattern: sanitizePath(rawPath),
            timestamp: new Date().toISOString(),
            decision_id: decisionId,
          }, CONFIG.cpTimeoutMs,
        );
        policyResult = evalRes.data;
        policyBreaker.recordSuccess();
      } catch (e) {
        policyError = true;
        policyBreaker.recordFailure();
        log('warn', 'Policy evaluation failed', { decisionId, error: e.message });
      }
    }

    // Handle policy failure
    if (policyError) {
      const failBehavior = resolveFailBehavior(CONFIG.workloadName);
      if (failBehavior === 'closed') {
        metrics.record('deny', Date.now() - start);
        auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'fail-closed', null, Date.now() - start, false));
        res.writeHead(503, { 'Content-Type': 'application/json', 'x-wid-decision-id': decisionId });
        return res.end(JSON.stringify({ error: 'Policy service unavailable', decision_id: decisionId }));
      }
      metrics.record('allow', Date.now() - start);
      auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'fail-open', null, Date.now() - start, false));
      return proxyWithHeaders(req, res, destHost, destPort, decisionId, start, null, chainDepth, aiInspector);
    }

    // Policy denied
    const verdict = policyResult?.decision || policyResult?.verdict;
    if (verdict === 'denied' || verdict === 'deny') {
      if (mode === 'audit') {
        metrics.record('deny', Date.now() - start);
        auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'audit-deny', policyResult, Date.now() - start, false));
        return proxyWithHeaders(req, res, destHost, destPort, decisionId, start, null, chainDepth, aiInspector);
      }
      metrics.record('deny', Date.now() - start);
      auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'deny', policyResult, Date.now() - start, false));
      res.writeHead(403, { 'Content-Type': 'application/json', 'x-wid-decision-id': decisionId });
      return res.end(JSON.stringify({ error: 'Access denied by policy', decision_id: decisionId }));
    }

    // Token exchange
    let tokenData = null;
    if (tokenBreaker.isOpen()) {
      const buffered = credBuffer.get(sourcePrincipal, destPrincipal);
      if (buffered) tokenData = buffered;
    } else {
      try {
        const parentJti = req.headers['x-wid-token-jti'];
        const tokenRes = await httpRequest(
          `${CONFIG.tokenServiceUrl}/v1/token/exchange`, 'POST', {
            subject: sourcePrincipal, audience: destPrincipal,
            scopes: ['*'], token_type: 'ephemeral', ttl: 300,
            ...(parentJti ? { parent_jti: parentJti } : {}),
          }, CONFIG.tokenTimeoutMs,
        );
        if (tokenRes.status < 300 && tokenRes.data?.token_jti) {
          tokenData = tokenRes.data;
          credBuffer.set(sourcePrincipal, destPrincipal, tokenData);
          tokenBreaker.recordSuccess();
        }
      } catch (e) {
        tokenBreaker.recordFailure();
        const buffered = credBuffer.get(sourcePrincipal, destPrincipal);
        if (buffered) tokenData = buffered;
      }
    }

    // Cache and proxy
    policyCache.set(sourcePrincipal, destPrincipal, method, rawPath, { decision: policyResult, tokenData });
    metrics.record('allow', Date.now() - start);
    auditBuffer.push(buildAuditEntry(decisionId, sourcePrincipal, destPrincipal, method, rawPath, 'allow', policyResult, Date.now() - start, false));
    return proxyWithHeaders(req, res, destHost, destPort, decisionId, start, tokenData, chainDepth, aiInspector);
  });
}


// =============================================================================
// Inbound Proxy — Validates incoming requests
// =============================================================================

function createInboundProxy(deps) {
  const { metrics, auditBuffer } = deps;

  return http.createServer(async (req, res) => {
    const tokenJti = req.headers['x-wid-token-jti'];
    const decisionId = req.headers['x-wid-decision-id'] || `dec_${crypto.randomBytes(6).toString('hex')}`;

    if (tokenJti) {
      try {
        const validateRes = await httpRequest(
          `${CONFIG.tokenServiceUrl}/v1/token/validate`,
          'POST', { token_jti: tokenJti }, CONFIG.tokenTimeoutMs,
        );
        if (validateRes.data && !validateRes.data.valid) {
          res.writeHead(401, { 'Content-Type': 'application/json', 'x-wid-decision-id': decisionId });
          return res.end(JSON.stringify({ error: 'Invalid or expired token', reason: validateRes.data.reason }));
        }

        // Capability-based scope enforcement (UC5: Multi-Agent Task Isolation)
        // If the token has scopes, enforce that the request matches an allowed scope
        if (validateRes.data?.scopes && Array.isArray(validateRes.data.scopes)) {
          const allowedScopes = validateRes.data.scopes;
          const requestedAction = mapRequestToCapability(req.method, req.url);

          if (!allowedScopes.includes('*') && requestedAction) {
            const scopeAllowed = allowedScopes.some(s =>
              s === requestedAction || requestedAction.startsWith(s + ':') || s === '*'
            );
            if (!scopeAllowed) {
              log('warn', `Scope denied: ${requestedAction} not in [${allowedScopes.join(',')}]`, { decisionId, tokenJti });
              res.writeHead(403, { 'Content-Type': 'application/json', 'x-wid-decision-id': decisionId });
              return res.end(JSON.stringify({
                error: 'Insufficient scope',
                required: requestedAction,
                granted: allowedScopes,
                decision_id: decisionId,
              }));
            }
          }
        }
      } catch {
        log('debug', 'Token validation skipped (service unavailable)');
      }
    }

    proxyToLocal(req, res, CONFIG.appPort);
  });
}

// Map HTTP request method+path to capability (for scope enforcement)
function mapRequestToCapability(method, path) {
  const p = (path || '').toLowerCase();
  // AI model invocations
  if (/\/(v1\/)?chat\/completions|\/v1\/messages|\/generate|\/embeddings/.test(p)) return 'model:invoke';
  if (/\/fine.?tun|\/training/.test(p)) return 'model:train';
  // MCP operations
  if (/\/mcp\//.test(p)) {
    if (method === 'GET') return 'mcp:query';
    return 'mcp:execute';
  }
  // Token operations
  if (/\/token\/exchange/.test(p)) return 'token:exchange';
  if (/\/token\/issue/.test(p)) return 'token:issue';
  // Credential operations
  if (/\/credentials?\//.test(p) || /\/secrets?\//.test(p)) {
    if (method === 'GET') return 'secret:read';
    return 'secret:write';
  }
  // Generic API
  return 'api:invoke';
}


// =============================================================================
// Admin API
// =============================================================================

function createAdminServer(deps) {
  const { policyCache, credBuffer, policyBreaker, tokenBreaker, metrics, auditBuffer, aiInspector } = deps;

  return http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const url = req.url.split('?')[0];

    if (url === '/healthz') {
      return res.end(JSON.stringify({ status: 'healthy', service: 'edge-gateway', workload: CONFIG.workloadName, spiffe_id: CONFIG.spiffeId, uptime: Math.floor(process.uptime()) }));
    }
    if (url === '/readyz') {
      return res.end(JSON.stringify({ ready: true, policyBreaker: policyBreaker.getState(), tokenBreaker: tokenBreaker.getState() }));
    }
    if (url === '/metrics') {
      return res.end(JSON.stringify({ decisions: metrics.getSnapshot(), cache: policyCache.getStats(), credentialBuffer: credBuffer.getStats(), breakers: { policy: policyBreaker.getState(), token: tokenBreaker.getState() }, audit: auditBuffer.getStats(), aiInspection: aiInspector?.getStats() || {} }));
    }
    if (url === '/metrics/prometheus') { res.setHeader('Content-Type', 'text/plain'); return res.end(metrics.toPrometheus()); }
    if (url === '/cache/clear' && req.method === 'POST') { policyCache.clear(); return res.end(JSON.stringify({ cleared: true })); }
    if (url === '/mode' && req.method === 'PUT') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const { mode } = JSON.parse(body);
          if (['audit', 'enforce', 'passthrough'].includes(mode)) { CONFIG.defaultMode = mode; res.end(JSON.stringify({ mode })); }
          else { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid mode' })); }
        } catch { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' })); }
      });
      return;
    }
    if (url === '/config') {
      return res.end(JSON.stringify({ workload: CONFIG.workloadName, spiffeId: CONFIG.spiffeId, mode: 'gateway', defaultMode: CONFIG.defaultMode, failBehavior: CONFIG.failBehavior, cacheEnabled: CONFIG.cacheEnabled }));
    }
    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
  });
}


// =============================================================================
// Proxy Helpers
// =============================================================================

function proxyWithHeaders(clientReq, clientRes, destHost, destPort, decisionId, start, tokenData, chainDepth, aiInspector) {
  const opts = {
    hostname: destHost, port: destPort, path: clientReq.url,
    method: clientReq.method, headers: { ...clientReq.headers },
    timeout: CONFIG.proxyTimeoutMs,
  };
  opts.headers['x-wid-decision-id'] = decisionId;
  opts.headers['x-wid-client'] = CONFIG.workloadName;
  opts.headers['x-wid-client-spiffe'] = CONFIG.spiffeId || '';
  opts.headers['x-wid-latency-ms'] = String(Date.now() - start);
  opts.headers['x-wid-mode'] = CONFIG.defaultMode;
  opts.headers['x-wid-chain-depth'] = String(chainDepth + 1);
  if (tokenData) {
    opts.headers['x-wid-token-jti'] = tokenData.token_jti;
    if (tokenData.root_jti) opts.headers['x-wid-root-jti'] = tokenData.root_jti;
  }
  // ── AI Inspection: detect before creating proxy request ──
  const aiMatch = aiInspector?.detectAIEndpoint(clientReq.headers.host);

  const proxyReq = http.request(opts, (proxyRes) => {
    proxyRes.headers['x-wid-decision-id'] = decisionId;
    if (aiMatch && clientReq.method === 'POST') {
      // AI traffic: intercept response for telemetry (tokens, cost, status)
      // captureResponse handles writeHead + piping to clientRes internally
      aiInspector.captureResponse(proxyRes, clientRes, aiMatch, decisionId);
    } else {
      // Non-AI: unchanged pipe
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(clientRes);
    }
  });
  proxyReq.on('error', (e) => {
    if (!clientRes.headersSent) { clientRes.writeHead(502, { 'Content-Type': 'application/json' }); clientRes.end(JSON.stringify({ error: 'Upstream failed', detail: e.message })); }
  });

  // ── AI Inspection Tee — request body (zero latency impact) ──
  if (aiMatch && clientReq.method === 'POST') {
    const tee = aiInspector.teeRequest(
      clientReq, aiMatch, destHost, clientReq.method,
      sanitizePath(clientReq.url), decisionId,
    );
    clientReq.pipe(tee);       // copy goes to inspector (async parse)
    clientReq.pipe(proxyReq);  // original goes to destination (unchanged)
  } else {
    clientReq.pipe(proxyReq);  // non-AI: unchanged behavior
  }
}

function proxyPassthrough(clientReq, clientRes, destHost, destPort) {
  const proxyReq = http.request({ hostname: destHost, port: destPort, path: clientReq.url, method: clientReq.method, headers: clientReq.headers, timeout: CONFIG.proxyTimeoutMs }, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });
  proxyReq.on('error', () => { if (!clientRes.headersSent) { clientRes.writeHead(502); clientRes.end('Passthrough failed'); } });
  clientReq.pipe(proxyReq);
}

function proxyToLocal(clientReq, clientRes, appPort) {
  const proxyReq = http.request({ hostname: CONFIG.appHost, port: appPort, path: clientReq.url, method: clientReq.method, headers: clientReq.headers, timeout: CONFIG.proxyTimeoutMs }, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });
  proxyReq.on('error', (e) => { if (!clientRes.headersSent) { clientRes.writeHead(503); clientRes.end(JSON.stringify({ error: 'Application not ready' })); } });
  clientReq.pipe(proxyReq);
}

function isPlatformTraffic(host, port) {
  if (CONFIG.platformPorts.includes(port)) return true;
  if (host === 'localhost' || host === '127.0.0.1') return true;
  return CONFIG.platformHosts.some(h => host.includes(h));
}

function resolveMode(workloadName) {
  const spiffe = CONFIG.spiffeId || `spiffe://${CONFIG.trustDomain}/ns/${CONFIG.namespace}/sa/${workloadName}`;
  return CONFIG.workloadOverrides[spiffe]?.mode || CONFIG.defaultMode;
}

function resolveFailBehavior(workloadName) {
  const spiffe = CONFIG.spiffeId || `spiffe://${CONFIG.trustDomain}/ns/${CONFIG.namespace}/sa/${workloadName}`;
  return CONFIG.workloadOverrides[spiffe]?.fail || CONFIG.failBehavior;
}


// =============================================================================
// Main
// =============================================================================

async function main() {
  log('info', '═══════════════════════════════════════════════════════');
  log('info', '  Edge Gateway — Workload Identity Platform');
  log('info', `  Workload: ${CONFIG.workloadName} | SPIFFE: ${CONFIG.spiffeId || '(auto)'}`);
  log('info', `  Outbound: :${CONFIG.outboundPort} | Inbound: :${CONFIG.inboundPort} | Admin: :${CONFIG.adminPort}`);
  log('info', `  Default: ${CONFIG.defaultMode} | Fail: ${CONFIG.failBehavior} | Cache: ${CONFIG.cacheEnabled ? 'ON' : 'OFF'}`);
  log('info', `  Policy: ${CONFIG.policyServiceUrl}`);
  log('info', `  Token:  ${CONFIG.tokenServiceUrl}`);
  log('info', '═══════════════════════════════════════════════════════');

  // Generate iptables script
  const iptables = generateIptablesScript({
    outboundPort: CONFIG.outboundPort, inboundPort: CONFIG.inboundPort,
    adminPort: CONFIG.adminPort, gatewayUid: process.env.GATEWAY_UID || 1337,
  });
  require('fs').writeFileSync('/tmp/edge-gateway-iptables.sh', iptables, { mode: 0o755 });
  log('info', 'iptables script written to /tmp/edge-gateway-iptables.sh');

  const policyCache = new PolicyCache({ ttlMs: CONFIG.cacheTtlMs, maxEntries: CONFIG.cacheMaxEntries, enabled: CONFIG.cacheEnabled });
  const credBuffer = new CredentialBuffer({ ttlMs: CONFIG.credBufferTtlMs, enabled: CONFIG.credBufferEnabled });
  const policyBreaker = new CircuitBreaker({ threshold: 5, cooldownMs: 10000, name: 'policy-engine' });
  const tokenBreaker = new CircuitBreaker({ threshold: 3, cooldownMs: 5000, name: 'token-service' });
  const metrics = new MetricsCollector();
  const auditBuffer = new AuditBuffer({ flushIntervalMs: 5000, batchSize: 50, endpoint: `${CONFIG.policyServiceUrl}/api/v1/access/decisions/batch` });

  const aiInspector = new AIInspector({
    auditBuffer,
    workloadName: CONFIG.workloadName,
    spiffeId: CONFIG.spiffeId,
    enabled: CONFIG.aiInspectionEnabled,
    maxBodyBytes: CONFIG.aiInspectionMaxBodyBytes,
  });

  const deps = { policyCache, credBuffer, policyBreaker, tokenBreaker, metrics, auditBuffer, aiInspector };

  const outbound = createOutboundProxy(deps);
  const inbound = createInboundProxy(deps);
  const admin = createAdminServer(deps);

  outbound.listen(CONFIG.outboundPort, '0.0.0.0', () => log('info', `Outbound proxy on :${CONFIG.outboundPort}`));
  inbound.listen(CONFIG.inboundPort, '0.0.0.0', () => log('info', `Inbound proxy on :${CONFIG.inboundPort}`));
  admin.listen(CONFIG.adminPort, '0.0.0.0', () => log('info', `Admin API on :${CONFIG.adminPort}`));

  const shutdown = () => {
    log('info', 'Shutting down...');
    auditBuffer.flush().then(() => auditBuffer.destroy());
    outbound.close(); inbound.close(); admin.close();
    setTimeout(() => process.exit(0), 1000);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = {
  CONFIG, createOutboundProxy, createInboundProxy, createAdminServer,
  proxyWithHeaders, proxyPassthrough, proxyToLocal,
  isPlatformTraffic, resolveMode, resolveFailBehavior,
};

if (require.main === module) {
  main().catch(e => { log('error', 'Fatal: ' + e.message); process.exit(1); });
}
