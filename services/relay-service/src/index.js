// =============================================================================
// WID Relay Service — Hub-and-Spoke Architecture
// =============================================================================
//
// The Relay runs in every environment (AWS region, on-prem DC, GCP project, etc.)
// and provides:
//
//   1. LOCAL POLICY CACHE — adapters call the relay instead of central control plane
//   2. POLICY SYNC       — pulls policies from central on an interval + webhook trigger
//   3. AUDIT FORWARDING  — accepts audit events from local adapters, batches upstream
//   4. REGISTRATION      — registers this environment with the central control plane
//   5. HEALTH AGGREGATION — local adapter health rolled up to central dashboard
//
// Architecture:
//
//   Central Control Plane (AWS/GCP/on-prem)
//       │
//       │  Policy bundles (pull) / Audit events (push)
//       │  mTLS or API key auth
//       │
//   ┌───▼──────────────────────────────────┐
//   │  WID Relay (runs in each environment)│
//   │                                       │
//   │  ┌─────────────┐  ┌───────────────┐  │
//   │  │ Policy Cache │  │ Audit Buffer  │  │
//   │  │  (in-memory) │  │ (batch flush) │  │
//   │  └──────┬──────┘  └───────┬───────┘  │
//   │         │                 │           │
//   │    Local adapters talk to relay       │
//   └───▲──────────────────────────────────┘
//       │
//   ext-authz adapters / edge gateways (same environment)
//
// =============================================================================

const express = require('express');
const cors = require('cors');
const http = require('http');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const CONFIG = {
  port:              parseInt(process.env.PORT || '3005'),
  envName:           process.env.ENVIRONMENT_NAME || 'local',
  envType:           process.env.ENVIRONMENT_TYPE || 'docker',       // docker, eks, gke, aks, on-prem, vm
  region:            process.env.REGION || 'local',
  clusterId:         process.env.CLUSTER_ID || 'local-docker',

  // Central control plane
  centralUrl:        process.env.CENTRAL_CONTROL_PLANE_URL || '',    // e.g. https://wid-central.company.com
  centralApiKey:     process.env.CENTRAL_API_KEY || '',
  registrationUrl:   process.env.CENTRAL_REGISTRATION_URL || '',     // defaults to centralUrl + /api/v1/relay/register

  // Sync settings
  policySyncIntervalMs:  parseInt(process.env.POLICY_SYNC_INTERVAL_MS || '30000'),   // 30s default
  auditFlushIntervalMs:  parseInt(process.env.AUDIT_FLUSH_INTERVAL_MS || '10000'),   // 10s default
  auditBatchSize:        parseInt(process.env.AUDIT_BATCH_SIZE || '100'),
  healthReportIntervalMs: parseInt(process.env.HEALTH_REPORT_INTERVAL_MS || '60000'), // 1min

  // Local services (in this environment)
  localPolicyEngineUrl:  process.env.LOCAL_POLICY_ENGINE_URL || '',  // if empty, relay IS the policy source
  localAdapters:         (process.env.LOCAL_ADAPTERS || '').split(',').filter(Boolean),

  // Resilience
  maxAuditBufferSize:    parseInt(process.env.MAX_AUDIT_BUFFER_SIZE || '10000'),
  syncTimeoutMs:         parseInt(process.env.SYNC_TIMEOUT_MS || '5000'),
  retryBackoffMs:        parseInt(process.env.RETRY_BACKOFF_MS || '5000'),
};

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════

const state = {
  // Policy cache
  policies: [],
  policyVersion: 0,
  policyHash: '',
  lastPolicySyncAt: null,
  policySyncErrors: 0,

  // Audit buffer
  auditBuffer: [],
  auditFlushed: 0,
  auditDropped: 0,
  lastAuditFlushAt: null,

  // Registration
  registered: false,
  relayId: null,
  registeredAt: null,
  lastHeartbeatAt: null,

  // Local adapter tracking
  adapters: new Map(),   // adapterId → { lastSeen, metrics, health }

  // Relay health
  startedAt: new Date().toISOString(),
  centralReachable: false,
};

// ═══════════════════════════════════════════════════════════════
// HTTP Client Helper
// ═══════════════════════════════════════════════════════════════

function httpRequest(url, method, body, timeoutMs, extraHeaders) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method,
      timeout: timeoutMs || CONFIG.syncTimeoutMs,
      headers: {
        'Content-Type': 'application/json',
        ...(CONFIG.centralApiKey ? { 'Authorization': `Bearer ${CONFIG.centralApiKey}` } : {}),
        'X-WID-Relay-Id': state.relayId || CONFIG.envName,
        'X-WID-Environment': CONFIG.envName,
        ...(extraHeaders || {}),
      },
    };
    const req = transport.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function log(level, msg, meta = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level,
    service: 'wid-relay',
    env: CONFIG.envName,
    msg,
    ...meta,
  }));
}

// ═══════════════════════════════════════════════════════════════
// 1. REGISTRATION — announce this relay to central control plane
// ═══════════════════════════════════════════════════════════════

async function registerWithCentral() {
  if (!CONFIG.centralUrl) {
    log('info', 'No central control plane configured, running standalone');
    return;
  }

  const registrationUrl = CONFIG.registrationUrl || `${CONFIG.centralUrl}/api/v1/relay/register`;
  const payload = {
    environment_name: CONFIG.envName,
    environment_type: CONFIG.envType,
    region: CONFIG.region,
    cluster_id: CONFIG.clusterId,
    relay_version: '1.0.0',
    capabilities: ['policy-cache', 'audit-forward', 'health-report'],
    endpoint: `http://${CONFIG.envName}-relay:${CONFIG.port}`,  // how central can reach us (if needed)
    adapters: CONFIG.localAdapters,
    registered_at: new Date().toISOString(),
  };

  try {
    const res = await httpRequest(registrationUrl, 'POST', payload);
    if (res.status === 200 || res.status === 201) {
      state.registered = true;
      state.relayId = res.data?.relay_id || CONFIG.envName;
      state.registeredAt = new Date().toISOString();
      state.centralReachable = true;
      log('info', 'Registered with central control plane', {
        relayId: state.relayId,
        centralUrl: CONFIG.centralUrl,
      });
    } else {
      log('warn', 'Registration failed', { status: res.status, body: res.data });
    }
  } catch (e) {
    log('warn', 'Cannot reach central control plane', { error: e.message, url: registrationUrl });
    state.centralReachable = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// 2. POLICY SYNC — pull policies from central control plane
// ═══════════════════════════════════════════════════════════════

async function syncPolicies() {
  if (!CONFIG.centralUrl) return;

  const syncUrl = `${CONFIG.centralUrl}/api/v1/relay/policies?since_version=${state.policyVersion}&environment=${CONFIG.envName}`;

  try {
    const res = await httpRequest(syncUrl, 'GET', null);
    if (res.status === 200 && res.data?.policies) {
      const newVersion = res.data.version || state.policyVersion + 1;
      if (newVersion > state.policyVersion || res.data.force) {
        state.policies = res.data.policies;
        state.policyVersion = newVersion;
        state.policyHash = res.data.hash || '';
        state.lastPolicySyncAt = new Date().toISOString();
        state.policySyncErrors = 0;
        state.centralReachable = true;

        log('info', 'Policy sync complete', {
          version: newVersion,
          policyCount: state.policies.length,
          hash: state.policyHash,
        });
      }
    } else if (res.status === 304) {
      // Not modified — our policies are current
      state.lastPolicySyncAt = new Date().toISOString();
      state.centralReachable = true;
    }
  } catch (e) {
    state.policySyncErrors++;
    state.centralReachable = false;
    log('warn', 'Policy sync failed', {
      error: e.message,
      consecutiveErrors: state.policySyncErrors,
      cachedPolicyCount: state.policies.length,
    });
  }
}

// ═══════════════════════════════════════════════════════════════
// 3. AUDIT FORWARDING — batch push audit events to central
// ═══════════════════════════════════════════════════════════════

function bufferAuditEvent(event) {
  if (state.auditBuffer.length >= CONFIG.maxAuditBufferSize) {
    state.auditDropped++;
    return false;
  }
  state.auditBuffer.push({
    ...event,
    relay_id: state.relayId,
    relay_env: CONFIG.envName,
    relay_region: CONFIG.region,
    buffered_at: new Date().toISOString(),
  });
  return true;
}

async function flushAuditBuffer() {
  if (state.auditBuffer.length === 0) return;

  const batch = state.auditBuffer.splice(0, CONFIG.auditBatchSize);

  // Spoke relays flush to central relay; hub relays flush to local policy engine (DB writer)
  let flushUrl;
  if (CONFIG.centralUrl) {
    flushUrl = `${CONFIG.centralUrl}/api/v1/relay/audit/batch`;
  } else if (POLICY_ENGINE_URL) {
    flushUrl = `${POLICY_ENGINE_URL}/api/v1/access/decisions/batch`;
  } else {
    // No destination — put back
    state.auditBuffer.unshift(...batch);
    return;
  }

  const body = CONFIG.centralUrl
    ? { relay_id: state.relayId, environment: CONFIG.envName, entries: batch }
    : { entries: batch };

  try {
    const res = await httpRequest(flushUrl, 'POST', body);

    if (res.status === 200 || res.status === 201) {
      state.auditFlushed += batch.length;
      state.lastAuditFlushAt = new Date().toISOString();
      state.centralReachable = true;
      log('debug', 'Audit batch flushed', { count: batch.length, total: state.auditFlushed, dest: CONFIG.centralUrl ? 'central' : 'policy-engine' });
    } else {
      // Put back on failure
      state.auditBuffer.unshift(...batch);
      log('warn', 'Audit flush failed', { status: res.status, dest: flushUrl });
    }
  } catch (e) {
    // Put back on failure
    state.auditBuffer.unshift(...batch);
    state.centralReachable = false;
    log('warn', 'Audit flush error', { error: e.message, buffered: state.auditBuffer.length });
  }
}

// ═══════════════════════════════════════════════════════════════
// 4. HEALTH REPORTING — periodic heartbeat to central
// ═══════════════════════════════════════════════════════════════

async function reportHealth() {
  if (!CONFIG.centralUrl || !state.registered) return;

  const healthUrl = `${CONFIG.centralUrl}/api/v1/relay/heartbeat`;
  const payload = {
    relay_id: state.relayId,
    environment: CONFIG.envName,
    status: 'healthy',
    uptime_seconds: Math.round((Date.now() - new Date(state.startedAt).getTime()) / 1000),
    policy_version: state.policyVersion,
    policy_count: state.policies.length,
    last_policy_sync: state.lastPolicySyncAt,
    audit_buffer_size: state.auditBuffer.length,
    audit_flushed_total: state.auditFlushed,
    audit_dropped_total: state.auditDropped,
    adapters: Object.fromEntries(state.adapters),
    timestamp: new Date().toISOString(),
  };

  try {
    await httpRequest(healthUrl, 'POST', payload);
    state.lastHeartbeatAt = new Date().toISOString();
    state.centralReachable = true;
  } catch (e) {
    state.centralReachable = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// API ENDPOINTS — served to LOCAL adapters in this environment
// ═══════════════════════════════════════════════════════════════

// ── Health ──
app.get('/health', (req, res) => {
  res.json({
    service: 'wid-relay',
    status: 'healthy',
    environment: CONFIG.envName,
    environment_type: CONFIG.envType,
    region: CONFIG.region,
    relay_id: state.relayId,
    central_reachable: state.centralReachable,
    central_url: CONFIG.centralUrl || 'none (standalone)',
    registered: state.registered,
    policy_version: state.policyVersion,
    policy_count: state.policies.length,
    audit_buffered: state.auditBuffer.length,
    uptime: Math.round((Date.now() - new Date(state.startedAt).getTime()) / 1000),
  });
});

// ── Policy evaluation (called by local adapters instead of central policy engine) ──
app.post('/api/v1/access/evaluate/principal', (req, res) => {
  const { source_principal, destination_principal, source_name, destination_name,
          method, path_pattern, decision_id, adapter_mode } = req.body;

  // If we have a local policy engine, proxy to it
  if (CONFIG.localPolicyEngineUrl) {
    return proxyToLocalPolicyEngine(req, res);
  }

  // Otherwise, evaluate against cached policies
  const matchedPolicy = evaluateCachedPolicies(req.body);

  const verdict = matchedPolicy ? (matchedPolicy.effect === 'allow' ? 'granted' : 'denied') : 'no-match';

  res.json({
    decision_id,
    verdict,
    allowed: verdict === 'granted',
    policy_name: matchedPolicy?.name || null,
    scopes: matchedPolicy?.scopes || [],
    ttl: matchedPolicy?.ttl || 300,
    relay: CONFIG.envName,
    policy_version: state.policyVersion,
  });
});

function evaluateCachedPolicies(request) {
  // Simple matcher against cached policies
  for (const policy of state.policies) {
    if (!policy.enabled) continue;

    // Match by source/destination patterns
    const srcMatch = !policy.source_match || matchWorkload(request.source_principal, request.source_name, policy.source_match);
    const dstMatch = !policy.destination_match || matchWorkload(request.destination_principal, request.destination_name, policy.destination_match);

    if (srcMatch && dstMatch) {
      return policy;
    }
  }
  return null;
}

function matchWorkload(principal, name, pattern) {
  if (pattern === '*') return true;
  if (principal && principal.includes(pattern)) return true;
  if (name && name.includes(pattern)) return true;
  return false;
}

function proxyToLocalPolicyEngine(req, res) {
  const url = `${CONFIG.localPolicyEngineUrl}/api/v1/access/evaluate/principal`;
  httpRequest(url, 'POST', req.body, CONFIG.syncTimeoutMs)
    .then(result => res.status(result.status).json(result.data))
    .catch(e => {
      // Fallback to cached policies if local engine is down
      log('warn', 'Local policy engine unreachable, using cached policies', { error: e.message });
      const matchedPolicy = evaluateCachedPolicies(req.body);
      const verdict = matchedPolicy ? (matchedPolicy.effect === 'allow' ? 'granted' : 'denied') : 'no-match';
      res.json({ decision_id: req.body.decision_id, verdict, allowed: verdict === 'granted', fallback: 'cached-policies' });
    });
}

// ── Receive audit events from local adapters ──
app.post('/api/v1/access/decisions/batch', (req, res) => {
  const entries = req.body?.entries || req.body?.decisions || req.body;
  if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries array required' });

  let accepted = 0;
  for (const entry of entries) {
    if (bufferAuditEvent(entry)) accepted++;
  }
  res.json({ accepted, total: entries.length, buffered: state.auditBuffer.length });
});

// ── Single audit event ──
app.post('/api/v1/access/decisions', (req, res) => {
  bufferAuditEvent(req.body);
  res.json({ accepted: 1, buffered: state.auditBuffer.length });
});

// ── Adapter registration (local adapters announce themselves) ──
app.post('/api/v1/relay/adapter/register', (req, res) => {
  const { adapter_id, adapter_type, endpoint } = req.body;
  state.adapters.set(adapter_id || `adapter-${state.adapters.size}`, {
    type: adapter_type || 'ext-authz',
    endpoint,
    registered_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
  });
  log('info', 'Adapter registered', { adapter_id, adapter_type, totalAdapters: state.adapters.size });
  res.json({ status: 'registered', relay_id: state.relayId, environment: CONFIG.envName });
});

// ── Adapter heartbeat ──
app.post('/api/v1/relay/adapter/heartbeat', (req, res) => {
  const { adapter_id, metrics } = req.body;
  const adapter = state.adapters.get(adapter_id);
  if (adapter) {
    adapter.last_seen = new Date().toISOString();
    adapter.metrics = metrics;
  }
  res.json({ status: 'ok' });
});

// ── Get cached policies (for adapters that want to pull directly) ──
app.get('/api/v1/relay/policies', (req, res) => {
  res.json({
    environment: CONFIG.envName,
    version: state.policyVersion,
    hash: state.policyHash,
    policies: state.policies,
    synced_at: state.lastPolicySyncAt,
    central_reachable: state.centralReachable,
  });
});

// ── Force policy sync ──
app.post('/api/v1/relay/sync', async (req, res) => {
  log('info', 'Manual policy sync triggered');
  await syncPolicies();
  res.json({
    version: state.policyVersion,
    policy_count: state.policies.length,
    synced_at: state.lastPolicySyncAt,
  });
});

// ── Relay status (detailed) ──
app.get('/api/v1/relay/status', (req, res) => {
  res.json({
    relay_id: state.relayId,
    environment: { name: CONFIG.envName, type: CONFIG.envType, region: CONFIG.region, cluster: CONFIG.clusterId },
    central: { url: CONFIG.centralUrl || 'none', reachable: state.centralReachable, registered: state.registered },
    policies: { version: state.policyVersion, count: state.policies.length, hash: state.policyHash, last_sync: state.lastPolicySyncAt, sync_errors: state.policySyncErrors },
    audit: { buffered: state.auditBuffer.length, flushed_total: state.auditFlushed, dropped_total: state.auditDropped, last_flush: state.lastAuditFlushAt },
    adapters: Object.fromEntries(state.adapters),
    uptime_seconds: Math.round((Date.now() - new Date(state.startedAt).getTime()) / 1000),
  });
});

// ── Metrics (Prometheus format) ──
app.get('/metrics', (req, res) => {
  res.json({
    environment: CONFIG.envName,
    policies: { version: state.policyVersion, count: state.policies.length, sync_errors: state.policySyncErrors },
    audit: { buffered: state.auditBuffer.length, flushed: state.auditFlushed, dropped: state.auditDropped },
    central: { reachable: state.centralReachable, registered: state.registered },
    adapters: state.adapters.size,
  });
});

// ═══════════════════════════════════════════════════════════════
// CENTRAL CONTROL PLANE ENDPOINTS
// These are added to the policy engine to support relay federation
// ═══════════════════════════════════════════════════════════════
// When this relay IS the central (running alongside the policy engine),
// it also serves these endpoints for other relays to connect to.

const relayRegistry = new Map();  // relayId → { env, region, lastHeartbeat, ... }

app.post('/api/v1/relay/register', (req, res) => {
  const { environment_name, environment_type, region, cluster_id, relay_version } = req.body;
  const relayId = `relay-${environment_name}-${Date.now().toString(36)}`;
  relayRegistry.set(relayId, {
    environment_name, environment_type, region, cluster_id, relay_version,
    registered_at: new Date().toISOString(),
    last_heartbeat: new Date().toISOString(),
    status: 'active',
  });
  log('info', 'Relay registered', { relayId, environment_name, region });
  res.json({ relay_id: relayId, status: 'registered' });
});

app.post('/api/v1/relay/heartbeat', (req, res) => {
  const { relay_id } = req.body;
  const relay = relayRegistry.get(relay_id);
  if (relay) {
    relay.last_heartbeat = new Date().toISOString();
    relay.status = 'active';
    relay.latest_report = req.body;
  }
  res.json({ status: 'ok' });
});

app.get('/api/v1/relay/policies', (req, res) => {
  // Return policies for relays to sync
  // In production, filter by environment/region if needed
  res.json({
    version: state.policyVersion,
    hash: state.policyHash,
    policies: state.policies,
    synced_at: new Date().toISOString(),
  });
});

app.post('/api/v1/relay/audit/batch', (req, res) => {
  const { relay_id, environment, entries } = req.body;
  // Buffer for storage (in production, write to DB or forward to audit service)
  let accepted = 0;
  if (Array.isArray(entries)) {
    for (const entry of entries) {
      bufferAuditEvent({ ...entry, source_relay: relay_id, source_environment: environment });
      accepted++;
    }
  }
  log('debug', 'Received audit batch from relay', { relay_id, environment, count: accepted });
  res.json({ accepted, total: entries?.length || 0 });
});

// ── List all connected relays (for web UI) ──
app.get('/api/v1/relay/environments', (req, res) => {
  const environments = [];
  for (const [id, relay] of relayRegistry) {
    environments.push({ relay_id: id, ...relay });
  }
  // Include self
  environments.unshift({
    relay_id: state.relayId || 'self',
    environment_name: CONFIG.envName,
    environment_type: CONFIG.envType,
    region: CONFIG.region,
    status: 'active',
    is_central: true,
    policy_count: state.policies.length,
    adapter_count: state.adapters.size,
  });
  res.json({ total: environments.length, environments });
});

// ═══════════════════════════════════════════════════════════════
// EDGE GATEWAY — Real HTTP Proxy with Policy Enforcement
//
// This is the actual enforcement point. Requests flow:
//   Client → Edge Gateway (this endpoint) → Policy Eval → Forward/Reject
//
// On ALLOW: forwards request to destination, injects identity headers
// On DENY:  returns HTTP 403 with decision reference
// ═══════════════════════════════════════════════════════════════

const POLICY_ENGINE_URL = process.env.POLICY_ENGINE_URL || process.env.LOCAL_POLICY_ENGINE_URL || '';

app.all('/gateway/proxy', async (req, res) => {
  const source = req.headers['x-wid-source'] || req.headers['x-source-workload'] || 'unknown';
  const destination = req.headers['x-wid-destination'] || req.headers['x-destination-workload'];
  const targetUrl = req.headers['x-wid-target-url'] || req.headers['x-target-url'];
  const traceId = req.headers['x-wid-trace-id'] || null;

  if (!destination && !targetUrl) {
    return res.status(400).json({ error: 'x-wid-destination or x-wid-target-url header required' });
  }

  const gwStart = Date.now();

  // ── Step 1: Evaluate policy ──
  let evalResult;
  try {
    const evalUrl = POLICY_ENGINE_URL
      ? `${POLICY_ENGINE_URL}/api/v1/gateway/evaluate`
      : null;

    if (evalUrl) {
      const result = await httpRequest(evalUrl, 'POST', {
        source, destination: destination || targetUrl,
        method: req.method, path: req.path,
        headers: { 'user-agent': req.headers['user-agent'] },
        context: { trace_id: traceId },
      }, CONFIG.syncTimeoutMs);
      evalResult = result.data;
    } else {
      // Local evaluation from cached policies
      const matchedPolicy = evaluateCachedPolicies({
        source_name: source, destination_name: destination,
        method: req.method, path_pattern: req.path,
      });
      evalResult = {
        verdict: matchedPolicy ? (matchedPolicy.effect === 'allow' ? 'allow' : 'deny') : 'deny',
        decision_id: `local-${Date.now()}`,
        policy_name: matchedPolicy?.name || null,
        enforcement_action: matchedPolicy?.effect === 'allow' ? 'FORWARD_REQUEST' : 'REJECT_REQUEST',
      };
    }
  } catch (e) {
    log('error', 'Policy evaluation failed', { error: e.message, source, destination });
    // Fail-closed: deny on eval failure
    return res.status(503).json({
      error: 'Policy evaluation unavailable',
      enforcement_action: 'REJECT_REQUEST',
      detail: 'Edge gateway could not reach policy engine. Fail-closed under zero-trust.',
    });
  }

  // ── Step 2: Enforce verdict ──
  if (evalResult.verdict !== 'allow') {
    // DENY — Return 403
    log('warn', 'GATEWAY DENY', {
      source, destination, method: req.method,
      policy: evalResult.policy_name, decision_id: evalResult.decision_id,
    });
    return res.status(403).json({
      error: 'Access Denied',
      enforcement_action: 'REJECT_REQUEST',
      decision_id: evalResult.decision_id,
      policy_name: evalResult.policy_name,
      reason: evalResult.reason || 'Request denied by policy',
      source, destination,
      gateway: CONFIG.envName,
      detail: `Edge gateway rejected ${req.method} from ${source} to ${destination}. ${evalResult.reason || 'No matching allow policy.'}`,
    });
  }

  // ── Step 3: ALLOW — Forward request ──
  if (!targetUrl) {
    // No target URL to proxy to — return the allow decision
    log('info', 'GATEWAY ALLOW (no proxy target)', {
      source, destination, decision_id: evalResult.decision_id,
    });
    return res.json({
      enforcement_action: 'FORWARD_REQUEST',
      decision_id: evalResult.decision_id,
      policy_name: evalResult.policy_name,
      source, destination,
      gateway: CONFIG.envName,
      detail: `Edge gateway permitted ${req.method} from ${source} to ${destination}. Policy: ${evalResult.policy_name || 'matched'}.`,
      headers_injected: {
        'X-WID-Decision': evalResult.decision_id,
        'X-WID-Source-Identity': source,
        'X-WID-Enforcement': 'allow',
        'X-WID-Gateway': CONFIG.envName,
      },
    });
  }

  // Proxy the actual request to target URL
  try {
    const proxyResult = await httpRequest(targetUrl, req.method, req.body, 15000, {
      'X-WID-Decision': evalResult.decision_id,
      'X-WID-Source-Identity': source,
      'X-WID-Enforcement': 'allow',
      'X-WID-Gateway': CONFIG.envName,
      'X-WID-Trace-Id': traceId || '',
    });

    const gwLatency = Date.now() - gwStart;
    log('info', 'GATEWAY FORWARD', {
      source, destination, target: targetUrl,
      status: proxyResult.status, latency_ms: gwLatency,
      decision_id: evalResult.decision_id,
    });

    // Forward response headers and body
    res.status(proxyResult.status).json({
      ...proxyResult.data,
      _gateway: {
        enforcement_action: 'FORWARD_REQUEST',
        decision_id: evalResult.decision_id,
        policy_name: evalResult.policy_name,
        latency_ms: gwLatency,
        source, destination,
      },
    });
  } catch (e) {
    log('error', 'GATEWAY FORWARD FAILED', { target: targetUrl, error: e.message });
    res.status(502).json({
      error: 'Bad Gateway',
      enforcement_action: 'FORWARD_FAILED',
      detail: `Policy allowed but upstream ${targetUrl} unreachable: ${e.message}`,
      decision_id: evalResult.decision_id,
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// JIT CREDENTIAL ENDPOINT — Short-lived, scoped credential issuance
//
// Agents/workloads request credentials for external APIs through
// the gateway instead of holding static keys. The gateway:
//   1. Evaluates policy (is this workload allowed to access this API?)
//   2. Issues a scoped, time-bound credential
//   3. Logs the issuance for audit
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');

// In-memory credential store (production: use Vault/KMS)
const issuedCredentials = new Map();

app.post('/api/v1/credentials/request', async (req, res) => {
  const { workload, target_api, scopes, ttl_seconds } = req.body;
  if (!workload || !target_api) {
    return res.status(400).json({ error: 'workload and target_api required' });
  }

  const requestedTtl = Math.min(ttl_seconds || 300, 3600); // max 1 hour
  const requestedScopes = scopes || ['read'];
  const credentialId = `cred-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  // ── Step 1: Policy evaluation — is this workload allowed to get credentials for this API? ──
  let evalResult = { verdict: 'deny' };
  try {
    if (POLICY_ENGINE_URL) {
      const result = await httpRequest(`${POLICY_ENGINE_URL}/api/v1/gateway/evaluate`, 'POST', {
        source: workload, destination: 'jit-credential-vault',
        method: 'POST', path: `/credentials/${target_api}`,
        context: { credential_request: true, target_api, scopes: requestedScopes },
      }, CONFIG.syncTimeoutMs);
      evalResult = result.data;
    }
  } catch (e) {
    return res.status(503).json({ error: 'Policy evaluation failed', detail: e.message });
  }

  if (evalResult.verdict !== 'allow') {
    log('warn', 'JIT CREDENTIAL DENIED', { workload, target_api, decision: evalResult.decision_id });
    return res.status(403).json({
      error: 'Credential request denied',
      enforcement_action: 'REJECT_CREDENTIAL',
      decision_id: evalResult.decision_id,
      policy_name: evalResult.policy_name,
      reason: evalResult.reason || 'Policy does not allow this workload to access this API',
      workload, target_api,
    });
  }

  // ── Step 2: Issue JIT credential ──
  const expiresAt = new Date(Date.now() + requestedTtl * 1000).toISOString();
  const credential = {
    credential_id: credentialId,
    type: 'jit-bearer-token',
    token: `wid_jit_${crypto.randomBytes(32).toString('base64url')}`,
    workload,
    target_api,
    scopes: requestedScopes,
    issued_at: new Date().toISOString(),
    expires_at: expiresAt,
    ttl_seconds: requestedTtl,
    policy_decision_id: evalResult.decision_id,
    policy_name: evalResult.policy_name,
    issuer: `wid-gateway-${CONFIG.envName}`,
  };

  issuedCredentials.set(credentialId, credential);

  // Auto-expire
  setTimeout(() => issuedCredentials.delete(credentialId), requestedTtl * 1000);

  log('info', 'JIT CREDENTIAL ISSUED', {
    credential_id: credentialId, workload, target_api,
    scopes: requestedScopes, ttl: requestedTtl,
    decision_id: evalResult.decision_id,
  });

  res.status(201).json({
    credential_id: credentialId,
    enforcement_action: 'ISSUE_CREDENTIAL',
    type: 'jit-bearer-token',
    token: credential.token,
    target_api,
    scopes: requestedScopes,
    expires_at: expiresAt,
    ttl_seconds: requestedTtl,
    policy_decision_id: evalResult.decision_id,
    detail: `JIT credential issued for ${workload} to access ${target_api}. Scopes: ${requestedScopes.join(',')}. Expires: ${expiresAt}.`,
  });
});

// ── Validate a JIT credential (target API calls this to verify) ──
app.post('/api/v1/credentials/validate', (req, res) => {
  const { token, target_api } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });

  for (const [id, cred] of issuedCredentials) {
    if (cred.token === token) {
      if (new Date(cred.expires_at) < new Date()) {
        issuedCredentials.delete(id);
        return res.json({ valid: false, reason: 'expired', credential_id: id });
      }
      if (target_api && cred.target_api !== target_api) {
        return res.json({ valid: false, reason: 'wrong_audience', credential_id: id, expected: cred.target_api });
      }
      return res.json({
        valid: true, credential_id: id, workload: cred.workload,
        target_api: cred.target_api, scopes: cred.scopes,
        expires_at: cred.expires_at, issued_at: cred.issued_at,
      });
    }
  }
  res.json({ valid: false, reason: 'not_found' });
});

// ── List active JIT credentials (admin/debug) ──
app.get('/api/v1/credentials/active', (req, res) => {
  const active = [];
  for (const [id, cred] of issuedCredentials) {
    if (new Date(cred.expires_at) > new Date()) {
      active.push({ credential_id: id, workload: cred.workload, target_api: cred.target_api,
        scopes: cred.scopes, expires_at: cred.expires_at, ttl_remaining_s: Math.round((new Date(cred.expires_at) - new Date()) / 1000) });
    }
  }
  res.json({ total: active.length, credentials: active });
});

// ═══════════════════════════════════════════════════════════════
// OBO DELEGATION — On-Behalf-Of Token Chain
//
// Implements scope-ceiling delegation:
//   User (full scope) → Agent (scoped) → MCP (further scoped)
//
// Each hop reduces available scopes. No hop can exceed its parent's ceiling.
// ═══════════════════════════════════════════════════════════════

const delegationChains = new Map(); // chain_id → { hops, root_scope, ... }

app.post('/api/v1/delegation/initiate', async (req, res) => {
  const { principal, target, scopes, context } = req.body;
  if (!principal || !target) return res.status(400).json({ error: 'principal and target required' });

  const chainId = `chain-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const rootScopes = scopes || ['read', 'write', 'admin'];

  // Evaluate policy
  let evalResult = { verdict: 'deny' };
  try {
    if (POLICY_ENGINE_URL) {
      const result = await httpRequest(`${POLICY_ENGINE_URL}/api/v1/gateway/evaluate`, 'POST', {
        source: principal, destination: target, method: 'POST', path: '/delegation',
      }, CONFIG.syncTimeoutMs);
      evalResult = result.data;
    }
  } catch (e) {
    return res.status(503).json({ error: 'Policy evaluation failed' });
  }

  if (evalResult.verdict !== 'allow') {
    return res.status(403).json({
      error: 'Delegation denied', enforcement_action: 'REJECT_DELEGATION',
      decision_id: evalResult.decision_id, principal, target,
    });
  }

  const token = `wid_obo_${crypto.randomBytes(32).toString('base64url')}`;
  const expiresAt = new Date(Date.now() + 300000).toISOString(); // 5 min

  const chain = {
    chain_id: chainId, root_principal: principal,
    scope_ceiling: rootScopes, current_scopes: rootScopes,
    hops: [{
      hop: 0, from: principal, to: target, token,
      scopes: rootScopes, granted_at: new Date().toISOString(), expires_at: expiresAt,
      decision_id: evalResult.decision_id,
    }],
    created_at: new Date().toISOString(),
  };

  delegationChains.set(chainId, chain);
  setTimeout(() => delegationChains.delete(chainId), 600000); // cleanup after 10 min

  log('info', 'OBO DELEGATION INITIATED', { chain_id: chainId, principal, target, scopes: rootScopes });

  res.status(201).json({
    chain_id: chainId, enforcement_action: 'INITIATE_DELEGATION',
    token, scopes: rootScopes, expires_at: expiresAt,
    scope_ceiling: rootScopes, hop: 0,
    detail: `Delegation chain initiated: ${principal} delegates to ${target} with scopes [${rootScopes.join(',')}].`,
  });
});

app.post('/api/v1/delegation/extend', async (req, res) => {
  const { chain_id, token, target, requested_scopes } = req.body;
  if (!chain_id || !token || !target) {
    return res.status(400).json({ error: 'chain_id, token, and target required' });
  }

  const chain = delegationChains.get(chain_id);
  if (!chain) return res.status(404).json({ error: 'Delegation chain not found or expired' });

  // Verify token matches the last hop
  const lastHop = chain.hops[chain.hops.length - 1];
  if (lastHop.token !== token) {
    return res.status(403).json({ error: 'Invalid delegation token' });
  }
  if (new Date(lastHop.expires_at) < new Date()) {
    return res.status(403).json({ error: 'Delegation token expired' });
  }

  // Scope ceiling enforcement: requested scopes must be subset of current
  const effectiveScopes = (requested_scopes || lastHop.scopes)
    .filter(s => chain.current_scopes.includes(s));

  if (effectiveScopes.length === 0) {
    return res.status(403).json({
      error: 'Scope ceiling exceeded',
      enforcement_action: 'REJECT_DELEGATION',
      detail: `Requested scopes [${(requested_scopes||[]).join(',')}] exceed ceiling [${chain.current_scopes.join(',')}].`,
      scope_ceiling: chain.current_scopes,
    });
  }

  // Evaluate policy for this hop
  let evalResult = { verdict: 'allow', decision_id: 'local' };
  try {
    if (POLICY_ENGINE_URL) {
      const result = await httpRequest(`${POLICY_ENGINE_URL}/api/v1/gateway/evaluate`, 'POST', {
        source: lastHop.to, destination: target, method: 'POST', path: '/delegation',
      }, CONFIG.syncTimeoutMs);
      evalResult = result.data;
    }
  } catch (e) { /* continue with local allow */ }

  if (evalResult.verdict !== 'allow') {
    return res.status(403).json({
      error: 'Delegation hop denied', enforcement_action: 'REJECT_DELEGATION',
      decision_id: evalResult.decision_id, from: lastHop.to, to: target,
    });
  }

  const newToken = `wid_obo_${crypto.randomBytes(32).toString('base64url')}`;
  const expiresAt = new Date(Date.now() + 300000).toISOString();
  const hopNum = chain.hops.length;

  chain.hops.push({
    hop: hopNum, from: lastHop.to, to: target, token: newToken,
    scopes: effectiveScopes, parent_scopes: lastHop.scopes,
    granted_at: new Date().toISOString(), expires_at: expiresAt,
    decision_id: evalResult.decision_id,
  });
  chain.current_scopes = effectiveScopes;

  log('info', 'OBO DELEGATION EXTENDED', {
    chain_id: chain_id, hop: hopNum, from: lastHop.to, to: target,
    scopes: effectiveScopes, ceiling: chain.scope_ceiling,
  });

  res.status(201).json({
    chain_id, enforcement_action: 'EXTEND_DELEGATION',
    token: newToken, scopes: effectiveScopes, expires_at: expiresAt,
    scope_ceiling: chain.scope_ceiling, hop: hopNum,
    detail: `Delegation extended: ${lastHop.to} delegates to ${target} with scopes [${effectiveScopes.join(',')}]. Ceiling: [${chain.scope_ceiling.join(',')}].`,
  });
});

// ── Inspect a delegation chain ──
app.get('/api/v1/delegation/chains/:chainId', (req, res) => {
  const chain = delegationChains.get(req.params.chainId);
  if (!chain) return res.status(404).json({ error: 'Chain not found or expired' });
  res.json({
    chain_id: chain.chain_id, root_principal: chain.root_principal,
    scope_ceiling: chain.scope_ceiling, current_scopes: chain.current_scopes,
    total_hops: chain.hops.length, created_at: chain.created_at,
    hops: chain.hops.map(h => ({
      hop: h.hop, from: h.from, to: h.to, scopes: h.scopes,
      granted_at: h.granted_at, expires_at: h.expires_at,
      decision_id: h.decision_id,
    })),
  });
});

// ── List active delegation chains ──
app.get('/api/v1/delegation/chains', (req, res) => {
  const chains = [];
  for (const [id, chain] of delegationChains) {
    chains.push({
      chain_id: id, root_principal: chain.root_principal,
      scope_ceiling: chain.scope_ceiling, current_scopes: chain.current_scopes,
      total_hops: chain.hops.length, created_at: chain.created_at,
    });
  }
  res.json({ total: chains.length, chains });
});

// ═══════════════════════════════════════════════════════════════
// Gateway Install Script Generator — for customer enforcement setup
// ═══════════════════════════════════════════════════════════════

app.get('/api/v1/install/:envName', (req, res) => {
  const envName = req.params.envName || 'customer-env';
  const method = req.query.method || 'docker';
  const centralUrl = CONFIG.centralUrl || `http://${req.hostname}:${CONFIG.port}`;
  // One-time token for gateway registration (short-lived)
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('hex');

  if (method === 'docker') {
    const script = `#!/usr/bin/env bash
# =============================================================================
# WID Edge Gateway — Docker Install (${envName})
# Generated by WID Platform
# =============================================================================
set -euo pipefail

ENV_NAME="${envName}"
CENTRAL_URL="${centralUrl}"
REG_TOKEN="${token}"

echo "Installing WID Edge Gateway for environment: \$ENV_NAME"
echo "Central: \$CENTRAL_URL"
echo ""

# Create docker-compose for relay + gateway
mkdir -p wid-gateway && cat > wid-gateway/docker-compose.yml <<'COMPOSE'
version: "3.8"
services:
  relay:
    image: us-central1-docker.pkg.dev/wid-platform/wid-services/relay-service:latest
    ports:
      - "3005:3005"
    environment:
      PORT: "3005"
      ENVIRONMENT_NAME: "${envName}"
      ENVIRONMENT_TYPE: "customer"
      CENTRAL_CONTROL_PLANE_URL: "${centralUrl}"
      REGISTRATION_TOKEN: "${token}"
      POLICY_SYNC_INTERVAL_MS: "15000"
      AUDIT_FLUSH_INTERVAL_MS: "5000"
      HEALTH_REPORT_INTERVAL_MS: "60000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:3005/health"]
      interval: 30s
      timeout: 5s
      retries: 3

  edge-gateway:
    image: us-central1-docker.pkg.dev/wid-platform/wid-services/edge-gateway:latest
    ports:
      - "15001:15001"
      - "15000:15000"
    environment:
      GATEWAY_ID: "${envName}-gw"
      WORKLOAD_NAME: "${envName}"
      POLICY_SERVICE_URL: "http://relay:3005"
      TOKEN_SERVICE_URL: "http://relay:3005"
      BROKER_URL: "http://relay:3005"
      DEFAULT_MODE: "audit"
      FAIL_BEHAVIOR: "open"
      OUTBOUND_PORT: "15001"
      ADMIN_PORT: "15000"
    depends_on:
      relay:
        condition: service_healthy
    restart: unless-stopped
COMPOSE

cd wid-gateway
echo "Starting WID relay and edge gateway..."
docker compose up -d

echo ""
echo "WID Edge Gateway installed and running."
echo "  Relay:    http://localhost:3005/health"
echo "  Gateway:  http://localhost:15000/metrics"
echo "  Central:  \$CENTRAL_URL"
`;
    res.setHeader('Content-Type', 'text/plain');
    return res.send(script);
  }

  if (method === 'kubernetes') {
    const manifest = `# WID Edge Gateway — Kubernetes Install (${envName})
# Apply: kubectl apply -f wid-gateway.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: wid-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wid-relay
  namespace: wid-system
  labels:
    app: wid-relay
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wid-relay
  template:
    metadata:
      labels:
        app: wid-relay
    spec:
      containers:
        - name: relay
          image: us-central1-docker.pkg.dev/wid-platform/wid-services/relay-service:latest
          ports:
            - containerPort: 3005
          env:
            - name: PORT
              value: "3005"
            - name: ENVIRONMENT_NAME
              value: "${envName}"
            - name: ENVIRONMENT_TYPE
              value: "customer"
            - name: CENTRAL_CONTROL_PLANE_URL
              value: "${centralUrl}"
            - name: REGISTRATION_TOKEN
              value: "${token}"
            - name: POLICY_SYNC_INTERVAL_MS
              value: "15000"
          livenessProbe:
            httpGet:
              path: /health
              port: 3005
            initialDelaySeconds: 10
            periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: wid-relay
  namespace: wid-system
spec:
  selector:
    app: wid-relay
  ports:
    - port: 3005
      targetPort: 3005
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wid-edge-gateway
  namespace: wid-system
  labels:
    app: wid-edge-gateway
spec:
  selector:
    matchLabels:
      app: wid-edge-gateway
  template:
    metadata:
      labels:
        app: wid-edge-gateway
    spec:
      containers:
        - name: gateway
          image: us-central1-docker.pkg.dev/wid-platform/wid-services/edge-gateway:latest
          ports:
            - containerPort: 15001
            - containerPort: 15000
          env:
            - name: GATEWAY_ID
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: POLICY_SERVICE_URL
              value: "http://wid-relay.wid-system.svc:3005"
            - name: TOKEN_SERVICE_URL
              value: "http://wid-relay.wid-system.svc:3005"
            - name: BROKER_URL
              value: "http://wid-relay.wid-system.svc:3005"
            - name: DEFAULT_MODE
              value: "audit"
            - name: FAIL_BEHAVIOR
              value: "open"
`;
    res.setHeader('Content-Type', 'text/plain');
    return res.send(manifest);
  }

  if (method === 'cloudrun') {
    const script = `#!/usr/bin/env bash
# WID Edge Gateway — Cloud Run Install (${envName})
set -euo pipefail

PROJECT_ID="\${1:?Usage: $0 <GCP_PROJECT_ID>}"
REGION="\${2:-us-central1}"
CENTRAL_URL="${centralUrl}"
ENV_NAME="${envName}"

echo "Deploying WID relay and gateway to Cloud Run..."

# Deploy relay
gcloud run deploy wid-relay \\
  --project="\$PROJECT_ID" \\
  --region="\$REGION" \\
  --image=us-central1-docker.pkg.dev/wid-platform/wid-services/relay-service:latest \\
  --port=3005 \\
  --set-env-vars="ENVIRONMENT_NAME=\$ENV_NAME,ENVIRONMENT_TYPE=customer,CENTRAL_CONTROL_PLANE_URL=\$CENTRAL_URL,REGISTRATION_TOKEN=${token}" \\
  --ingress=internal \\
  --allow-unauthenticated \\
  --min-instances=1 \\
  --max-instances=3

echo "WID relay deployed. Gateway can be added as a sidecar or separate service."
`;
    res.setHeader('Content-Type', 'text/plain');
    return res.send(script);
  }

  res.status(400).json({ error: 'Unsupported method. Use: docker, kubernetes, or cloudrun' });
});

// ═══════════════════════════════════════════════════════════════
// Startup
// ═══════════════════════════════════════════════════════════════

async function start() {
  log('info', 'Starting WID Relay', {
    environment: CONFIG.envName,
    type: CONFIG.envType,
    region: CONFIG.region,
    central: CONFIG.centralUrl || 'standalone',
    port: CONFIG.port,
  });

  // Register with central
  await registerWithCentral();

  // Initial policy sync
  await syncPolicies();

  // Start periodic tasks
  setInterval(syncPolicies, CONFIG.policySyncIntervalMs);
  setInterval(flushAuditBuffer, CONFIG.auditFlushIntervalMs);
  setInterval(reportHealth, CONFIG.healthReportIntervalMs);

  // Start HTTP server
  app.listen(CONFIG.port, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║  WID Relay — Hub & Spoke Federation                         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Environment:  ${(CONFIG.envName + ' (' + CONFIG.envType + ')').padEnd(42)}║
║  Region:       ${CONFIG.region.padEnd(42)}║
║  Cluster:      ${CONFIG.clusterId.padEnd(42)}║
║  Central:      ${(CONFIG.centralUrl || 'standalone').padEnd(42)}║
║  Registered:   ${String(state.registered).padEnd(42)}║
║  Port:         ${String(CONFIG.port).padEnd(42)}║
║                                                              ║
║  Endpoints for local adapters:                               ║
║    POST /api/v1/access/evaluate/principal  (policy eval)     ║
║    POST /api/v1/access/decisions/batch     (audit events)    ║
║    ALL  /gateway/proxy                     (enforce+proxy)   ║
║    POST /api/v1/credentials/request        (JIT credential)  ║
║    POST /api/v1/credentials/validate       (verify cred)     ║
║    POST /api/v1/delegation/initiate        (OBO start)       ║
║    POST /api/v1/delegation/extend          (OBO hop)         ║
║    GET  /api/v1/relay/status               (relay status)    ║
║                                                              ║
║  Central federation endpoints:                               ║
║    POST /api/v1/relay/register             (relay join)      ║
║    POST /api/v1/relay/heartbeat            (relay heartbeat) ║
║    GET  /api/v1/relay/environments         (all envs)        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);
  });
}

start().catch(e => {
  log('error', 'Failed to start relay', { error: e.message });
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  log('info', 'Shutting down, flushing audit buffer...');
  await flushAuditBuffer();
  process.exit(0);
});

module.exports = { app, CONFIG, state };
