// =============================================================================
// Decision Generator — Produces real authorization decisions from WID service
// topology by exercising the relay's gateway proxy endpoint.
//
// Each cycle sends real service-to-service call patterns through the relay,
// which evaluates policies via the policy engine and logs decisions to
// ext_authz_decisions. This gives the Evidence tab real, live data.
//
// Alternates between:
//   - Single decisions (individual service-to-service calls)
//   - Trace chains (multi-hop evaluate-chain calls grouped by trace_id)
// =============================================================================

const RELAY_URL = process.env.RELAY_URL || 'http://relay-service:3005';
const POLICY_ENGINE_URL = process.env.POLICY_ENGINE_URL || 'http://policy-sync-service:3001';
const INTERVAL_MS = parseInt(process.env.INTERVAL_MS || '30000');
const STARTUP_DELAY_MS = parseInt(process.env.STARTUP_DELAY_MS || '45000');

// Real WID inter-service call patterns (single-hop)
const SERVICE_PATTERNS = [
  { source: 'wip-discovery', dest: 'wip-policy-sync', target: `${POLICY_ENGINE_URL}/health`, method: 'GET', desc: 'discovery→policy health' },
  { source: 'wip-discovery', dest: 'wip-token-service', target: 'http://token-service:3000/health', method: 'GET', desc: 'discovery→token health' },
  { source: 'wip-web', dest: 'wip-discovery', target: 'http://discovery-service:3003/api/v1/workloads', method: 'GET', desc: 'web→discovery workloads' },
  { source: 'wip-web', dest: 'wip-policy-sync', target: `${POLICY_ENGINE_URL}/api/v1/policies`, method: 'GET', desc: 'web→policy list' },
  { source: 'wip-relay', dest: 'wip-policy-sync', target: `${POLICY_ENGINE_URL}/api/v1/relay/policies`, method: 'GET', desc: 'relay→policy sync' },
  { source: 'wip-credential-broker', dest: 'wip-vault', target: 'http://vault:8200/v1/sys/health', method: 'GET', desc: 'broker→vault health' },
  { source: 'wip-audit-service', dest: 'wip-policy-sync', target: `${POLICY_ENGINE_URL}/health`, method: 'GET', desc: 'audit→policy health' },
  { source: 'wip-decision-generator', dest: 'wip-relay', target: `${RELAY_URL}/health`, method: 'GET', desc: 'generator→relay health' },
  { source: 'wip-policy-sync', dest: 'wip-opa', target: 'http://opa:8181/health', method: 'GET', desc: 'policy→opa eval' },
];

// Multi-hop trace chain patterns (realistic service call chains)
const CHAIN_PATTERNS = [
  {
    desc: 'web→policy→opa (policy evaluation chain)',
    hops: [
      { source: 'wip-web', destination: 'wip-policy-sync', method: 'POST', path: '/api/v1/policies/evaluate' },
      { source: 'wip-policy-sync', destination: 'wip-opa', method: 'POST', path: '/v1/data/workload/authz' },
    ],
  },
  {
    desc: 'web→discovery→policy (graph build chain)',
    hops: [
      { source: 'wip-web', destination: 'wip-discovery', method: 'GET', path: '/api/v1/graph' },
      { source: 'wip-discovery', destination: 'wip-policy-sync', method: 'GET', path: '/api/v1/policies' },
    ],
  },
  {
    desc: 'relay→policy→opa (policy sync chain)',
    hops: [
      { source: 'wip-relay', destination: 'wip-policy-sync', method: 'GET', path: '/api/v1/relay/policies' },
      { source: 'wip-policy-sync', destination: 'wip-opa', method: 'POST', path: '/v1/data/workload/authz' },
    ],
  },
  {
    desc: 'web→broker→vault (credential fetch chain)',
    hops: [
      { source: 'wip-web', destination: 'wip-credential-broker', method: 'POST', path: '/api/v1/credentials/fetch' },
      { source: 'wip-credential-broker', destination: 'wip-vault', method: 'GET', path: '/v1/secret/data/wid' },
    ],
  },
  {
    desc: 'discovery→token→policy (attestation chain)',
    hops: [
      { source: 'wip-discovery', destination: 'wip-token-service', method: 'POST', path: '/api/v1/tokens/issue' },
      { source: 'wip-token-service', destination: 'wip-policy-sync', method: 'POST', path: '/api/v1/gateway/evaluate' },
    ],
  },
  {
    desc: 'web→policy→opa→vault (enforce chain)',
    hops: [
      { source: 'wip-web', destination: 'wip-policy-sync', method: 'POST', path: '/api/v1/policies/from-template/jit-credential-gateway' },
      { source: 'wip-policy-sync', destination: 'wip-opa', method: 'POST', path: '/v1/data/workload/authz' },
      { source: 'wip-policy-sync', destination: 'wip-vault', method: 'POST', path: '/v1/secret/data/wid/jit' },
    ],
  },
  {
    desc: 'audit→policy→relay (audit flush chain)',
    hops: [
      { source: 'wip-audit-service', destination: 'wip-policy-sync', method: 'GET', path: '/api/v1/access/decisions/live' },
      { source: 'wip-audit-service', destination: 'wip-relay', method: 'POST', path: '/api/v1/audit/flush' },
    ],
  },
];

async function generateDecision(pattern) {
  try {
    const resp = await fetch(`${RELAY_URL}/gateway/proxy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WID-Source': pattern.source,
        'X-WID-Destination': pattern.dest,
        'X-WID-Target-URL': pattern.target,
      },
      body: JSON.stringify({ method: pattern.method }),
      signal: AbortSignal.timeout(10000),
    });

    const result = await resp.json();
    return { pattern: pattern.desc, verdict: result.verdict || 'error', policy: result.policy_name || null, status: resp.status };
  } catch (err) {
    // Relay might not have gateway/proxy yet, fall back to direct policy engine evaluate
    try {
      const evalResp = await fetch(`${POLICY_ENGINE_URL}/api/v1/gateway/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: pattern.source,
          destination: pattern.dest,
          method: pattern.method,
          path: new URL(pattern.target).pathname,
        }),
        signal: AbortSignal.timeout(10000),
      });

      const evalResult = await evalResp.json();
      return { pattern: pattern.desc, verdict: evalResult.verdict || 'error', policy: evalResult.policy_name || null, status: evalResp.status, via: 'direct' };
    } catch (fallbackErr) {
      return { pattern: pattern.desc, verdict: 'unreachable', error: fallbackErr.message };
    }
  }
}

async function generateChain(chain) {
  try {
    const resp = await fetch(`${POLICY_ENGINE_URL}/api/v1/gateway/evaluate-chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hops: chain.hops }),
      signal: AbortSignal.timeout(15000),
    });

    const result = await resp.json();
    return {
      pattern: chain.desc,
      trace_id: result.trace_id || null,
      chain_verdict: result.chain_verdict || 'error',
      hops: result.hops?.length || chain.hops.length,
      status: resp.status,
    };
  } catch (err) {
    return { pattern: chain.desc, chain_verdict: 'unreachable', error: err.message };
  }
}

let cycleNum = 0;

async function runCycle() {
  cycleNum++;
  const results = [];

  // Every cycle: mix of single decisions + trace chains
  // Odd cycles: more singles. Even cycles: more chains.
  const doChains = cycleNum % 2 === 0;

  // Single decisions (2-4 patterns)
  const shuffledSingles = [...SERVICE_PATTERNS].sort(() => Math.random() - 0.5);
  const singleCount = doChains ? 2 : (3 + Math.floor(Math.random() * 2));
  const selectedSingles = shuffledSingles.slice(0, singleCount);

  for (const pattern of selectedSingles) {
    const result = await generateDecision(pattern);
    results.push(result);
    await new Promise(r => setTimeout(r, 300));
  }

  // Trace chains (1-2 per even cycle, 1 per odd cycle)
  const chainCount = doChains ? (1 + Math.floor(Math.random() * 2)) : (Math.random() > 0.5 ? 1 : 0);
  if (chainCount > 0) {
    const shuffledChains = [...CHAIN_PATTERNS].sort(() => Math.random() - 0.5);
    const selectedChains = shuffledChains.slice(0, chainCount);

    for (const chain of selectedChains) {
      const result = await generateChain(chain);
      results.push(result);
      await new Promise(r => setTimeout(r, 300));
    }
  }

  const singles = results.filter(r => !r.trace_id);
  const traces = results.filter(r => r.trace_id);
  const verdictSummary = results.reduce((acc, r) => {
    const v = r.verdict || r.chain_verdict || 'unknown';
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  console.log(`[${new Date().toISOString()}] Cycle ${cycleNum}: ${singles.length} singles + ${traces.length} traces (${results.length} total): ${JSON.stringify(verdictSummary)}`);
}

// Main loop
console.log(`Decision Generator starting (interval: ${INTERVAL_MS}ms, startup delay: ${STARTUP_DELAY_MS}ms)`);
console.log(`  Relay: ${RELAY_URL}`);
console.log(`  Policy Engine: ${POLICY_ENGINE_URL}`);
console.log(`  Service patterns: ${SERVICE_PATTERNS.length} single, ${CHAIN_PATTERNS.length} chains`);

setTimeout(async () => {
  console.log('Running first decision cycle...');
  await runCycle();

  setInterval(async () => {
    try {
      await runCycle();
    } catch (err) {
      console.error('Decision cycle error:', err.message);
    }
  }, INTERVAL_MS);
}, STARTUP_DELAY_MS);
