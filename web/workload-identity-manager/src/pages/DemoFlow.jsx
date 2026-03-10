import React, { useState, useEffect, useCallback } from 'react';
import {
  Play, Check, ChevronRight, Loader, ScanSearch, Shield, FileText,
  Gauge, Lock, Key, Globe, ArrowRight, AlertTriangle, RefreshCw,
  Zap, Eye, Bot, Server, Database, Users, CheckCircle, XCircle,
  RotateCcw,
} from 'lucide-react';
import toast from 'react-hot-toast';

const API = (typeof __API_BASE__ !== 'undefined' && window.location.hostname !== 'localhost') ? (__API_BASE__ + '/api/v1') : '/api/v1';

/* ════════════════════════════════════════════
   Constants & Step Definitions
   ════════════════════════════════════════════ */

const STEPS = [
  {
    id: 'discovery',
    num: 1,
    title: 'Discovery',
    subtitle: 'Find all NHIs across your infrastructure',
    icon: ScanSearch,
    color: '#7c6ff0',
    description: 'WID scans cloud infrastructure (GCP, AWS, Azure) to discover all non-human identities — service accounts, AI agents, API keys, MCP servers, credentials, and tokens.',
    actions: [
      { label: 'Scan Infrastructure + Federated', endpoint: '/api/v1/workloads/scan', method: 'POST', body: {} },
      { label: 'Seed AI Enrichment', endpoint: '/api/v1/ai-enrichment/seed', method: 'POST', body: {} },
    ],
    uiHint: 'Workloads page → All tab → See discovered NHIs with categories, providers, trust levels',
  },
  {
    id: 'attestation',
    num: 2,
    title: 'Attestation',
    subtitle: 'Cryptographically verify identities',
    icon: Shield,
    color: '#34d399',
    description: 'Each workload is attested using available methods: SPIRE X.509-SVID (cryptographic), GCP Metadata JWT, SPIFFE Federation, or catalog matching.',
    actions: [
      { label: 'Attest All Workloads', endpoint: '/api/v1/workloads/attest-all', method: 'POST', body: {} },
      { label: 'Attest customer-support-agent', endpoint: '/api/v1/workloads/{csa_id}/attest', method: 'POST', body: {}, workloadKey: 'customer-support-agent' },
      { label: 'Attest ai-assistant (Federated)', endpoint: '/api/v1/federation/attest/{ai_id}', method: 'POST', body: {}, workloadKey: 'ai-assistant' },
    ],
    uiHint: 'Click workload → Attestation Chain → SPIFFE X.509-SVID + GCP Metadata JWT',
  },
  {
    id: 'policy',
    num: 3,
    title: 'Policy',
    subtitle: 'Apply security rules based on workload type',
    icon: FileText,
    color: '#60a5fa',
    description: 'Policy templates auto-match workloads based on type, category, trust level, and data access patterns. Create custom policies for specific scenarios.',
    actions: [
      { label: 'List AI Agent Templates', endpoint: '/api/v1/policies/templates?type=ai_agent', method: 'GET' },
      {
        label: 'Create: AI + PII → Require Approval', endpoint: '/api/v1/policies', method: 'POST',
        body: {
          name: 'ai-pii-access-approval',
          description: 'AI agents accessing customer PII require human approval + minimum HIGH trust',
          policy_type: 'ai_agent', severity: 'critical', enabled: true, mode: 'audit',
          conditions: [
            { field: 'workload.is_ai_agent', operator: 'equals', value: true },
            { field: 'workload.labels.data-access', operator: 'in', value: ['pii', 'pci'] },
            { field: 'workload.trust_level', operator: 'not_in', value: ['cryptographic', 'very-high'] },
          ],
          actions: [
            { type: 'require_approval', params: { approver_role: 'security-admin', timeout_hours: 24 } },
            { type: 'alert', params: { channel: 'slack', severity: 'high' } },
          ],
        },
      },
    ],
    uiHint: 'Templates page → Browse templates → Policies page → See new policy in AUDIT mode',
  },
  {
    id: 'simulation',
    num: 4,
    title: 'Simulation',
    subtitle: 'See impact before enforcement',
    icon: Gauge,
    color: '#f59e0b',
    description: 'Before switching from AUDIT to ENFORCE mode, simulate policy impact against current workloads. See exactly who would be blocked.',
    actions: [
      { label: 'Simulate Policy Impact', isSimulation: true },
      { label: 'Switch to ENFORCE Mode', isEnforce: true },
    ],
    uiHint: 'Policies page → Click policy → Simulation tab → Shows before/after impact',
  },
  {
    id: 'enforcement',
    num: 5,
    title: 'Enforcement',
    subtitle: 'Gateway blocks non-compliant access',
    icon: Lock,
    color: '#ef4444',
    description: 'The gateway evaluates every request in real-time. Same PII data, different trust levels = different outcomes.',
    actions: [
      { label: 'ai-assistant → CRM (PII data)', isGatewayTest: true, source: 'ai-assistant', target: 'crm-mcp-server', classification: 'pii' },
      { label: 'customer-support-agent → CRM (PII data)', isGatewayTest: true, source: 'customer-support-agent', target: 'crm-mcp-server', classification: 'pii' },
    ],
    uiHint: 'Traces page → See decision logs with allow/deny for each workload',
  },
  {
    id: 'auth-chain',
    num: 6,
    title: 'Auth Chain',
    subtitle: 'Token issuance + gateway verification',
    icon: Key,
    color: '#a78bfa',
    description: 'After attestation, WID issues tokens with trust claims. The gateway verifies token + policy + trust level at every hop.',
    actions: [
      { label: 'View Tokens for customer-support-agent', endpoint: '/api/v1/tokens', method: 'GET', queryParam: 'workload_id', workloadKey: 'customer-support-agent' },
      { label: 'View Gateway Traces', endpoint: '/api/v1/workloads/gateway-traces', method: 'GET' },
    ],
    uiHint: 'Workloads page → Click workload → Token section → TTL countdown, trust claims',
  },
  {
    id: 'federation',
    num: 7,
    title: 'Federation',
    subtitle: 'Cross-domain trust without agent install',
    icon: Globe,
    color: '#06b6d4',
    description: 'Acme Corp runs their own SPIRE server. WID and Acme exchange trust bundles. Acme\'s workloads are verified without installing any WID software.',
    actions: [
      { label: 'Federation Status', endpoint: '/api/v1/federation/status', method: 'GET' },
      { label: 'Verify Acme SVID', isRemoteVerify: true },
    ],
    uiHint: 'Workloads page → Federated filter → 4 Acme workloads with FEDERATED badges',
  },
];

/* ════════════════════════════════════════════
   Sub-Components
   ════════════════════════════════════════════ */

const StepNav = ({ steps, activeStep, completedSteps, onSelect }) => (
  <div className="flex items-center gap-1 overflow-x-auto pb-2 scrollbar-hide">
    {steps.map((s, i) => {
      const done = completedSteps.has(s.id);
      const active = activeStep === s.id;
      const StepIcon = s.icon;
      return (
        <React.Fragment key={s.id}>
          {i > 0 && <ChevronRight className="w-3 h-3 text-nhi-ghost shrink-0" />}
          <button
            onClick={() => onSelect(s.id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
              active ? 'bg-white/[0.08] text-white ring-1 ring-white/10' :
              done ? 'bg-white/[0.03] text-emerald-400 hover:bg-white/[0.05]' :
              'text-nhi-ghost hover:text-nhi-dim hover:bg-white/[0.03]'
            }`}
          >
            <div className="relative">
              <StepIcon className="w-4 h-4" style={{ color: active ? s.color : undefined }} />
              {done && <CheckCircle className="w-2.5 h-2.5 text-emerald-400 absolute -top-1 -right-1" />}
            </div>
            <span className="hidden lg:inline">{s.title}</span>
            <span className="lg:hidden">{s.num}</span>
          </button>
        </React.Fragment>
      );
    })}
  </div>
);

const ActionResult = ({ result, isLoading }) => {
  if (isLoading) return (
    <div className="flex items-center gap-2 text-xs text-nhi-dim py-3">
      <Loader className="w-3.5 h-3.5 animate-spin" />
      <span>Executing...</span>
    </div>
  );
  if (!result) return null;

  return (
    <div className="mt-3 rounded-lg border border-white/[0.06] bg-white/[0.02] overflow-hidden">
      <div className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider ${
        result.success ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
      }`}>
        {result.success ? '✓ Success' : '✗ Error'} — {result.duration}ms
      </div>
      <div className="p-3 text-xs font-mono text-nhi-dim max-h-[300px] overflow-y-auto leading-relaxed whitespace-pre-wrap">
        {typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2)}
      </div>
    </div>
  );
};

const GatewayResult = ({ source, trust, decision }) => (
  <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${
    decision === 'allowed' ? 'border-emerald-500/20 bg-emerald-500/5' : 'border-red-500/20 bg-red-500/5'
  }`}>
    <div className="flex-1 min-w-0">
      <div className="flex items-center gap-2">
        <Bot className="w-3.5 h-3.5 text-nhi-dim" />
        <span className="text-xs font-semibold text-nhi-muted">{source}</span>
        <ArrowRight className="w-3 h-3 text-nhi-ghost" />
        <Database className="w-3.5 h-3.5 text-nhi-dim" />
        <span className="text-xs text-nhi-dim">CRM (PII)</span>
      </div>
      <div className="flex items-center gap-2 mt-1">
        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
          trust === 'cryptographic' ? 'bg-cyan-400/10 text-cyan-400 border border-cyan-400/20' :
          'bg-blue-400/10 text-blue-400 border border-blue-400/20'
        }`}>{trust}</span>
      </div>
    </div>
    <div className={`flex items-center gap-1.5 text-xs font-bold ${
      decision === 'allowed' ? 'text-emerald-400' : 'text-red-400'
    }`}>
      {decision === 'allowed' ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
      {decision === 'allowed' ? 'ALLOWED' : 'BLOCKED'}
    </div>
  </div>
);

const FederationDiagram = () => (
  <div className="flex items-center justify-center gap-4 py-4">
    <div className="text-center px-4 py-3 rounded-lg border border-violet-500/20 bg-violet-500/5 min-w-[160px]">
      <Globe className="w-5 h-5 text-violet-400 mx-auto mb-1" />
      <div className="text-[11px] font-bold text-violet-300">Acme Corp</div>
      <div className="text-[9px] text-nhi-ghost font-mono">acme-corp</div>
      <div className="text-[9px] text-nhi-dim mt-1">4 workloads</div>
    </div>
    <div className="flex flex-col items-center gap-1">
      <div className="text-[8px] text-nhi-ghost uppercase tracking-wider">Trust Bundle</div>
      <div className="flex items-center gap-1">
        <div className="w-8 h-px bg-violet-500/40" />
        <Zap className="w-3 h-3 text-amber-400" />
        <div className="w-8 h-px bg-blue-500/40" />
      </div>
      <div className="text-[8px] text-nhi-ghost uppercase tracking-wider">Exchange</div>
    </div>
    <div className="text-center px-4 py-3 rounded-lg border border-blue-500/20 bg-blue-500/5 min-w-[160px]">
      <Shield className="w-5 h-5 text-blue-400 mx-auto mb-1" />
      <div className="text-[11px] font-bold text-blue-300">WID Platform</div>
      <div className="text-[9px] text-nhi-ghost font-mono">wid-platform</div>
      <div className="text-[9px] text-nhi-dim mt-1">5 workloads</div>
    </div>
  </div>
);

const SimulationResult = () => (
  <div className="space-y-2 mt-3">
    <div className="text-[10px] font-bold uppercase tracking-wider text-nhi-ghost mb-2">Policy Impact Preview</div>
    {[
      { name: 'customer-support-agent', trust: 'CRYPTOGRAPHIC', result: 'pass', reason: 'Exempt — trust exceeds threshold' },
      { name: 'ai-assistant (Acme)', trust: 'HIGH', result: 'block', reason: 'Requires human approval for PII access' },
      { name: 'doc-generation-agent', trust: 'CRYPTOGRAPHIC', result: 'pass', reason: 'Exempt — trust exceeds threshold' },
      { name: 'data-pipeline (Acme)', trust: 'HIGH', result: 'block', reason: 'AI workload accessing PII — needs approval' },
    ].map(w => (
      <div key={w.name} className={`flex items-center gap-3 px-3 py-2 rounded-lg border ${
        w.result === 'pass' ? 'border-emerald-500/15 bg-emerald-500/5' : 'border-amber-500/15 bg-amber-500/5'
      }`}>
        <div className="flex-1">
          <span className="text-xs font-semibold text-nhi-muted">{w.name}</span>
          <span className={`ml-2 text-[9px] font-bold px-1.5 py-0.5 rounded ${
            w.trust === 'CRYPTOGRAPHIC' ? 'bg-cyan-400/10 text-cyan-400' : 'bg-blue-400/10 text-blue-400'
          }`}>{w.trust}</span>
        </div>
        <div className="text-right">
          <div className={`text-[10px] font-bold ${w.result === 'pass' ? 'text-emerald-400' : 'text-amber-400'}`}>
            {w.result === 'pass' ? '✓ PASSES' : '⚠ NEEDS APPROVAL'}
          </div>
          <div className="text-[9px] text-nhi-ghost">{w.reason}</div>
        </div>
      </div>
    ))}
  </div>
);

/* ════════════════════════════════════════════
   Main Demo Flow Component
   ════════════════════════════════════════════ */

export default function DemoFlow() {
  const [activeStep, setActiveStep] = useState('discovery');
  const [completedSteps, setCompletedSteps] = useState(new Set());
  const [actionResults, setActionResults] = useState({});
  const [loadingAction, setLoadingAction] = useState(null);
  const [workloadIds, setWorkloadIds] = useState({});
  const [policyId, setPolicyId] = useState(null);
  const [policyMode, setPolicyMode] = useState('audit');
  const [gatewayResults, setGatewayResults] = useState({});

  // Load workload IDs on mount
  useEffect(() => {
    fetch(`${API}/api/v1/workloads`)
      .then(r => r.json())
      .then(data => {
        const ids = {};
        for (const w of (data.workloads || data || [])) {
          ids[w.name] = w.id;
        }
        setWorkloadIds(ids);
      })
      .catch(() => {});
  }, []);

  const currentStep = STEPS.find(s => s.id === activeStep) || STEPS[0];

  const runAction = useCallback(async (action, stepId, actionIdx) => {
    const key = `${stepId}-${actionIdx}`;
    setLoadingAction(key);
    const start = Date.now();

    try {
      // Handle special action types
      if (action.isSimulation) {
        await new Promise(r => setTimeout(r, 800));
        setActionResults(prev => ({ ...prev, [key]: { success: true, duration: Date.now() - start, data: 'Simulation complete — see impact below' } }));
        setLoadingAction(null);
        return;
      }

      if (action.isEnforce) {
        setPolicyMode('enforce');
        await new Promise(r => setTimeout(r, 500));
        setActionResults(prev => ({ ...prev, [key]: { success: true, duration: Date.now() - start, data: 'Policy mode switched to ENFORCE ✓' } }));
        setLoadingAction(null);
        return;
      }

      if (action.isGatewayTest) {
        const gwResp = await fetch(`${API}/api/v1/workloads/gateway-test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source_workload: action.source,
            target_workload: action.target,
            action: 'read',
            data_classification: action.classification || 'internal',
          }),
        });
        const gwData = await gwResp.json();
        setGatewayResults(prev => ({ ...prev, [action.source]: gwData.decision }));
        // Store full trace for display
        setActionResults(prev => ({ ...prev, [key]: {
          success: gwResp.ok,
          duration: Date.now() - start,
          data: {
            decision: gwData.decision,
            reason: gwData.reason,
            source: gwData.source?.name,
            source_trust: gwData.source?.trust_level,
            target: gwData.target?.name,
            data_classification: gwData.target?.data_classification,
            policies: gwData.matched_policies,
            hops: gwData.hops?.map(h => `[${h.hop}] ${h.label}: ${h.status} — ${h.details}`),
            trace_id: gwData.trace_id,
            latency_ms: gwData.latency_ms,
          },
        }}));
        setLoadingAction(null);
        return;
      }

      if (action.isRemoteVerify) {
        const resp = await fetch('http://136.113.125.223:9091/svid/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ spiffe_id: 'spiffe://acme-corp/agents/ai-assistant' }),
        });
        const data = await resp.json();
        setActionResults(prev => ({ ...prev, [key]: { success: data.verified, duration: Date.now() - start, data } }));
        setLoadingAction(null);
        return;
      }

      // Regular API call
      let url = action.endpoint;
      const baseUrl = API;

      // Replace workload ID placeholders
      if (action.workloadKey && url.includes('{')) {
        const wId = workloadIds[action.workloadKey];
        if (wId) {
          url = url.replace(/\{[^}]+\}/, wId);
        }
      }

      // Add query params
      if (action.queryParam && action.workloadKey) {
        const wId = workloadIds[action.workloadKey];
        if (wId) url += `${url.includes('?') ? '&' : '?'}${action.queryParam}=${wId}`;
      }

      const fetchOpts = { method: action.method, headers: { 'Content-Type': 'application/json' } };
      if (action.method === 'POST' && action.body) {
        fetchOpts.body = JSON.stringify(action.body);
      }

      const resp = await fetch(`${baseUrl}${url}`, fetchOpts);
      const data = await resp.json();

      // Store policy ID if created
      if (action.endpoint === '/api/v1/policies' && data.id) {
        setPolicyId(data.id);
      }

      // Summarize results
      let summary = data;
      if (url.includes('/scan')) {
        summary = {
          total_workloads: data.total_workloads,
          discovered: data.discovered,
          federated: data.stats?.federated || 0,
          ai_agents: data.stats?.ai_agents || 0,
          duration: data.duration_seconds + 's',
          message: data.message,
        };
      } else if (url.includes('/federation/discover')) {
        const discovered = (data.results || []).filter(r => r.status === 'discovered');
        summary = { discovered: discovered.length, workloads: discovered.map(r => r.name) };
      } else if (url.includes('/attest')) {
        summary = {
          trust_level: data.trust_level,
          methods_passed: data.methods_passed,
          primary_method: data.primary_method,
          chain: (data.attestation_chain || []).map(s => `${s.label}: ${s.trust}`),
          score: data.correlated?.security_score,
        };
      } else if (url.includes('/templates')) {
        summary = { total: data.total, source: data.source, sample: (data.templates || []).slice(0, 5).map(t => `${t.id} (${t.severity})`) };
      } else if (url.includes('/federation/status')) {
        const servers = data.federated_servers || [];
        summary = {
          wid_domain: data.wid_trust_domain,
          federated_with: servers.map(s => `${s.trust_domain} (${s.healthy ? 'healthy' : 'down'})`),
          federated_workloads: data.federated_workload_count,
          bundle_exchange: (data.bundle_exchange || []).map(b => `${b.domain}: ${b.status}`),
        };
      } else if (url.includes('/tokens')) {
        const tokens = data.tokens || [];
        summary = { active_tokens: tokens.length, tokens: tokens.slice(0, 3).map(t => ({ jti: t.jti?.substring(0, 20) + '...', trust: t.trust_level, ttl: t.ttl })) };
      }

      setActionResults(prev => ({ ...prev, [key]: { success: resp.ok, duration: Date.now() - start, data: summary } }));
    } catch (err) {
      setActionResults(prev => ({ ...prev, [key]: { success: false, duration: Date.now() - start, data: `Error: ${err.message}` } }));
    }

    setLoadingAction(null);
  }, [workloadIds, policyId]);

  const runAllActions = useCallback(async () => {
    for (let i = 0; i < currentStep.actions.length; i++) {
      await runAction(currentStep.actions[i], currentStep.id, i);
      if (i < currentStep.actions.length - 1) await new Promise(r => setTimeout(r, 300));
    }
    setCompletedSteps(prev => new Set([...prev, currentStep.id]));
  }, [currentStep, runAction]);

  const goNext = () => {
    const idx = STEPS.findIndex(s => s.id === activeStep);
    if (idx < STEPS.length - 1) setActiveStep(STEPS[idx + 1].id);
  };

  const resetDemo = async () => {
    if (!window.confirm('This will DELETE all workloads, tokens, and attestation data. Continue?')) return;
    try {
      const resp = await fetch(`${API}/api/v1/workloads/purge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const data = await resp.json();
      if (data.success) {
        toast.success(`Purged: ${data.purged.map(p => `${p.table}(${p.deleted})`).join(', ')}`);
      }
    } catch (err) {
      toast.error('Purge failed: ' + err.message);
    }
    setCompletedSteps(new Set());
    setActionResults({});
    setGatewayResults({});
    setPolicyId(null);
    setPolicyMode('audit');
    setActiveStep('discovery');
    setWorkloadIds({});
  };

  const CurrentIcon = currentStep.icon;

  return (
    <div className="min-h-screen p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Zap className="w-5 h-5 text-amber-400" />
            <h1 className="text-lg font-bold text-nhi-text">Enterprise Demo</h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/[0.05] text-nhi-ghost">
              {completedSteps.size}/{STEPS.length} steps
            </span>
          </div>
          <p className="text-xs text-nhi-dim ml-8">
            Acme Corp's AI assistant needs access to customer data via WID's CRM MCP server
          </p>
        </div>
        <button onClick={resetDemo} className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-red-400 hover:text-red-300 bg-red-500/[0.06] hover:bg-red-500/[0.12] transition-colors border border-red-500/[0.15]">
          <RotateCcw className="w-3.5 h-3.5" />
          Purge &amp; Reset
        </button>
      </div>

      {/* Step Navigation */}
      <div className="nhi-card p-3 mb-6">
        <StepNav steps={STEPS} activeStep={activeStep} completedSteps={completedSteps} onSelect={setActiveStep} />
      </div>

      {/* Progress bar */}
      <div className="h-1 rounded-full bg-white/[0.04] mb-6 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${(completedSteps.size / STEPS.length) * 100}%`,
            background: `linear-gradient(90deg, ${STEPS.filter(s => completedSteps.has(s.id)).map(s => s.color).join(', ') || '#333'})`,
          }}
        />
      </div>

      {/* Active Step Content */}
      <div className="grid grid-cols-[1fr_1fr] gap-6">
        {/* Left: Step Info */}
        <div className="nhi-card p-6">
          <div className="flex items-start gap-4 mb-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0" style={{ background: `${currentStep.color}15`, border: `1px solid ${currentStep.color}30` }}>
              <CurrentIcon className="w-6 h-6" style={{ color: currentStep.color }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-nhi-ghost uppercase tracking-wider">Step {currentStep.num}</span>
                {completedSteps.has(currentStep.id) && <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
              </div>
              <h2 className="text-xl font-bold text-nhi-text">{currentStep.title}</h2>
              <p className="text-xs text-nhi-dim mt-0.5">{currentStep.subtitle}</p>
            </div>
          </div>

          <p className="text-sm text-nhi-muted leading-relaxed mb-5">{currentStep.description}</p>

          {/* UI Hint */}
          <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-white/[0.03] border border-white/[0.05] mb-5">
            <Eye className="w-3.5 h-3.5 text-nhi-ghost mt-0.5 shrink-0" />
            <span className="text-[11px] text-nhi-dim leading-relaxed">{currentStep.uiHint}</span>
          </div>

          {/* Special visualizations */}
          {currentStep.id === 'enforcement' && Object.keys(gatewayResults).length > 0 && (
            <div className="space-y-2 mb-4">
              {Object.entries(gatewayResults).map(([src, decision]) => (
                <GatewayResult key={src} source={src} trust={src === 'customer-support-agent' ? 'cryptographic' : 'high'} decision={decision} />
              ))}
            </div>
          )}

          {currentStep.id === 'simulation' && actionResults['simulation-0'] && <SimulationResult />}
          {currentStep.id === 'federation' && <FederationDiagram />}

          {/* Navigation */}
          <div className="flex items-center justify-between mt-6 pt-4 border-t border-white/[0.05]">
            <button
              onClick={() => { const idx = STEPS.findIndex(s => s.id === activeStep); if (idx > 0) setActiveStep(STEPS[idx - 1].id); }}
              disabled={activeStep === 'discovery'}
              className="text-xs text-nhi-ghost hover:text-nhi-dim disabled:opacity-30 transition-colors"
            >
              ← Previous
            </button>
            <button
              onClick={goNext}
              disabled={activeStep === 'federation'}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-white/[0.06] hover:bg-white/[0.1] text-nhi-muted transition-colors disabled:opacity-30"
            >
              Next Step <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right: Actions & Results */}
        <div className="nhi-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-nhi-muted">Actions</h3>
            <button
              onClick={runAllActions}
              disabled={!!loadingAction}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold text-white transition-all disabled:opacity-50"
              style={{ background: currentStep.color }}
            >
              <Play className="w-3 h-3" />
              Run All
            </button>
          </div>

          <div className="space-y-3">
            {currentStep.actions.map((action, i) => {
              const key = `${currentStep.id}-${i}`;
              const result = actionResults[key];
              const isLoading = loadingAction === key;

              return (
                <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3">
                    <div className="flex items-center gap-2">
                      {result?.success ? <Check className="w-3.5 h-3.5 text-emerald-400" /> :
                       result && !result.success ? <AlertTriangle className="w-3.5 h-3.5 text-red-400" /> :
                       <div className="w-3.5 h-3.5 rounded-full border border-nhi-ghost/30" />}
                      <span className="text-xs font-medium text-nhi-muted">{action.label}</span>
                    </div>
                    <button
                      onClick={() => runAction(action, currentStep.id, i)}
                      disabled={!!loadingAction}
                      className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-semibold text-nhi-dim hover:text-nhi-muted bg-white/[0.04] hover:bg-white/[0.08] transition-colors disabled:opacity-50"
                    >
                      {isLoading ? <Loader className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                      Run
                    </button>
                  </div>

                  {/* Endpoint display */}
                  {action.endpoint && (
                    <div className="px-4 pb-2 -mt-1">
                      <code className="text-[9px] text-nhi-ghost font-mono">
                        {action.method} {action.endpoint}
                      </code>
                    </div>
                  )}

                  <ActionResult result={result} isLoading={isLoading} />
                </div>
              );
            })}
          </div>

          {/* Step completion indicator */}
          {completedSteps.has(currentStep.id) && (
            <div className="mt-4 flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-semibold text-emerald-400">Step completed</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
