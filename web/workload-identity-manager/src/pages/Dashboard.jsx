import React, { useState, useEffect, useMemo } from 'react';
import {
  Server, AlertTriangle, ShieldCheck, Bot, Eye,
  TrendingUp, Loader, Shield, Lock, KeyRound,
  Fingerprint, Network, FileWarning, Users, Clock,
  ArrowRight, CheckCircle2, XCircle, AlertCircle, Activity,
  Key, Unlock, Zap, RefreshCw, ChevronRight, BarChart3,
} from 'lucide-react';
import { enrichWorkload } from '../utils/enrichment';
import { useNavigate } from 'react-router-dom';

/* ═══════════════════════════════════════════
   Trust Colors
   ═══════════════════════════════════════════ */
const TRUST_COLORS = {
  'cryptographic': { text: '#10b981', bg: '#10b98118', label: 'Cryptographic' },
  'very-high':     { text: '#22d3ee', bg: '#22d3ee18', label: 'Very High' },
  'high':          { text: '#3b82f6', bg: '#3b82f618', label: 'High' },
  'medium':        { text: '#f59e0b', bg: '#f59e0b18', label: 'Medium' },
  'low':           { text: '#f97316', bg: '#f9731618', label: 'Low' },
  'none':          { text: '#ef4444', bg: '#ef444418', label: 'None' },
};

const RISK_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', good: '#10b981' };

/* ═══════════════════════════════════════════
   OWASP NHI Top 10
   ═══════════════════════════════════════════ */
const OWASP_NHI_TOP_10 = [
  { id: 'NHI1', title: 'Improper Offboarding', icon: Users, check: (ws) => ws.filter(w => !w.owner && w.verified).length, desc: 'NHIs without owners that are still active' },
  { id: 'NHI2', title: 'Secret Leakage', icon: KeyRound, check: (ws) => ws.filter(w => w._category === 'Secrets Manager' && !w.verified).length, desc: 'Unattested secrets/credentials' },
  { id: 'NHI3', title: 'Vulnerable Third-Party NHI', icon: Network, check: (ws) => ws.filter(w => w._vendor && !w.verified).length, desc: 'Third-party integrations not verified' },
  { id: 'NHI4', title: 'Insecure Authentication', icon: Lock, check: (ws) => ws.filter(w => !w.spiffe_id && w.verified).length, desc: 'Attested but no cryptographic identity' },
  { id: 'NHI5', title: 'Overly Permissive NHI', icon: Shield, check: (ws) => ws.filter(w => w.type === 'iam' && w.name?.toLowerCase().includes('admin')).length, desc: 'Admin-level NHIs detected' },
  { id: 'NHI6', title: 'Insecure Cloud Deployment', icon: FileWarning, check: (ws) => ws.filter(w => !w.environment || w.environment === 'unknown').length, desc: 'NHIs with unknown environment' },
  { id: 'NHI7', title: 'Long-Lived Credentials', icon: Clock, check: (ws) => ws.filter(w => w._age && w._age > 180).length, desc: 'Credentials older than 180 days' },
  { id: 'NHI8', title: 'Environment Isolation Failure', icon: AlertCircle, check: (ws) => ws.filter(w => w.environment === 'production' && w.trust_level !== 'very-high' && w.trust_level !== 'cryptographic').length, desc: 'Prod NHIs without high trust' },
  { id: 'NHI9', title: 'NHI Reuse', icon: Fingerprint, check: (ws) => { const names = ws.map(w => w.name); return names.length - new Set(names).size; }, desc: 'Duplicate identity names detected' },
  { id: 'NHI10', title: 'Human Use of NHI', icon: Users, check: (ws) => ws.filter(w => w.type === 'iam' && w.name?.match(/[A-Z][a-z]+_/)).length, desc: 'Possible human-named service accounts' },
];

/* ═══════════════════════════════════════════
   Micro Components
   ═══════════════════════════════════════════ */
const MetricCard = ({ label, value, sub, icon: Icon, color, onClick }) => (
  <div className={`nhi-card p-5 animate-fadeInUp ${onClick ? 'cursor-pointer hover:border-white/[0.08] transition-colors' : ''}`} onClick={onClick}>
    <div className="absolute top-0 left-0 right-0 h-[2px] opacity-60" style={{ background: color }} />
    <div className="flex items-start justify-between mb-3">
      <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: `${color}15` }}>
        <Icon className="w-[18px] h-[18px]" style={{ color }} />
      </div>
    </div>
    <div className="text-[11px] font-semibold text-nhi-muted uppercase tracking-[0.08em] mb-1.5">{label}</div>
    <div className="text-[28px] font-bold text-nhi-text font-mono tracking-tight leading-none">{value}</div>
    {sub && <div className="text-[11px] text-nhi-faint mt-2 font-medium">{sub}</div>}
  </div>
);

const TrustBar = ({ counts, total }) => {
  if (total === 0) return null;
  const levels = ['cryptographic', 'very-high', 'high', 'medium', 'low', 'none'];
  return (
    <div className="flex h-3 rounded-full overflow-hidden bg-white/[0.03]">
      {levels.map(level => {
        const count = counts[level] || 0;
        if (count === 0) return null;
        const pct = (count / total) * 100;
        const c = TRUST_COLORS[level];
        return (
          <div key={level} className="relative group" style={{ width: `${pct}%`, background: c.text }} title={`${c.label}: ${count}`}>
            <div className="absolute -top-8 left-1/2 -translate-x-1/2 hidden group-hover:block text-[9px] font-bold text-white bg-black/90 px-1.5 py-0.5 rounded whitespace-nowrap z-10">
              {c.label}: {count} ({Math.round(pct)}%)
            </div>
          </div>
        );
      })}
    </div>
  );
};

/* ── Enhanced Posture Score Ring with breakdown ── */
const PostureScoreRing = ({ score, breakdown, total }) => {
  const r = 46;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : score >= 40 ? '#f97316' : '#ef4444';
  const label = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Needs Work' : 'Critical';

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: 110, height: 110 }}>
        <svg viewBox="0 0 110 110" className="transform -rotate-90">
          <circle cx="55" cy="55" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
          <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
            className="transition-all duration-1000"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[24px] font-bold font-mono leading-none" style={{ color }}>{score}</span>
          <span className="text-[8px] text-nhi-faint font-mono">/100</span>
        </div>
      </div>
      <span className="text-[10px] font-bold uppercase tracking-widest mt-2" style={{ color }}>{label}</span>
      {/* Breakdown bars */}
      {breakdown && (
        <div className="w-full mt-3 space-y-1.5">
          {breakdown.map((b, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="text-[8px] text-nhi-faint w-16 text-right shrink-0 font-medium">{b.label}</span>
              <div className="flex-1 h-[3px] rounded-full bg-white/[0.04]">
                <div className="h-full rounded-full transition-all duration-700" style={{ width: `${(b.value / b.max) * 100}%`, background: b.color }} />
              </div>
              <span className="text-[8px] font-mono text-nhi-faint w-8 shrink-0">{b.value}/{b.max}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

/* ═══════════════════════════════════════════
   Dashboard
   ═══════════════════════════════════════════ */
const Dashboard = () => {
  const [workloads, setWorkloads] = useState([]);
  const [enforcement, setEnforcement] = useState(null);
  const [graphSummary, setGraphSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [wRes, eRes, gRes] = await Promise.all([
          fetch('/api/v1/workloads').then(r => r.ok ? r.json() : { workloads: [] }).catch(() => ({ workloads: [] })),
          fetch('/api/v1/enforcement/summary').then(r => r.ok ? r.json() : null).catch(() => null),
          fetch('/api/v1/graph').then(r => r.ok ? r.json() : null).catch(() => null),
        ]);
        setWorkloads(wRes.workloads || []);
        if (eRes) setEnforcement(eRes);
        if (gRes?.summary) setGraphSummary(gRes.summary);
      } catch (e) { console.error('Dashboard fetch error:', e); }
      finally { setLoading(false); }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  /* ── Computed stats ── */
  const stats = useMemo(() => {
    const enriched = workloads.map(enrichWorkload);

    // Coerce AI/MCP flags — DB may return string "true", "1", or integer 1
    enriched.forEach(w => {
      w.is_ai_agent = w.is_ai_agent === true || w.is_ai_agent === 'true' || w.is_ai_agent === 1 || w.is_ai_agent === '1';
      w.is_mcp_server = w.is_mcp_server === true || w.is_mcp_server === 'true' || w.is_mcp_server === 1 || w.is_mcp_server === '1';
    });

    const total = enriched.length;
    const attested = enriched.filter(w => w.verified).length;
    const shadow = enriched.filter(w => w.is_shadow).length;
    const aiMcp = enriched.filter(w => w.is_ai_agent || w.is_mcp_server).length;
    const atRisk = enriched.filter(w => w._risk === 'Critical' || w._risk === 'High').length;
    const noOwner = enriched.filter(w => !w.owner).length;
    const noTeam = enriched.filter(w => !w.team).length;
    const noSpiffe = enriched.filter(w => !w.spiffe_id).length;

    // Trust distribution
    const trustCounts = {};
    enriched.forEach(w => { const tl = w.trust_level || 'none'; trustCounts[tl] = (trustCounts[tl] || 0) + 1; });

    const avgScore = total > 0 ? Math.round(enriched.reduce((sum, w) => sum + (w.security_score || 0), 0) / total) : 0;

    // Categories
    const categories = {};
    enriched.forEach(w => {
      const cat = w._category || 'Unknown';
      if (!categories[cat]) categories[cat] = { count: 0, attested: 0, icon: w._categoryIcon };
      categories[cat].count++;
      if (w.verified) categories[cat].attested++;
    });

    // OWASP
    const owaspFindings = OWASP_NHI_TOP_10.map(item => ({ ...item, count: item.check(enriched) }));
    const owaspPassing = owaspFindings.filter(f => f.count === 0).length;

    // Top risks
    const topRisks = enriched
      .filter(w => w._risk === 'Critical' || w._risk === 'High')
      .sort((a, b) => (a.security_score || 0) - (b.security_score || 0))
      .slice(0, 5);

    // ── Credential & Key Insights ──
    const sas = enriched.filter(w => w.type === 'service-account');
    const withUserKeys = sas.filter(w => (w.metadata?.user_managed_keys || 0) > 0);
    const oldKeys = sas.filter(w => (w.metadata?.oldest_key_age_days || 0) > 90);
    const defaultSAs = sas.filter(w => w.metadata?.is_default);

    // ── Access & Exposure Insights ──
    const publicIngress = enriched.filter(w => w.metadata?.ingress === 'INGRESS_TRAFFIC_ALL');
    const internalOnly = enriched.filter(w => w.metadata?.ingress === 'INGRESS_TRAFFIC_INTERNAL_ONLY');
    const sharedSAs = {};
    enriched.forEach(w => {
      const sa = w.metadata?.service_account;
      if (sa) {
        if (!sharedSAs[sa]) sharedSAs[sa] = [];
        sharedSAs[sa].push(w.name);
      }
    });
    const sharedSAList = Object.entries(sharedSAs).filter(([, ws]) => ws.length > 1);

    // ── Attestation Health ──
    const now = Date.now();
    const expiring24h = enriched.filter(w => {
      const exp = w.attestation_data?.expires_at;
      if (!exp) return false;
      return new Date(exp) - now < 24 * 60 * 60 * 1000;
    });
    const expiring48h = enriched.filter(w => {
      const exp = w.attestation_data?.expires_at;
      if (!exp) return false;
      const diff = new Date(exp) - now;
      return diff >= 24 * 60 * 60 * 1000 && diff < 48 * 60 * 60 * 1000;
    });

    // ── Posture Score ──
    let postureScore = 0;
    if (total > 0) {
      const attestPts = Math.round((attested / total) * 30);
      const scorePts = Math.round((avgScore / 100) * 25);
      const ownerPts = Math.round(((total - noOwner) / total) * 20);
      const shadowPts = Math.round(((total - shadow) / total) * 15);
      const keyPts = withUserKeys.length === 0 ? 10 : oldKeys.length === 0 ? 5 : 0;
      postureScore = attestPts + scorePts + ownerPts + shadowPts + keyPts;
    }

    return {
      enriched, total, attested, shadow, aiMcp, atRisk, noOwner, noTeam, noSpiffe,
      trustCounts, avgScore, categories, owaspFindings, owaspPassing, topRisks,
      sas, withUserKeys, oldKeys, defaultSAs,
      publicIngress, internalOnly, sharedSAList,
      expiring24h, expiring48h, postureScore,
    };
  }, [workloads]);

  // Posture breakdown for the ring
  const postureBreakdown = stats.total > 0 ? [
    { label: 'Attestation', value: Math.round((stats.attested / stats.total) * 30), max: 30, color: '#10b981' },
    { label: 'Avg Score', value: Math.round((stats.avgScore / 100) * 25), max: 25, color: '#3b82f6' },
    { label: 'Ownership', value: Math.round(((stats.total - stats.noOwner) / stats.total) * 20), max: 20, color: '#f59e0b' },
    { label: 'No Shadows', value: Math.round(((stats.total - stats.shadow) / stats.total) * 15), max: 15, color: '#a78bfa' },
    { label: 'Key Hygiene', value: stats.withUserKeys.length === 0 ? 10 : stats.oldKeys.length === 0 ? 5 : 0, max: 10, color: '#22d3ee' },
  ] : [];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 gap-3">
        <Loader className="w-5 h-5 text-accent animate-spin" />
        <span className="text-sm text-nhi-muted">Loading dashboard...</span>
      </div>
    );
  }

  return (
    <div className="max-w-full">
      {/* Row 1: Metrics */}
      <div className="grid grid-cols-5 gap-4 mb-6 stagger">
        <MetricCard label="Total NHIs" value={stats.total} sub={`${Object.keys(stats.categories).length} categories`} icon={Server} color="#7c6ff0" onClick={() => navigate('/workloads')} />
        <MetricCard label="Attested" value={stats.attested} sub={stats.total > 0 ? `${Math.round(stats.attested/stats.total*100)}% coverage` : '\u2014'} icon={ShieldCheck} color="#34d399" />
        <MetricCard label="At Risk" value={stats.atRisk} sub="Score below 70" icon={AlertTriangle} color="#ef4444" />
        <MetricCard label="Shadow" value={stats.shadow} sub={`${stats.noOwner} without owner`} icon={Eye} color="#f97316" />
        <MetricCard label="AI / MCP" value={stats.aiMcp} sub="Agents & MCP servers" icon={Bot} color="#a78bfa" />
      </div>

      {/* Row 1.5: Policy Enforcement Status */}
      {enforcement && (
        <div className="nhi-card p-5 mb-6 animate-fadeInUp" style={{ animationDelay: '0.15s' }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-accent" />
              <span className="text-sm font-bold text-nhi-text">Policy Enforcement</span>
            </div>
            <div className="flex items-center gap-3">
              {graphSummary?.enforced_paths > 0 && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1" style={{ background: '#10b98118', color: '#10b981' }}>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> {graphSummary.enforced_paths} paths enforced
                </span>
              )}
              {graphSummary?.unmitigated_paths > 0 && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1" style={{ background: '#ef444418', color: '#ef4444' }}>
                  {graphSummary.unmitigated_paths} unmitigated
                </span>
              )}
              <button onClick={() => navigate('/policies')} className="text-[10px] font-semibold text-accent hover:text-accent/80 flex items-center gap-1">
                Manage <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="px-3 py-2.5 rounded-lg" style={{ background: '#10b98108', border: '1px solid #10b98115' }}>
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold">Enforcing</div>
              <div className="text-[20px] font-bold text-emerald-400 mt-0.5">{enforcement.summary.enforcing}</div>
              <div className="text-[9px] text-nhi-muted">policies active</div>
            </div>
            <div className="px-3 py-2.5 rounded-lg" style={{ background: '#f59e0b08', border: '1px solid #f59e0b15' }}>
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold">Audit Mode</div>
              <div className="text-[20px] font-bold text-amber-400 mt-0.5">{enforcement.summary.auditing}</div>
              <div className="text-[9px] text-nhi-muted">logging only</div>
            </div>
            <div className="px-3 py-2.5 rounded-lg" style={{ background: enforcement.summary.total_open_violations > 0 ? '#ef444408' : '#10b98108', border: `1px solid ${enforcement.summary.total_open_violations > 0 ? '#ef444415' : '#10b98115'}` }}>
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold">Open Violations</div>
              <div className={`text-[20px] font-bold mt-0.5 ${enforcement.summary.total_open_violations > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {enforcement.summary.total_open_violations}
              </div>
              <div className="text-[9px] text-nhi-muted">{enforcement.summary.recent_violations_24h} in last 24h</div>
            </div>
            <div className="px-3 py-2.5 rounded-lg" style={{ background: '#3b82f608', border: '1px solid #3b82f615' }}>
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold">Decisions (24h)</div>
              <div className="text-[20px] font-bold text-blue-400 mt-0.5">{enforcement.summary.decisions_24h?.total || 0}</div>
              <div className="text-[9px] text-nhi-muted">
                {enforcement.summary.decisions_24h?.denied || 0} blocked
                {enforcement.summary.decisions_24h?.audit_denied > 0 && ` · ${enforcement.summary.decisions_24h.audit_denied} audit-logged`}
              </div>
            </div>
          </div>

          {/* Per-policy status */}
          {enforcement.policies.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold">Active Policies</div>
              {enforcement.policies.map((p) => (
                <div key={p.id} className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                  p.mode === 'enforce' ? 'bg-emerald-500/[0.03] hover:bg-emerald-500/[0.06]' : 'bg-amber-500/[0.03] hover:bg-amber-500/[0.06]'
                }`}>
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    p.mode === 'enforce' ? 'bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.4)]' : 'bg-amber-400 shadow-[0_0_6px_rgba(245,158,11,0.3)]'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <span className="text-[11px] font-semibold text-nhi-text">{p.name}</span>
                  </div>
                  <span className={`text-[8px] font-bold px-2 py-0.5 rounded-full ${
                    p.mode === 'enforce' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'
                  }`}>
                    {p.mode === 'enforce' ? '● ENFORCING' : '◐ AUDIT'}
                  </span>
                  {p.open_violations > 0 ? (
                    <span className="text-[9px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">{p.open_violations} violations</span>
                  ) : p.evaluation_count > 0 ? (
                    <span className="text-[9px] font-semibold text-emerald-400">✓ clean</span>
                  ) : (
                    <span className="text-[9px] text-nhi-faint">not evaluated</span>
                  )}
                  {p.last_evaluated && (
                    <span className="text-[8px] text-nhi-faint">{new Date(p.last_evaluated).toLocaleString()}</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Recent enforcement events */}
          {enforcement.recent_violations.length > 0 && (
            <div className="mt-3 pt-3 border-t border-white/[0.04]">
              <div className="text-[9px] text-nhi-faint uppercase tracking-widest font-bold mb-1.5">Recent Enforcement Events (24h)</div>
              {enforcement.recent_violations.slice(0, 5).map((v, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px] py-1.5 border-t border-white/[0.02]">
                  <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                  <span className="font-mono text-nhi-text font-semibold">{v.workload_name}</span>
                  <span className="text-nhi-muted flex-1 truncate">{v.policy_name}: {v.message}</span>
                  <span className="text-[8px] text-nhi-faint flex-shrink-0">{new Date(v.created_at).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          )}

          {/* Empty state */}
          {enforcement.policies.length === 0 && (
            <div className="text-center py-4">
              <Shield className="w-6 h-6 text-nhi-faint mx-auto mb-2" />
              <div className="text-[11px] text-nhi-muted">No policies deployed yet.</div>
              <button onClick={() => navigate('/graph')} className="text-[10px] text-accent font-semibold mt-1 hover:text-accent/80">
                View attack paths to get started →
              </button>
            </div>
          )}
        </div>
      )}

      {/* Row 2: Trust Distribution + Posture Score + Coverage */}
      <div className="grid grid-cols-[1fr_auto_1fr] gap-4 mb-6">
        {/* Trust Distribution */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.2s' }}>
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-accent" />
            <span className="text-sm font-bold text-nhi-text">Trust Distribution</span>
          </div>
          <TrustBar counts={stats.trustCounts} total={stats.total} />
          <div className="grid grid-cols-3 gap-2 mt-4">
            {['cryptographic', 'very-high', 'high', 'medium', 'low', 'none'].map(level => {
              const c = TRUST_COLORS[level];
              const count = stats.trustCounts[level] || 0;
              return (
                <div key={level} className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background: c.text }} />
                  <span className="text-[10px] text-nhi-muted">{c.label}</span>
                  <span className="text-[10px] font-bold font-mono ml-auto" style={{ color: c.text }}>{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Posture Score — Enhanced with breakdown */}
        <div className="nhi-card p-5 flex flex-col items-center justify-center animate-fadeInUp" style={{ animationDelay: '0.25s', minWidth: 200 }}>
          <span className="text-[10px] font-bold text-nhi-faint uppercase tracking-widest mb-3">Posture Score</span>
          <PostureScoreRing score={stats.postureScore} breakdown={postureBreakdown} total={stats.total} />
        </div>

        {/* Coverage by Category */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.3s' }}>
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-accent" />
            <span className="text-sm font-bold text-nhi-text">Coverage by Category</span>
          </div>
          <div className="space-y-2">
            {Object.entries(stats.categories).sort((a, b) => b[1].count - a[1].count).slice(0, 6).map(([cat, data]) => {
              const pct = data.count > 0 ? Math.round(data.attested / data.count * 100) : 0;
              return (
                <div key={cat}>
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[10px] text-nhi-muted flex items-center gap-1"><span>{data.icon}</span> {cat}</span>
                    <span className="text-[9px] font-mono text-nhi-faint">{data.attested}/{data.count} ({pct}%)</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/[0.03] overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${pct}%`, background: pct === 100 ? '#10b981' : pct >= 70 ? '#3b82f6' : pct >= 40 ? '#f59e0b' : '#ef4444' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Row 3: OWASP NHI Top 10 + Top Risks (Enhanced) */}
      <div className="grid grid-cols-[1.3fr_0.7fr] gap-4 mb-6">
        {/* OWASP NHI Top 10 */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.35s' }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-accent" />
              <span className="text-sm font-bold text-nhi-text">OWASP NHI Top 10</span>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full" style={{
              background: stats.owaspPassing >= 8 ? '#10b98118' : stats.owaspPassing >= 5 ? '#f59e0b18' : '#ef444418',
              color: stats.owaspPassing >= 8 ? '#10b981' : stats.owaspPassing >= 5 ? '#f59e0b' : '#ef4444',
            }}>
              {stats.owaspPassing}/10 passing
            </span>
          </div>
          <div className="space-y-1">
            {stats.owaspFindings.map((f) => {
              const passing = f.count === 0;
              const FindingIcon = f.icon;
              return (
                <div key={f.id} className="flex items-center gap-3 py-1.5 px-2 rounded hover:bg-white/[0.02] transition-colors">
                  <span className="text-[9px] font-bold text-nhi-faint w-8 shrink-0">{f.id}</span>
                  <FindingIcon className="w-3.5 h-3.5 shrink-0" style={{ color: passing ? '#10b981' : '#ef4444' }} />
                  <div className="flex-1 min-w-0">
                    <span className="text-[10px] font-medium text-nhi-muted block">{f.title}</span>
                    <span className="text-[8px] text-nhi-faint block">{f.desc}</span>
                  </div>
                  {passing ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0"
                      style={{ background: '#ef444418', color: '#ef4444' }}>
                      {f.count} issue{f.count !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Risks — ENHANCED with findings + workload names */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.4s' }}>
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-sm font-bold text-nhi-text">Top Risks & Findings</span>
          </div>

          {/* Risk findings — aggregated and actionable */}
          <div className="space-y-2 mb-4">
            {[
              stats.noOwner > 0 && { severity: 'critical', icon: Users, finding: `${stats.noOwner} identities have no owner`, detail: 'No accountability for lifecycle management', workloads: stats.enriched.filter(w => !w.owner).slice(0, 3).map(w => w.name), action: () => navigate('/workloads') },
              stats.noTeam > 0 && { severity: 'high', icon: Users, finding: `${stats.noTeam} identities have no team`, detail: 'No escalation path for incidents', workloads: stats.enriched.filter(w => !w.team).slice(0, 3).map(w => w.name), action: () => navigate('/workloads') },
              stats.withUserKeys.length > 0 && { severity: 'medium', icon: Key, finding: `${stats.withUserKeys.length} SA with user-managed keys`, detail: stats.oldKeys.length > 0 ? `${stats.oldKeys.length} key(s) over 90 days old` : 'Keys should be rotated regularly', workloads: stats.withUserKeys.map(w => w.name), action: () => navigate('/workloads') },
              stats.sharedSAList.length > 0 && { severity: 'medium', icon: Fingerprint, finding: `${stats.sharedSAList.length} shared service account`, detail: `Used by ${stats.sharedSAList[0]?.[1]?.length || 0} services \u2014 violates least-privilege`, workloads: [stats.sharedSAList[0]?.[0]?.split('@')[0]], action: () => navigate('/workloads') },
              stats.publicIngress.length > 3 && { severity: 'low', icon: Unlock, finding: `${stats.publicIngress.length} services publicly exposed`, detail: 'Consider restricting to internal traffic', workloads: stats.publicIngress.slice(0, 3).map(w => w.name), action: () => navigate('/workloads') },
              stats.expiring24h.length > 0 && { severity: 'critical', icon: Clock, finding: `${stats.expiring24h.length} attestation(s) expiring in <24h`, detail: 'Re-attest to maintain trust levels', workloads: stats.expiring24h.slice(0, 3).map(w => w.name), action: () => navigate('/workloads') },
            ].filter(Boolean).slice(0, 5).map((r, i) => {
              const RiskIcon = r.icon;
              const severityColor = RISK_COLORS[r.severity] || RISK_COLORS.medium;
              return (
                <div key={i} className="rounded-lg cursor-pointer hover:brightness-110 transition-all"
                  onClick={r.action}
                  style={{ borderLeft: `3px solid ${severityColor}`, background: `${severityColor}08`, padding: '8px 10px' }}>
                  <div className="flex items-center gap-2">
                    <RiskIcon className="w-3.5 h-3.5 shrink-0" style={{ color: severityColor }} />
                    <span className="text-[11px] font-semibold flex-1" style={{ color: severityColor }}>{r.finding}</span>
                  </div>
                  <div className="text-[9px] text-nhi-faint mt-1">{r.detail}</div>
                  {/* Affected workloads */}
                  {r.workloads && r.workloads.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {r.workloads.map((name, j) => (
                        <span key={j} className="text-[8px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.06] text-nhi-muted">
                          {name?.replace('wid-dev-', '')}
                        </span>
                      ))}
                      {stats.noOwner > 3 && i === 0 && (
                        <span className="text-[8px] text-nhi-faint">+{stats.noOwner - 3} more</span>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            {stats.noOwner === 0 && stats.noTeam === 0 && stats.withUserKeys.length === 0 && stats.expiring24h.length === 0 && (
              <div className="text-center py-6">
                <CheckCircle2 className="w-7 h-7 text-emerald-400/50 mx-auto mb-2" />
                <span className="text-[11px] text-nhi-muted">No critical findings</span>
              </div>
            )}
          </div>

          {/* Quick gaps summary */}
          {(stats.noSpiffe > 0 || stats.enriched.filter(w => !w.environment || w.environment === 'unknown').length > 0) && (
            <div className="pt-3 border-t border-white/[0.04]">
              <span className="text-[9px] font-bold text-nhi-faint uppercase tracking-widest">Additional Gaps</span>
              <div className="space-y-1 mt-2">
                {stats.noSpiffe > 0 && (
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-amber-400/80">No SPIFFE ID</span>
                    <span className="font-bold text-amber-400 font-mono">{stats.noSpiffe}</span>
                  </div>
                )}
                {stats.enriched.filter(w => !w.environment || w.environment === 'unknown').length > 0 && (
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-amber-400/80">Unknown environment</span>
                    <span className="font-bold text-amber-400 font-mono">{stats.enriched.filter(w => !w.environment || w.environment === 'unknown').length}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Row 4: Credential Hygiene + Access Exposure + Attestation Health */}
      <div className="grid grid-cols-3 gap-4 mb-6">

        {/* Credential & Key Hygiene */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.45s' }}>
          <div className="flex items-center gap-2 mb-4">
            <Key className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-bold text-nhi-text">Credential Hygiene</span>
          </div>

          {/* SA summary metrics */}
          <div className="grid grid-cols-2 gap-2 mb-4">
            {[
              { label: 'Service Accounts', value: stats.sas.length, color: '#7c6ff0' },
              { label: 'User-Managed Keys', value: stats.withUserKeys.length, color: stats.withUserKeys.length > 0 ? '#f59e0b' : '#10b981' },
              { label: 'Keys > 90 Days', value: stats.oldKeys.length, color: stats.oldKeys.length > 0 ? '#ef4444' : '#10b981' },
              { label: 'Default SAs', value: stats.defaultSAs.length, color: stats.defaultSAs.length > 0 ? '#f97316' : '#10b981' },
            ].map((m, i) => (
              <div key={i} className="text-center py-2 px-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className="text-[16px] font-bold font-mono" style={{ color: m.color }}>{m.value}</div>
                <div className="text-[8px] text-nhi-faint font-medium uppercase tracking-wider">{m.label}</div>
              </div>
            ))}
          </div>

          {/* Per-SA details */}
          <div className="space-y-1.5">
            {stats.sas.map((sa, i) => {
              const keys = sa.metadata?.user_managed_keys || 0;
              const age = sa.metadata?.oldest_key_age_days || 0;
              const hygiene = keys === 0 ? { label: 'Excellent', color: '#10b981' } : age > 90 ? { label: 'Critical', color: '#ef4444' } : age > 30 ? { label: 'Fair', color: '#f59e0b' } : { label: 'Good', color: '#3b82f6' };
              return (
                <div key={i} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-white/[0.02] transition-colors">
                  <div className="min-w-0 flex-1">
                    <span className="text-[10px] font-semibold text-nhi-muted font-mono truncate block">{sa.name}</span>
                    <span className="text-[8px] text-nhi-faint">{keys > 0 ? `${keys} key${keys > 1 ? 's' : ''} \u00b7 ${age}d old` : 'Platform-managed'}</span>
                  </div>
                  <span className="text-[8px] font-bold px-1.5 py-0.5 rounded shrink-0"
                    style={{ background: `${hygiene.color}15`, color: hygiene.color, border: `1px solid ${hygiene.color}30` }}>
                    {hygiene.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Access & Exposure */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.5s' }}>
          <div className="flex items-center gap-2 mb-4">
            <Lock className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-bold text-nhi-text">Access & Exposure</span>
          </div>

          {/* Network exposure */}
          <div className="mb-4">
            <span className="text-[9px] font-bold text-nhi-faint uppercase tracking-widest">Network Exposure</span>
            <div className="space-y-1.5 mt-2">
              {stats.enriched.filter(w => w.metadata?.ingress).map((w, i) => {
                const isPublic = w.metadata.ingress === 'INGRESS_TRAFFIC_ALL';
                return (
                  <div key={i} className="flex items-center justify-between py-1 px-2 rounded"
                    style={{ background: isPublic ? 'rgba(249,115,22,0.04)' : 'rgba(16,185,129,0.04)', border: `1px solid ${isPublic ? 'rgba(249,115,22,0.1)' : 'rgba(16,185,129,0.1)'}` }}>
                    <div className="flex items-center gap-1.5">
                      {isPublic ? <Unlock className="w-3 h-3 text-orange-400" /> : <Lock className="w-3 h-3 text-emerald-400" />}
                      <span className="text-[10px] font-mono text-nhi-muted">{w.name.replace('wid-dev-', '')}</span>
                    </div>
                    <span className="text-[8px] font-bold px-1.5 py-0.5 rounded"
                      style={{ background: isPublic ? '#f9731615' : '#10b98115', color: isPublic ? '#f97316' : '#10b981' }}>
                      {isPublic ? 'PUBLIC' : 'INTERNAL'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Shared SA warning */}
          {stats.sharedSAList.length > 0 && (
            <div className="pt-3 border-t border-white/[0.04]">
              <span className="text-[9px] font-bold text-nhi-faint uppercase tracking-widest">Shared Identities</span>
              {stats.sharedSAList.map(([sa, services], i) => (
                <div key={i} className="mt-2 p-2.5 rounded-lg bg-orange-500/[0.04] border border-orange-500/10">
                  <div className="flex items-center gap-1.5 mb-1">
                    <AlertTriangle className="w-3 h-3 text-orange-400" />
                    <span className="text-[10px] font-semibold text-orange-400">{services.length} services share 1 SA</span>
                  </div>
                  <span className="text-[8px] font-mono text-nhi-faint block truncate" title={sa}>{sa.split('@')[0]}</span>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {services.slice(0, 4).map((s, j) => (
                      <span key={j} className="text-[7px] font-mono px-1 py-0.5 rounded bg-white/[0.04] text-nhi-faint">{s.replace('wid-dev-', '')}</span>
                    ))}
                    {services.length > 4 && <span className="text-[7px] text-nhi-faint">+{services.length - 4}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attestation Health */}
        <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.55s' }}>
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-bold text-nhi-text">Attestation Health</span>
          </div>

          {/* Expiry timeline bar */}
          <div className="mb-4">
            <span className="text-[9px] font-bold text-nhi-faint uppercase tracking-widest">Expiry Timeline</span>
            <div className="flex h-5 rounded overflow-hidden bg-white/[0.03] mt-2">
              {stats.expiring24h.length > 0 && (
                <div className="flex items-center justify-center" style={{
                  flex: stats.expiring24h.length, background: 'rgba(239,68,68,0.15)',
                  borderRight: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <span className="text-[8px] font-bold text-red-400">{stats.expiring24h.length} &lt;24h</span>
                </div>
              )}
              {stats.expiring48h.length > 0 && (
                <div className="flex items-center justify-center" style={{
                  flex: stats.expiring48h.length, background: 'rgba(59,130,246,0.12)',
                }}>
                  <span className="text-[8px] font-bold text-blue-400">{stats.expiring48h.length} 24-48h</span>
                </div>
              )}
              {stats.expiring24h.length === 0 && stats.expiring48h.length === 0 && (
                <div className="flex items-center justify-center flex-1" style={{ background: 'rgba(16,185,129,0.1)' }}>
                  <span className="text-[8px] font-bold text-emerald-400">All current</span>
                </div>
              )}
            </div>
          </div>

          {/* Coverage metrics */}
          <div className="grid grid-cols-2 gap-2 mb-4">
            <div className="text-center py-2 px-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <div className="text-[16px] font-bold font-mono text-emerald-400">{stats.attested}</div>
              <div className="text-[8px] text-nhi-faint font-medium uppercase tracking-wider">Attested</div>
            </div>
            <div className="text-center py-2 px-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <div className="text-[16px] font-bold font-mono" style={{ color: stats.total - stats.attested > 0 ? '#f97316' : '#10b981' }}>
                {stats.total - stats.attested}
              </div>
              <div className="text-[8px] text-nhi-faint font-medium uppercase tracking-wider">Unattested</div>
            </div>
          </div>

          {/* Per-workload attestation details */}
          <div className="space-y-1">
            {stats.enriched.slice(0, 6).map((w, i) => {
              const ad = (() => {
                if (!w.attestation_data) return null;
                if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } }
                return w.attestation_data;
              })();
              const tc = TRUST_COLORS[w.trust_level] || TRUST_COLORS.none;
              const exp = ad?.expires_at ? new Date(ad.expires_at) : null;
              const hoursLeft = exp ? Math.max(0, Math.round((exp - Date.now()) / 3600000)) : null;
              const urgent = hoursLeft !== null && hoursLeft < 24;

              return (
                <div key={i} className="flex items-center gap-2 py-1 px-2 rounded transition-colors"
                  style={{ background: urgent ? 'rgba(239,68,68,0.04)' : 'transparent' }}>
                  <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: tc.text, boxShadow: `0 0 4px ${tc.text}40` }} />
                  <span className="text-[10px] font-mono text-nhi-muted truncate flex-1">{w.name.replace('wid-dev-', '')}</span>
                  <span className="text-[8px] font-mono text-nhi-faint shrink-0">
                    {ad ? `${ad.methods_passed || 0}/${ad.methods_attempted || 0}` : '\u2014'}
                  </span>
                  <span className="text-[8px] font-mono shrink-0" style={{ color: urgent ? '#ef4444' : '#666' }}>
                    {hoursLeft !== null ? `${hoursLeft}h` : '\u2014'}
                  </span>
                  {ad?.multi_signal_bonus && <span className="text-[8px] text-cyan-400 shrink-0">\u2726</span>}
                </div>
              );
            })}
            {stats.enriched.length > 6 && (
              <button onClick={() => navigate('/workloads')} className="text-[9px] text-accent hover:text-accent-light flex items-center gap-1 mt-1 ml-2">
                View all {stats.total} <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Row 5: Quick Actions */}
      <div className="nhi-card p-5 animate-fadeInUp" style={{ animationDelay: '0.6s' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-accent" />
            <span className="text-sm font-bold text-nhi-text">Quick Actions</span>
          </div>
          <button onClick={() => navigate('/workloads')} className="text-[10px] text-accent hover:text-accent-light transition-colors flex items-center gap-1">
            View all identities <ArrowRight className="w-3 h-3" />
          </button>
        </div>
        <div className="grid grid-cols-4 gap-3 mt-4">
          <button onClick={() => navigate('/workloads')}
            className="p-3 rounded-lg bg-orange-500/5 border border-orange-500/10 hover:bg-orange-500/10 transition-colors text-left">
            <Eye className="w-4 h-4 text-orange-400 mb-2" />
            <span className="text-[10px] font-bold text-nhi-muted block">Review Shadows</span>
            <span className="text-[8px] text-nhi-faint">{stats.shadow} unverified identities</span>
          </button>
          <button onClick={() => navigate('/workloads')}
            className="p-3 rounded-lg bg-red-500/5 border border-red-500/10 hover:bg-red-500/10 transition-colors text-left">
            <Users className="w-4 h-4 text-red-400 mb-2" />
            <span className="text-[10px] font-bold text-nhi-muted block">Assign Owners</span>
            <span className="text-[8px] text-nhi-faint">{stats.noOwner} need an owner</span>
          </button>
          <button onClick={() => navigate('/workloads')}
            className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/10 hover:bg-purple-500/10 transition-colors text-left">
            <Bot className="w-4 h-4 text-purple-400 mb-2" />
            <span className="text-[10px] font-bold text-nhi-muted block">AI Agent Security</span>
            <span className="text-[8px] text-nhi-faint">{stats.aiMcp} agents to review</span>
          </button>
          <button onClick={() => navigate('/policies/create')}
            className="p-3 rounded-lg bg-accent/5 border border-accent/10 hover:bg-accent/10 transition-colors text-left">
            <Shield className="w-4 h-4 text-accent mb-2" />
            <span className="text-[10px] font-bold text-nhi-muted block">Create Policy</span>
            <span className="text-[8px] text-nhi-faint">Enforce governance rules</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;