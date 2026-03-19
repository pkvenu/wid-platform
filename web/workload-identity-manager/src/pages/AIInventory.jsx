import React, { useState, useEffect, useCallback } from 'react';
import {
  Bot, Server, Wrench, Brain, Database, AlertTriangle,
  Loader, RefreshCw, ArrowRight, Shield, ChevronDown,
  ChevronUp, Clock, ExternalLink, Bug, XCircle, Info,
} from 'lucide-react';

/* ═══════════════════════════════════════════
   Constants
   ═══════════════════════════════════════════ */

const SEVERITY_CFG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', label: 'CRITICAL' },
  high:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', label: 'HIGH' },
  medium:   { color: '#3b82f6', bg: 'rgba(59,130,246,0.08)', label: 'MEDIUM' },
  low:      { color: '#10b981', bg: 'rgba(16,185,129,0.08)', label: 'LOW' },
  info:     { color: '#64748b', bg: 'rgba(100,116,139,0.08)', label: 'INFO' },
};

const CARD_CONFIG = [
  { key: 'agents',       label: 'Agents',       icon: Bot,      color: '#a78bfa', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.2)' },
  { key: 'mcp_servers',  label: 'MCP Servers',   icon: Server,   color: '#3b82f6', bg: 'rgba(59,130,246,0.08)',  border: 'rgba(59,130,246,0.2)' },
  { key: 'tools',        label: 'Tools',         icon: Wrench,   color: '#14b8a6', bg: 'rgba(20,184,166,0.08)',  border: 'rgba(20,184,166,0.2)' },
  { key: 'models',       label: 'Models',        icon: Brain,    color: '#10b981', bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.2)' },
  { key: 'data_sources', label: 'Data Sources',  icon: Database,  color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.2)' },
];

const ATLAS_TACTICS = [
  { id: 'ML.TA0001', name: 'Reconnaissance' },
  { id: 'ML.TA0002', name: 'Resource Development' },
  { id: 'ML.TA0003', name: 'Initial Access' },
  { id: 'ML.TA0004', name: 'ML Model Access' },
  { id: 'ML.TA0005', name: 'Execution' },
  { id: 'ML.TA0006', name: 'Persistence' },
  { id: 'ML.TA0007', name: 'Defense Evasion' },
  { id: 'ML.TA0008', name: 'Discovery' },
  { id: 'ML.TA0009', name: 'Collection' },
  { id: 'ML.TA0010', name: 'Exfiltration' },
  { id: 'ML.TA0011', name: 'Impact' },
];

/* ═══════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════ */

function SkeletonCard() {
  return (
    <div className="rounded-xl border p-4 animate-pulse" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
      <div className="h-4 w-16 rounded bg-surface-3 mb-3" />
      <div className="h-8 w-12 rounded bg-surface-3 mb-2" />
      <div className="h-3 w-24 rounded bg-surface-3" />
    </div>
  );
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-4 py-3 animate-pulse">
      <div className="h-4 w-32 rounded bg-surface-3" />
      <div className="h-4 w-16 rounded bg-surface-3" />
      <div className="h-4 w-12 rounded bg-surface-3" />
      <div className="h-4 w-12 rounded bg-surface-3" />
      <div className="h-4 w-12 rounded bg-surface-3" />
      <div className="h-4 w-12 rounded bg-surface-3" />
    </div>
  );
}

function ViolationBadge({ count, severity }) {
  const cfg = SEVERITY_CFG[severity] || SEVERITY_CFG.medium;
  if (!count || count === 0) return <span className="text-[10px] text-nhi-ghost font-mono">0</span>;
  const color = severity === 'critical' && count > 100 ? '#ef4444'
    : severity === 'high' && count > 50 ? '#f97316'
    : count === 0 ? '#10b981' : cfg.color;
  return (
    <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded" style={{ background: cfg.bg, color }}>
      {count}
    </span>
  );
}

function SeverityBadge({ severity, count }) {
  const cfg = SEVERITY_CFG[severity] || SEVERITY_CFG.info;
  return (
    <span className="text-[8px] font-bold px-1.5 py-0.5 rounded inline-flex items-center gap-1" style={{ background: cfg.bg, color: cfg.color }}>
      {cfg.label}{count != null && `: ${count}`}
    </span>
  );
}

function formatTimeAgo(ts) {
  if (!ts) return '';
  const now = Date.now();
  const d = now - new Date(ts).getTime();
  if (d < 60000) return 'just now';
  if (d < 3600000) return `${Math.floor(d / 60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d / 3600000)}h ago`;
  return `${Math.floor(d / 86400000)}d ago`;
}

/* ═══════════════════════════════════════════
   API Fetch Helper
   ═══════════════════════════════════════════ */

async function safeFetch(url) {
  try {
    const res = await fetch(url, { credentials: 'include' });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════
   Main Component
   ═══════════════════════════════════════════ */

export default function AIInventory() {
  const [inventory, setInventory] = useState(null);
  const [violations, setViolations] = useState(null);
  const [atlasCoverage, setAtlasCoverage] = useState(null);
  const [cves, setCves] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedCard, setExpandedCard] = useState(null);
  const [sortField, setSortField] = useState('violations_7d');
  const [sortDir, setSortDir] = useState('desc');
  const [selectedAgent, setSelectedAgent] = useState(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [inv, viol, atlas, cveData] = await Promise.all([
        safeFetch('/api/v1/ai-inventory'),
        safeFetch('/api/v1/violations/by-agent?days=7'),
        safeFetch('/api/v1/graph/atlas-coverage'),
        safeFetch('/api/v1/graph/cves'),
      ]);
      setInventory(inv);
      setViolations(viol);
      setAtlasCoverage(atlas);
      setCves(cveData);
      if (!inv && !viol && !atlas && !cveData) {
        setError('Unable to reach AI Inventory APIs. Backend services may not be deployed yet.');
      }
    } catch (e) {
      console.error('AI Inventory fetch error:', e);
      setError('Failed to load AI Inventory data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  /* ── Sorting ── */
  const sortedAgents = (() => {
    const agents = violations?.agents || [];
    return [...agents].sort((a, b) => {
      const av = a[sortField] ?? 0;
      const bv = b[sortField] ?? 0;
      return sortDir === 'desc' ? bv - av : av - bv;
    });
  })();

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const SortIndicator = ({ field }) => {
    if (sortField !== field) return null;
    return sortDir === 'desc'
      ? <ChevronDown className="w-3 h-3 inline ml-0.5" />
      : <ChevronUp className="w-3 h-3 inline ml-0.5" />;
  };

  /* ── ATLAS Coverage Helpers ── */
  const atlasMatrix = atlasCoverage?.matrix || {};
  const atlasCoveragePct = atlasCoverage?.coverage_pct ?? 0;

  const getAtlasCellColor = (tacticId, techniqueId) => {
    const cell = atlasMatrix?.[tacticId]?.[techniqueId];
    if (!cell) return { bg: 'var(--surface-3)', text: 'var(--text-ghost)', status: 'not_covered' };
    if (cell.findings > 0) return { bg: 'rgba(239,68,68,0.15)', text: '#ef4444', status: 'findings' };
    if (cell.active) return { bg: 'rgba(16,185,129,0.15)', text: '#10b981', status: 'active' };
    return { bg: 'rgba(245,158,11,0.1)', text: '#f59e0b', status: 'mapped' };
  };

  /* ── All unique technique IDs across all tactics ── */
  const allTechniques = (() => {
    const set = new Set();
    for (const tacticId of Object.keys(atlasMatrix)) {
      for (const techId of Object.keys(atlasMatrix[tacticId] || {})) {
        set.add(techId);
      }
    }
    return [...set].sort();
  })();

  /* ═══════ RENDER ═══════ */

  if (loading) {
    return (
      <div className="flex-1 flex flex-col h-full overflow-auto">
        <div className="px-6 py-5 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center gap-3">
            <Bot className="w-5 h-5 text-accent" />
            <div>
              <h1 className="text-[16px] font-bold text-nhi-text">AI Inventory</h1>
              <p className="text-[11px] text-nhi-dim">Loading agent and AI asset inventory...</p>
            </div>
          </div>
        </div>
        <div className="px-6 py-5">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
            {[1,2,3,4,5].map(i => <SkeletonCard key={i} />)}
          </div>
          <div className="rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
            {[1,2,3,4,5].map(i => <SkeletonRow key={i} />)}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col h-full overflow-auto">
      {/* ── Header ── */}
      <div className="flex-shrink-0 px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-3">
          <Bot className="w-5 h-5 text-accent" />
          <div>
            <h1 className="text-[16px] font-bold text-nhi-text">AI Inventory</h1>
            <p className="text-[11px] text-nhi-dim">Agents, MCP servers, tools, models, and data sources across your environment.</p>
          </div>
          <div className="flex-1" />
          <button onClick={fetchAll}
            className="text-[9px] font-bold px-2.5 py-1.5 rounded-md border text-nhi-dim bg-surface-3 border-[var(--border)] hover:bg-surface-2 flex items-center gap-1.5">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* ── Error Banner ── */}
      {error && (
        <div className="mx-6 mt-4 flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
          <Info className="w-4 h-4 text-amber-400 shrink-0" />
          <span className="text-[10px] text-amber-400 font-medium">{error}</span>
        </div>
      )}

      <div className="px-6 py-5 space-y-6">
        {/* ═══════ SUMMARY CARDS ═══════ */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          {CARD_CONFIG.map(cfg => {
            const Icon = cfg.icon;
            const data = inventory?.[cfg.key];
            const count = data?.total ?? data?.count ?? 0;
            const breakdown = data?.breakdown || {};
            const isExpanded = expandedCard === cfg.key;

            return (
              <div
                key={cfg.key}
                onClick={() => setExpandedCard(isExpanded ? null : cfg.key)}
                className="rounded-xl border p-4 cursor-pointer transition-all duration-200 hover:shadow-[0_0_20px_rgba(124,111,240,0.08)]"
                style={{
                  borderColor: isExpanded ? cfg.border : 'var(--border)',
                  background: isExpanded ? cfg.bg : 'var(--surface-2)',
                }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: cfg.bg }}>
                    <Icon className="w-4 h-4" style={{ color: cfg.color }} />
                  </div>
                  <span className="text-[10px] font-semibold text-nhi-dim">{cfg.label}</span>
                </div>
                <div className="text-[28px] font-bold leading-none mb-1" style={{ color: cfg.color }}>
                  {inventory ? count : '--'}
                </div>
                {/* Sub-breakdown */}
                {isExpanded && Object.keys(breakdown).length > 0 && (
                  <div className="mt-3 pt-3 space-y-1" style={{ borderTop: `1px solid ${cfg.border}` }}>
                    {Object.entries(breakdown).map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between">
                        <span className="text-[9px] text-nhi-dim capitalize">{k.replace(/_/g, ' ')}</span>
                        <span className="text-[10px] font-bold font-mono" style={{ color: cfg.color }}>{v}</span>
                      </div>
                    ))}
                  </div>
                )}
                {!isExpanded && Object.keys(breakdown).length > 0 && (
                  <div className="text-[8px] text-nhi-ghost mt-1">
                    {Object.entries(breakdown).slice(0, 2).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(' / ')}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* ═══════ MIDDLE SECTION: Riskiest Issues + Recent Threats ═══════ */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Riskiest AI Issues */}
          <div className="lg:col-span-2 rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
            <div className="px-4 py-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span className="text-[12px] font-bold text-nhi-text">Riskiest AI Issues</span>
              <div className="flex-1" />
              {inventory?.issues && (
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-bold text-nhi-text">{inventory.issues.total ?? 0} issues</span>
                  {(inventory.issues.by_severity || []).map(s => (
                    <SeverityBadge key={s.severity} severity={s.severity} count={s.count} />
                  ))}
                </div>
              )}
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {(inventory?.issues?.top || []).length === 0 && (
                <div className="px-4 py-8 text-center">
                  <Shield className="w-8 h-8 mx-auto mb-2 text-nhi-ghost opacity-30" />
                  <div className="text-[11px] text-nhi-faint">No AI issues detected</div>
                  <div className="text-[9px] text-nhi-ghost mt-1">Run a scan to discover AI-specific risks</div>
                </div>
              )}
              {(inventory?.issues?.top || []).map((issue, i) => {
                const sev = SEVERITY_CFG[issue.severity] || SEVERITY_CFG.medium;
                return (
                  <div key={issue.id || i} className="px-4 py-3 flex items-center gap-3 hover:bg-surface-3/30 transition-colors">
                    <div className="w-5 h-5 rounded-full flex items-center justify-center shrink-0" style={{ background: sev.bg }}>
                      <AlertTriangle className="w-3 h-3" style={{ color: sev.color }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-semibold text-nhi-text truncate">{issue.title}</div>
                      <div className="text-[9px] text-nhi-dim mt-0.5 truncate">{issue.description}</div>
                    </div>
                    {/* Mini attack path */}
                    {issue.attack_path && (
                      <div className="flex items-center gap-1 shrink-0">
                        <span className="text-[8px] font-mono text-nhi-dim">{issue.attack_path.source}</span>
                        <ArrowRight className="w-3 h-3 text-nhi-ghost" />
                        <span className="text-[8px] font-bold" style={{ color: sev.color }}>{issue.attack_path.impacted} affected</span>
                      </div>
                    )}
                    <SeverityBadge severity={issue.severity} />
                  </div>
                );
              })}
            </div>
          </div>

          {/* Recent AI Threats + CVE Panel */}
          <div className="flex flex-col gap-4">
            {/* Recent Threats */}
            <div className="rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
              <div className="px-4 py-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
                <Shield className="w-4 h-4 text-red-400" />
                <span className="text-[12px] font-bold text-nhi-text">Recent AI Threats</span>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {(inventory?.recent_threats || []).length === 0 && (
                  <div className="px-4 py-6 text-center">
                    <Shield className="w-6 h-6 mx-auto mb-2 text-emerald-400 opacity-40" />
                    <div className="text-[10px] text-nhi-faint">No recent threats</div>
                  </div>
                )}
                {(inventory?.recent_threats || []).map((threat, i) => {
                  const sev = SEVERITY_CFG[threat.severity] || SEVERITY_CFG.info;
                  return (
                    <div key={threat.id || i} className="px-4 py-2.5 flex items-start gap-2 hover:bg-surface-3/30 transition-colors">
                      <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: sev.color }} />
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] font-semibold text-nhi-text truncate">{threat.title}</div>
                        <div className="text-[8px] text-nhi-ghost flex items-center gap-1 mt-0.5">
                          <Clock className="w-2.5 h-2.5" />
                          {formatTimeAgo(threat.detected_at)}
                        </div>
                      </div>
                      <SeverityBadge severity={threat.severity} />
                    </div>
                  );
                })}
              </div>
            </div>

            {/* CVE Panel */}
            <div className="rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
              <div className="px-4 py-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
                <Bug className="w-4 h-4 text-orange-400" />
                <span className="text-[12px] font-bold text-nhi-text">AI/ML CVEs</span>
                {cves?.total != null && (
                  <span className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded bg-orange-400/10 text-orange-400 ml-auto">
                    {cves.total}
                  </span>
                )}
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {(!cves || (cves.items || []).length === 0) && (
                  <div className="px-4 py-6 text-center">
                    <Bug className="w-6 h-6 mx-auto mb-2 text-nhi-ghost opacity-30" />
                    <div className="text-[10px] text-nhi-faint">No CVEs tracked</div>
                  </div>
                )}
                {(cves?.items || []).slice(0, 5).map((cve, i) => {
                  const sev = SEVERITY_CFG[cve.severity] || SEVERITY_CFG.medium;
                  return (
                    <div key={cve.id || i} className="px-4 py-2.5 flex items-center gap-2 hover:bg-surface-3/30 transition-colors">
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] font-bold font-mono text-nhi-text">{cve.id}</div>
                        <div className="text-[8px] text-nhi-dim truncate mt-0.5">{cve.description}</div>
                      </div>
                      <SeverityBadge severity={cve.severity} />
                      {cve.url && (
                        <a href={cve.url} target="_blank" rel="noopener noreferrer"
                          className="text-nhi-ghost hover:text-accent transition-colors" onClick={e => e.stopPropagation()}>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ═══════ VIOLATIONS BY AGENT TABLE ═══════ */}
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
          <div className="px-4 py-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
            <XCircle className="w-4 h-4 text-red-400" />
            <span className="text-[12px] font-bold text-nhi-text">Security Violations by Agent</span>
            <span className="text-[9px] text-nhi-faint ml-1">(7-day window)</span>
            <div className="flex-1" />
            {violations?.summary && (
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-bold text-nhi-text">{violations.summary.total_agents} agents</span>
                <span className="text-[10px] text-nhi-ghost">/</span>
                <span className="text-[10px] font-bold text-red-400">{violations.summary.total_violations} violations</span>
              </div>
            )}
          </div>

          {/* Table Header */}
          <div className="grid grid-cols-[1fr_80px_80px_60px_60px_80px_80px] gap-2 px-4 py-2 text-[8px] font-bold uppercase text-nhi-faint tracking-wider" style={{ background: 'var(--surface-3)', borderBottom: '1px solid var(--border)' }}>
            <button onClick={() => handleSort('name')} className="text-left hover:text-nhi-dim transition-colors">
              Agent Name <SortIndicator field="name" />
            </button>
            <button onClick={() => handleSort('status')} className="text-center hover:text-nhi-dim transition-colors">
              Status <SortIndicator field="status" />
            </button>
            <button onClick={() => handleSort('violations_7d')} className="text-center hover:text-nhi-dim transition-colors">
              Violations (7d) <SortIndicator field="violations_7d" />
            </button>
            <button onClick={() => handleSort('critical')} className="text-center hover:text-nhi-dim transition-colors">
              Critical <SortIndicator field="critical" />
            </button>
            <button onClick={() => handleSort('high')} className="text-center hover:text-nhi-dim transition-colors">
              High <SortIndicator field="high" />
            </button>
            <button onClick={() => handleSort('over_privileged')} className="text-center hover:text-nhi-dim transition-colors">
              Over-Privileged <SortIndicator field="over_privileged" />
            </button>
            <button onClick={() => handleSort('mcp_issues')} className="text-center hover:text-nhi-dim transition-colors">
              MCP Issues <SortIndicator field="mcp_issues" />
            </button>
          </div>

          {/* Table Body */}
          <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {sortedAgents.length === 0 && (
              <div className="px-4 py-8 text-center">
                <Bot className="w-8 h-8 mx-auto mb-2 text-nhi-ghost opacity-30" />
                <div className="text-[11px] text-nhi-faint">No agent violation data available</div>
                <div className="text-[9px] text-nhi-ghost mt-1">Violation data will appear after agents are discovered and monitored</div>
              </div>
            )}
            {sortedAgents.map((agent, i) => {
              const totalViolations = agent.violations_7d ?? 0;
              const rowColor = totalViolations > 100 ? 'rgba(239,68,68,0.04)' : totalViolations > 50 ? 'rgba(245,158,11,0.04)' : 'transparent';
              const isSelected = selectedAgent === agent.id;

              return (
                <React.Fragment key={agent.id || i}>
                  <div
                    className="grid grid-cols-[1fr_80px_80px_60px_60px_80px_80px] gap-2 px-4 py-2.5 items-center hover:bg-surface-3/30 cursor-pointer transition-colors"
                    style={{ background: rowColor }}
                    onClick={() => setSelectedAgent(isSelected ? null : agent.id)}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <Bot className="w-3.5 h-3.5 text-accent shrink-0" />
                      <span className="text-[11px] font-semibold text-nhi-text truncate">{agent.name}</span>
                    </div>
                    <div className="text-center">
                      <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${
                        agent.status === 'active' ? 'bg-emerald-400/10 text-emerald-400'
                        : agent.status === 'warning' ? 'bg-amber-400/10 text-amber-400'
                        : agent.status === 'critical' ? 'bg-red-400/10 text-red-400'
                        : 'bg-surface-3 text-nhi-ghost'
                      }`}>
                        {(agent.status || 'unknown').toUpperCase()}
                      </span>
                    </div>
                    <div className="text-center">
                      <span className={`text-[11px] font-bold font-mono ${
                        totalViolations > 100 ? 'text-red-400' : totalViolations > 50 ? 'text-amber-400' : totalViolations > 0 ? 'text-nhi-text' : 'text-emerald-400'
                      }`}>
                        {totalViolations}
                      </span>
                    </div>
                    <div className="text-center"><ViolationBadge count={agent.critical} severity="critical" /></div>
                    <div className="text-center"><ViolationBadge count={agent.high} severity="high" /></div>
                    <div className="text-center"><ViolationBadge count={agent.over_privileged} severity="medium" /></div>
                    <div className="text-center"><ViolationBadge count={agent.mcp_issues} severity="info" /></div>
                  </div>

                  {/* Expanded violation breakdown */}
                  {isSelected && agent.breakdown && (
                    <div className="px-6 py-3" style={{ background: 'var(--surface-3)', borderTop: '1px solid var(--border)' }}>
                      <div className="text-[9px] font-bold text-nhi-faint uppercase mb-2">Violation Breakdown</div>
                      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                        {Object.entries(agent.breakdown).map(([category, count]) => (
                          <div key={category} className="flex items-center justify-between px-2 py-1.5 rounded-lg" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                            <span className="text-[9px] text-nhi-dim capitalize">{category.replace(/_/g, ' ')}</span>
                            <span className="text-[10px] font-bold font-mono text-nhi-text">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* ═══════ MITRE ATLAS COVERAGE ═══════ */}
        <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
          <div className="px-4 py-3 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
            <Shield className="w-4 h-4 text-accent" />
            <span className="text-[12px] font-bold text-nhi-text">MITRE ATLAS Coverage</span>
            <div className="flex-1" />
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ background: 'rgba(16,185,129,0.3)' }} />
                <span className="text-[8px] text-nhi-dim">Active Detection</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ background: 'rgba(245,158,11,0.2)' }} />
                <span className="text-[8px] text-nhi-dim">Mapped</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ background: 'rgba(239,68,68,0.2)' }} />
                <span className="text-[8px] text-nhi-dim">Findings</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ background: 'var(--surface-3)' }} />
                <span className="text-[8px] text-nhi-dim">Not Covered</span>
              </div>
              {atlasCoverage && (
                <span className={`text-[11px] font-bold ml-2 ${
                  atlasCoveragePct >= 80 ? 'text-emerald-400' : atlasCoveragePct >= 50 ? 'text-amber-400' : 'text-red-400'
                }`}>
                  {atlasCoveragePct}% Coverage
                </span>
              )}
            </div>
          </div>

          {!atlasCoverage ? (
            <div className="px-4 py-8 text-center">
              <Shield className="w-8 h-8 mx-auto mb-2 text-nhi-ghost opacity-30" />
              <div className="text-[11px] text-nhi-faint">ATLAS coverage data not available</div>
              <div className="text-[9px] text-nhi-ghost mt-1">Configure threat detections to see MITRE ATLAS mapping</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px]">
                <thead>
                  <tr>
                    <th className="px-2 py-2 text-left text-[8px] font-bold text-nhi-faint uppercase tracking-wider sticky left-0 z-10" style={{ background: 'var(--surface-2)', minWidth: '100px' }}>
                      Technique
                    </th>
                    {ATLAS_TACTICS.map(tactic => (
                      <th key={tactic.id} className="px-1 py-2 text-center text-[7px] font-bold text-nhi-faint uppercase tracking-wider" style={{ minWidth: '70px' }}>
                        <div className="truncate" title={tactic.name}>{tactic.name}</div>
                        <div className="text-[6px] text-nhi-ghost font-mono mt-0.5">{tactic.id}</div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {allTechniques.length === 0 && (
                    <tr>
                      <td colSpan={ATLAS_TACTICS.length + 1} className="px-4 py-6 text-center text-[10px] text-nhi-faint">
                        No techniques mapped. Coverage matrix will populate as detections are configured.
                      </td>
                    </tr>
                  )}
                  {allTechniques.map(techId => (
                    <tr key={techId} className="hover:bg-surface-3/20">
                      <td className="px-2 py-1.5 text-[8px] font-mono font-semibold text-nhi-dim sticky left-0 z-10" style={{ background: 'var(--surface-2)' }}>
                        {techId}
                      </td>
                      {ATLAS_TACTICS.map(tactic => {
                        const cell = getAtlasCellColor(tactic.id, techId);
                        return (
                          <td key={tactic.id} className="px-1 py-1.5 text-center">
                            <div
                              className="w-full h-5 rounded-sm flex items-center justify-center"
                              style={{ background: cell.bg }}
                              title={`${tactic.name} / ${techId}: ${cell.status}`}
                            >
                              {cell.status === 'findings' && (
                                <span className="text-[7px] font-bold" style={{ color: cell.text }}>
                                  {atlasMatrix[tactic.id]?.[techId]?.findings}
                                </span>
                              )}
                              {cell.status === 'active' && (
                                <div className="w-1.5 h-1.5 rounded-full" style={{ background: cell.text }} />
                              )}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
