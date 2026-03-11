import React, { useState, useEffect, useCallback } from 'react';
import { Shield, ChevronRight, ChevronLeft, CheckCircle2, XCircle, AlertTriangle,
         Loader, RefreshCw, ArrowRight, Filter } from 'lucide-react';

const FRAMEWORK_ICONS = {
  SOC2: '🛡️',
  PCI_DSS: '💳',
  NIST_800_53: '🏛️',
  ISO_27001: '🌐',
  EU_AI_ACT: '🧠',
};

const SEVERITY_CFG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', label: 'CRITICAL' },
  high:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', label: 'HIGH' },
  medium:   { color: '#3b82f6', bg: 'rgba(59,130,246,0.08)', label: 'MEDIUM' },
  low:      { color: '#10b981', bg: 'rgba(16,185,129,0.08)', label: 'LOW' },
  info:     { color: '#64748b', bg: 'rgba(100,116,139,0.08)', label: 'INFO' },
};

function ProgressBar({ pct, color = '#10b981', height = 6 }) {
  return (
    <div className="w-full rounded-full overflow-hidden" style={{ background: 'var(--surface-3)', height }}>
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.min(pct, 100)}%`, background: color }} />
    </div>
  );
}

function CoverageColor(pct) {
  if (pct >= 80) return '#10b981';
  if (pct >= 50) return '#f59e0b';
  return '#ef4444';
}

export default function Compliance() {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFw, setSelectedFw] = useState(null);
  const [fwDetail, setFwDetail] = useState(null);
  const [fwDetailLoading, setFwDetailLoading] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [deployResult, setDeployResult] = useState(null);
  const [filter, setFilter] = useState('all'); // all | deployed | not-deployed

  const fetchFrameworks = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/v1/compliance/frameworks');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFrameworks(data.frameworks || []);
    } catch (e) {
      console.error('Failed to fetch frameworks:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchFrameworkDetail = useCallback(async (fwId) => {
    try {
      setFwDetailLoading(true);
      setDeployResult(null);
      const res = await fetch(`/api/v1/compliance/frameworks/${fwId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFwDetail(data);
    } catch (e) {
      console.error('Failed to fetch framework detail:', e);
    } finally {
      setFwDetailLoading(false);
    }
  }, []);

  const deployAll = async () => {
    if (!selectedFw || deploying) return;
    try {
      setDeploying(true);
      const res = await fetch(`/api/v1/compliance/frameworks/${selectedFw}/deploy`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setDeployResult(data);
      // Refresh detail and framework list
      await fetchFrameworkDetail(selectedFw);
      await fetchFrameworks();
    } catch (e) {
      setDeployResult({ error: e.message });
    } finally {
      setDeploying(false);
    }
  };

  useEffect(() => { fetchFrameworks(); }, [fetchFrameworks]);

  useEffect(() => {
    if (selectedFw) fetchFrameworkDetail(selectedFw);
  }, [selectedFw, fetchFrameworkDetail]);

  const handleSelectFramework = (fwId) => {
    setSelectedFw(fwId);
    setFilter('all');
    setDeployResult(null);
  };

  const filteredTemplates = fwDetail?.templates?.filter(t => {
    if (filter === 'deployed') return t.deployed;
    if (filter === 'not-deployed') return !t.deployed;
    return true;
  }) || [];

  // Group templates by control for the detail view
  const templatesByControl = {};
  if (fwDetail) {
    for (const tpl of (fwDetail.templates || [])) {
      for (const ctrl of (tpl.controls || [])) {
        if (!templatesByControl[ctrl]) templatesByControl[ctrl] = [];
        templatesByControl[ctrl].push(tpl);
      }
    }
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <Loader className="w-6 h-6 animate-spin text-accent" />
      </div>
    );
  }

  // ═══════ FRAMEWORK DETAIL VIEW ═══════
  if (selectedFw && fwDetail) {
    const fw = fwDetail.framework;
    const coverageColor = CoverageColor(fwDetail.coverage_pct);
    const undeployed = (fwDetail.templates || []).filter(t => !t.deployed).length;

    return (
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Header */}
        <div className="flex-shrink-0 px-6 py-4" style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface-2)' }}>
          <div className="flex items-center gap-3 mb-3">
            <button onClick={() => { setSelectedFw(null); setFwDetail(null); }}
              className="text-[10px] font-bold px-2 py-1 rounded-md border text-nhi-dim bg-surface-3 border-[var(--border)] hover:bg-surface-2 flex items-center gap-1">
              <ChevronLeft className="w-3 h-3" /> Back
            </button>
            <span className="text-2xl">{FRAMEWORK_ICONS[selectedFw] || '📋'}</span>
            <div>
              <h1 className="text-[16px] font-bold text-nhi-text">{fw.name}</h1>
              <p className="text-[11px] text-nhi-dim">{fw.description}</p>
            </div>
            <div className="flex-1" />
            <div className="text-right mr-4">
              <div className="text-[24px] font-bold" style={{ color: coverageColor }}>{fwDetail.coverage_pct}%</div>
              <div className="text-[9px] text-nhi-faint">{fwDetail.deployed}/{fwDetail.total} deployed</div>
            </div>
            {undeployed > 0 && (
              <button onClick={deployAll} disabled={deploying}
                className="text-[11px] font-bold px-4 py-2 rounded-lg bg-accent text-white hover:bg-accent/90 disabled:opacity-50 flex items-center gap-2">
                {deploying ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                Deploy All ({undeployed})
              </button>
            )}
          </div>

          {/* Coverage bar */}
          <ProgressBar pct={fwDetail.coverage_pct} color={coverageColor} height={8} />

          {/* Deploy result banner */}
          {deployResult && !deployResult.error && (
            <div className="mt-2 flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)' }}>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span className="text-[10px] font-bold text-emerald-400">
                Deployed {deployResult.deployed} policies in audit mode
              </span>
              {deployResult.skipped > 0 && <span className="text-[10px] text-nhi-faint">({deployResult.skipped} already deployed)</span>}
            </div>
          )}
          {deployResult?.error && (
            <div className="mt-2 flex items-center gap-2 px-3 py-2 rounded-lg" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-[10px] font-bold text-red-400">Deploy error: {deployResult.error}</span>
            </div>
          )}

          {/* Filter tabs */}
          <div className="flex items-center gap-1 mt-3">
            {[
              { key: 'all', label: `All (${fwDetail.total})` },
              { key: 'deployed', label: `Deployed (${fwDetail.deployed})` },
              { key: 'not-deployed', label: `Not Deployed (${fwDetail.total - fwDetail.deployed})` },
            ].map(f => (
              <button key={f.key} onClick={() => setFilter(f.key)}
                className={`text-[9px] font-bold px-2.5 py-1 rounded-md transition-colors ${
                  filter === f.key ? 'bg-accent/15 text-accent' : 'text-nhi-faint hover:text-nhi-dim hover:bg-surface-3'
                }`}>
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Template list */}
        <div className="flex-1 overflow-auto px-6 py-4">
          {fwDetailLoading ? (
            <div className="flex justify-center py-8"><Loader className="w-5 h-5 animate-spin text-accent" /></div>
          ) : (
            <div className="space-y-4">
              {Object.entries(fwDetail.framework.controls || {}).map(([ctrlId, ctrlName]) => {
                const ctrlTemplates = (templatesByControl[ctrlId] || []).filter(t => {
                  if (filter === 'deployed') return t.deployed;
                  if (filter === 'not-deployed') return !t.deployed;
                  return true;
                });
                if (ctrlTemplates.length === 0 && filter !== 'all') return null;

                return (
                  <div key={ctrlId} className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                    <div className="px-3 py-2 flex items-center gap-2" style={{ background: 'var(--surface-2)', borderBottom: '1px solid var(--border)' }}>
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-accent/15 text-accent">{ctrlId}</span>
                      <span className="text-[10px] font-semibold text-nhi-text">{ctrlName}</span>
                      <span className="text-[8px] text-nhi-faint ml-auto">{ctrlTemplates.length} {ctrlTemplates.length === 1 ? 'policy' : 'policies'}</span>
                    </div>
                    {ctrlTemplates.length > 0 ? (
                      <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                        {ctrlTemplates.map((tpl) => {
                          const sev = SEVERITY_CFG[tpl.severity] || SEVERITY_CFG.medium;
                          return (
                            <div key={`${ctrlId}-${tpl.id}`} className="px-3 py-2 flex items-center gap-2 hover:bg-surface-3/30 transition-colors">
                              {tpl.deployed
                                ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                                : <XCircle className="w-3.5 h-3.5 text-nhi-ghost flex-shrink-0" />}
                              <span className="text-[10px] font-medium text-nhi-text flex-1 min-w-0 truncate">{tpl.name}</span>
                              <span className="text-[7px] font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: sev.bg, color: sev.color }}>{sev.label}</span>
                              {tpl.deployed && tpl.enforcement_mode && (
                                <span className={`text-[7px] font-bold px-1.5 py-0.5 rounded flex-shrink-0 ${
                                  tpl.enforcement_mode === 'enforce' ? 'bg-emerald-400/15 text-emerald-400' :
                                  tpl.enforcement_mode === 'audit' ? 'bg-amber-400/15 text-amber-400' :
                                  'bg-blue-400/15 text-blue-400'
                                }`}>{tpl.enforcement_mode.toUpperCase()}</span>
                              )}
                              {!tpl.deployed && (
                                <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-surface-3 text-nhi-ghost flex-shrink-0">NOT DEPLOYED</span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="px-3 py-2 text-[9px] text-nhi-ghost">No policies mapped to this control</div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    );
  }

  // ═══════ FRAMEWORK CARDS VIEW ═══════
  return (
    <div className="flex-1 flex flex-col h-full overflow-auto">
      <div className="px-6 py-5 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-accent" />
          <div>
            <h1 className="text-[16px] font-bold text-nhi-text">Compliance</h1>
            <p className="text-[11px] text-nhi-dim">Map policies to compliance frameworks. Deploy policy packs with one click.</p>
          </div>
          <div className="flex-1" />
          <button onClick={fetchFrameworks}
            className="text-[9px] font-bold px-2.5 py-1.5 rounded-md border text-nhi-dim bg-surface-3 border-[var(--border)] hover:bg-surface-2 flex items-center gap-1.5">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      <div className="px-6 py-5">
        {frameworks.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-10 h-10 mx-auto mb-3 text-nhi-ghost opacity-30" />
            <div className="text-[12px] text-nhi-faint">No compliance frameworks available</div>
            <div className="text-[10px] text-nhi-ghost mt-1">Run template migration to seed compliance data</div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {frameworks.map(fw => {
              const coverageColor = CoverageColor(fw.coverage_pct);
              return (
                <div key={fw.id} onClick={() => handleSelectFramework(fw.id)}
                  className="rounded-xl border p-4 cursor-pointer transition-all duration-200 hover:border-accent/40 hover:shadow-[0_0_20px_rgba(124,111,240,0.08)]"
                  style={{ borderColor: 'var(--border)', background: 'var(--surface-2)' }}>
                  <div className="flex items-start gap-3 mb-3">
                    <span className="text-2xl">{FRAMEWORK_ICONS[fw.id] || '📋'}</span>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-[13px] font-bold text-nhi-text">{fw.name}</h3>
                      <p className="text-[9px] text-nhi-dim mt-0.5 line-clamp-2">{fw.description}</p>
                    </div>
                  </div>

                  {/* Coverage bar */}
                  <div className="mb-2">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[8px] font-bold text-nhi-faint uppercase">Coverage</span>
                      <span className="text-[11px] font-bold" style={{ color: coverageColor }}>{fw.coverage_pct}%</span>
                    </div>
                    <ProgressBar pct={fw.coverage_pct} color={coverageColor} />
                  </div>

                  {/* Stats */}
                  <div className="flex items-center gap-3 mt-3">
                    <div className="text-[8px]">
                      <span className="text-nhi-faint">Templates: </span>
                      <span className="font-bold text-nhi-text">{fw.mapped_templates}</span>
                    </div>
                    <div className="text-[8px]">
                      <span className="text-nhi-faint">Deployed: </span>
                      <span className="font-bold text-emerald-400">{fw.deployed_policies}</span>
                    </div>
                    <div className="text-[8px]">
                      <span className="text-nhi-faint">Controls: </span>
                      <span className="font-bold text-nhi-text">{fw.total_controls}</span>
                    </div>
                    <ChevronRight className="w-3.5 h-3.5 text-nhi-ghost ml-auto" />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
