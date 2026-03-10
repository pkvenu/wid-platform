import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, RefreshCw, Loader, Eye, CheckCircle, Clock,
  Activity, Zap, Play, Square, RotateCcw, Timer, Fingerprint,
  Server, AlertCircle, TrendingUp, X, AlertTriangle, ArrowDown, ChevronDown, Lock,
  ArrowUp, Check, ChevronRight,
} from 'lucide-react';
import toast from 'react-hot-toast';

const API = '/api/v1';

/* ════════════════════════════════════════════════════════════════
   Operations — Continuous Attestation Monitor + Token Lifecycle
   ════════════════════════════════════════════════════════════════ */

export default function Operations() {
  const [tab, setTab] = useState('attestation');

  const tabs = [
    { id: 'attestation', label: 'Continuous Attestation', icon: Fingerprint },
    { id: 'tokens', label: 'Token Lifecycle', icon: Shield },
  ];

  return (
    <div className="flex flex-col h-[calc(100vh-7rem)]">
      <div className="flex items-center gap-4 mb-5">
        <div className="w-9 h-9 rounded-xl bg-accent/10 flex items-center justify-center">
          <Activity className="w-5 h-5 text-accent" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-nhi-text tracking-tight">Operations</h1>
          <p className="text-[10px] text-nhi-dim">Attestation scheduling, monitoring, and token management</p>
        </div>
      </div>

      <div className="flex gap-1 mb-4 p-1 rounded-xl bg-surface-2 w-fit border border-[var(--border)]">
        {tabs.map(t => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-semibold transition-all ${
                active ? 'bg-surface-1 text-nhi-text shadow-sm border border-[var(--border)]' : 'text-nhi-dim hover:text-nhi-muted'
              }`}>
              <Icon className="w-3.5 h-3.5" style={{ color: active ? (t.id === 'attestation' ? '#06b6d4' : '#8b5cf6') : undefined }} />
              {t.label}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-auto">
        {tab === 'attestation' && <ContinuousAttestation />}
        {tab === 'tokens' && <TokenLifecycle />}
      </div>
    </div>
  );
}


/* ════════════════════════════════════════════════════════════════
   Continuous Attestation — Read-Only Monitoring Dashboard
   ════════════════════════════════════════════════════════════════ */

function ContinuousAttestation() {
  const [status, setStatus] = useState(null);
  const [scheduler, setScheduler] = useState(null);
  const [loading, setLoading] = useState(true);
  const [interval, setIntervalVal] = useState(300);
  const [countdown, setCountdown] = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [sRes, schRes] = await Promise.all([
        fetch(`${API}/attestation/status`).catch(() => null),
        fetch(`${API}/attestation/scheduler/status`).catch(() => null),
      ]);
      if (sRes?.ok) {
        try { setStatus(await sRes.json()); } catch {}
      }
      if (schRes?.ok) {
        try {
          const d = await schRes.json();
          setScheduler(d);
          if (d.interval_seconds) setIntervalVal(d.interval_seconds);
        } catch {}
      }
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Poll every 10s
  useEffect(() => {
    const iv = setInterval(fetchAll, 10000);
    return () => clearInterval(iv);
  }, [fetchAll]);

  // Countdown timer
  useEffect(() => {
    if (!scheduler?.enabled || !scheduler?.next_run) { setCountdown(null); return; }
    const tick = () => {
      const rem = Math.max(0, Math.floor((new Date(scheduler.next_run) - Date.now()) / 1000));
      setCountdown(rem);
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, [scheduler?.next_run, scheduler?.enabled]);

  const startScheduler = async () => {
    try {
      const r = await fetch(`${API}/attestation/scheduler/start`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval_seconds: interval }),
      });
      const text = await r.text();
      try { JSON.parse(text); } catch { toast.error('Scheduler endpoint not available'); return; }
      if (r.ok) { toast.success('Scheduler started'); fetchAll(); }
    } catch (e) { toast.error(e.message); }
  };

  const stopScheduler = async () => {
    try {
      const r = await fetch(`${API}/attestation/scheduler/stop`, { method: 'POST' });
      const text = await r.text();
      try { JSON.parse(text); } catch { toast.error('Scheduler endpoint not available'); return; }
      if (r.ok) { toast.success('Scheduler stopped'); fetchAll(); }
    } catch (e) { toast.error(e.message); }
  };

  // Trigger manual run using existing endpoint
  const runNow = async () => {
    toast.loading('Running attestation...', { id: 'run' });
    try {
      const r = await fetch(`${API}/workloads/continuous-attest`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force: false }),
      });
      const text = await r.text();
      let d;
      try { d = JSON.parse(text); } catch { toast.error('Endpoint not available', { id: 'run' }); return; }
      if (d.renewed > 0) toast.success(`${d.renewed} renewed`, { id: 'run' });
      else if (d.expired > 0) toast.error(`${d.expired} expired`, { id: 'run' });
      else toast.success('All current — nothing to renew', { id: 'run' });
      fetchAll();
    } catch (e) { toast.error(e.message, { id: 'run' }); }
  };

  if (loading) return <div className="flex justify-center py-16"><Loader className="w-5 h-5 text-accent animate-spin" /></div>;

  const s = status || {};
  const sch = scheduler || {};
  const coveragePct = s.coverage_pct || 0;
  const coverageColor = coveragePct >= 80 ? '#10b981' : coveragePct >= 50 ? '#f59e0b' : '#ef4444';

  return (
    <div className="space-y-4">

      {/* ── Scheduler Control Strip ── */}
      <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-4">
        <div className="flex items-center gap-4">
          {/* Status indicator */}
          <div className="flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-full ${sch.enabled ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            <span className="text-[12px] font-bold text-nhi-text">{sch.enabled ? 'Scheduler Running' : 'Scheduler Stopped'}</span>
          </div>

          {/* Interval selector */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-3 border border-[var(--border)]">
            <Timer className="w-3 h-3 text-nhi-ghost" />
            <span className="text-[9px] text-nhi-dim font-semibold">Interval</span>
            <select value={interval} onChange={e => setIntervalVal(Number(e.target.value))}
              disabled={sch.enabled}
              className="text-[10px] bg-transparent border-none text-nhi-text outline-none cursor-pointer disabled:opacity-50">
              <option value={60}>1 min</option>
              <option value={300}>5 min</option>
              <option value={900}>15 min</option>
              <option value={1800}>30 min</option>
              <option value={3600}>1 hour</option>
            </select>
          </div>

          {/* Start/Stop */}
          {!sch.enabled ? (
            <button onClick={startScheduler}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-500/25 transition-all">
              <Play className="w-3.5 h-3.5" /> Start Scheduler
            </button>
          ) : (
            <button onClick={stopScheduler}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/25 hover:bg-red-500/25 transition-all">
              <Square className="w-3 h-3" /> Stop
            </button>
          )}

          {/* Manual run */}
          <button onClick={runNow}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-all">
            <RotateCcw className="w-3.5 h-3.5" /> Run Now
          </button>

          <div className="flex-1" />

          {/* Next run countdown */}
          {sch.enabled && countdown !== null && (
            <div className="text-right">
              <div className="text-[9px] text-nhi-ghost">Next run in</div>
              <div className="text-[14px] font-mono font-bold text-cyan-400">
                {Math.floor(countdown / 60)}:{String(countdown % 60).padStart(2, '0')}
              </div>
            </div>
          )}

          {/* Run stats */}
          {sch.run_count > 0 && (
            <div className="text-right pl-3 border-l border-[var(--border)]">
              <div className="text-[9px] text-nhi-ghost">Runs</div>
              <div className="text-[13px] font-bold text-nhi-text">{sch.run_count}</div>
            </div>
          )}
        </div>

        {/* Started at / last run info */}
        {sch.started_at && (
          <div className="flex gap-6 mt-2 pt-2 border-t border-[var(--border)]">
            <span className="text-[9px] text-nhi-ghost">Started: <span className="text-nhi-dim">{new Date(sch.started_at).toLocaleTimeString()}</span></span>
            {sch.last_run && <span className="text-[9px] text-nhi-ghost">Last run: <span className="text-nhi-dim">{new Date(sch.last_run).toLocaleTimeString()}</span></span>}
            {sch.totals && (
              <>
                <span className="text-[9px] text-emerald-400">{sch.totals.renewed} renewed</span>
                <span className="text-[9px] text-red-400">{sch.totals.expired} expired</span>
                <span className="text-[9px] text-amber-400">{sch.totals.failed} failed</span>
              </>
            )}
          </div>
        )}
      </div>

      {/* ── Stats Grid ── */}
      <div className="grid grid-cols-5 gap-3">
        <StatCard label="Coverage" value={`${coveragePct}%`} sub={`${s.attested}/${s.total}`} color={coverageColor} icon={Shield} />
        <StatCard label="Attested" value={s.attested || 0} color="#10b981" icon={CheckCircle} />
        <StatCard label="Expired" value={s.expired || 0} sub="Need renewal" color="#ef4444" icon={AlertCircle} />
        <StatCard label="Expiring Soon" value={s.expiring_soon || 0} sub="Within 1hr" color="#f59e0b" icon={Clock} />
        <StatCard label="Unattested" value={s.unattested || 0} color="#64748b" icon={Server} />
      </div>

      {/* ── Coverage Bar ── */}
      <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-bold text-nhi-dim uppercase tracking-wider">Trust Coverage</span>
          <span className="text-[11px] font-mono font-bold" style={{ color: coverageColor }}>{coveragePct}%</span>
        </div>
        <div className="w-full h-2.5 bg-surface-3 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700" style={{ width: `${coveragePct}%`, background: `linear-gradient(90deg, ${coverageColor}, ${coverageColor}aa)` }} />
        </div>
        <div className="flex justify-between mt-2 text-[9px] text-nhi-ghost">
          <span className="text-emerald-400">{s.attested || 0} attested</span>
          <span className="text-red-400">{s.expired || 0} expired</span>
          <span className="text-amber-400">{s.shadow || 0} shadow</span>
          <span className="text-purple-400">{s.ai_agents || 0} AI agents</span>
          <span>{s.recently_attested || 0} attested last hour</span>
        </div>
      </div>

      {/* ── 2-column: Next Expiring + Last Run Result ── */}
      <div className="grid grid-cols-2 gap-3">

        {/* Next Expiring */}
        <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Timer className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-[10px] font-bold text-nhi-dim uppercase tracking-wider">Next Expiring</span>
          </div>
          {s.next_expiring?.length > 0 ? (
            <div className="space-y-1.5">
              {s.next_expiring.map((w, i) => {
                const remaining = Math.max(0, Math.floor((new Date(w.attestation_expires) - Date.now()) / 1000));
                const hours = Math.floor(remaining / 3600);
                const mins = Math.floor((remaining % 3600) / 60);
                const secs = remaining % 60;
                const urgency = remaining < 300 ? '#ef4444' : remaining < 3600 ? '#f59e0b' : '#64748b';
                return (
                  <div key={i} className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-surface-3 transition-colors">
                    <div className="w-1.5 h-1.5 rounded-full" style={{ background: urgency }} />
                    <span className="text-[10px] font-mono text-nhi-text flex-1 truncate">{w.name}</span>
                    <span className="text-[8px] px-1.5 py-0.5 rounded bg-white/[0.04] text-nhi-ghost">{w.trust_level}</span>
                    {w.is_ai_agent && <span className="text-[7px] px-1 py-0.5 rounded bg-purple-500/10 text-purple-400">AI</span>}
                    <span className="text-[10px] font-mono font-bold" style={{ color: urgency }}>
                      {hours > 0 ? `${hours}h ${mins}m` : mins > 0 ? `${mins}m ${secs}s` : `${secs}s`}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-[10px] text-nhi-ghost py-4 text-center">No expiring workloads</div>
          )}
        </div>

        {/* Last Run Result */}
        <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[10px] font-bold text-nhi-dim uppercase tracking-wider">Last Run</span>
            {sch.last_result?.timestamp && (
              <span className="text-[8px] text-nhi-ghost ml-auto">{new Date(sch.last_result.timestamp).toLocaleTimeString()}</span>
            )}
          </div>
          {sch.last_result && !sch.last_result.error ? (
            <>
              <div className="grid grid-cols-4 gap-2 mb-3">
                <MiniStat label="Renewed" value={sch.last_result.renewed} color="#10b981" />
                <MiniStat label="Expired" value={sch.last_result.expired} color="#ef4444" />
                <MiniStat label="Failed" value={sch.last_result.failed} color="#f59e0b" />
                <MiniStat label="Skipped" value={sch.last_result.skipped} color="#64748b" />
              </div>
              {sch.last_result.details?.renewed?.length > 0 && (
                <div className="space-y-1">
                  {sch.last_result.details.renewed.map((r, i) => (
                    <div key={i} className="flex items-center gap-2 text-[9px] px-2 py-1 rounded bg-emerald-500/5">
                      <ArrowUp className="w-3 h-3 text-emerald-400" />
                      <span className="font-mono text-nhi-text truncate">{r.name}</span>
                      <span className="text-emerald-400 ml-auto">{r.trust_level}</span>
                    </div>
                  ))}
                </div>
              )}
              {sch.last_result.details?.expired?.length > 0 && (
                <div className="space-y-1 mt-1">
                  {sch.last_result.details.expired.map((r, i) => (
                    <div key={i} className="flex items-center gap-2 text-[9px] px-2 py-1 rounded bg-red-500/5">
                      <ArrowDown className="w-3 h-3 text-red-400" />
                      <span className="font-mono text-nhi-text truncate">{r.name}</span>
                      <span className="text-red-400 ml-auto">{r.was_trust} → none</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : sch.last_result?.error ? (
            <div className="text-[10px] text-red-400 py-2">{sch.last_result.error}</div>
          ) : (
            <div className="text-[10px] text-nhi-ghost py-4 text-center">No runs yet — start the scheduler or click Run Now</div>
          )}
        </div>
      </div>

      {/* ── 24h Event History ── */}
      {s.history?.length > 0 && (
        <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-4">
          <span className="text-[10px] font-bold text-nhi-dim uppercase tracking-wider">Last 24h Event History</span>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1">
            {s.history.map((h, i) => {
              const colors = {
                'auto-attest': '#10b981', 'continuous-attest': '#06b6d4', 'single-attest': '#3b82f6',
                'manual-approval': '#a78bfa', 'auto-attest-manual-review': '#f59e0b',
                'continuous-attest-expired': '#ef4444', 'continuous-attest-failed': '#f97316',
              };
              return (
                <div key={i} className="flex items-center gap-2 text-[9px] py-1">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ background: colors[h.event_type] || '#64748b' }} />
                  <span className="text-nhi-dim flex-1">{h.event_type.replace(/-/g, ' ')}</span>
                  <span className="font-bold font-mono" style={{ color: colors[h.event_type] || '#64748b' }}>{h.count}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Architecture Note ── */}
      <div className="rounded-xl border border-dashed border-[var(--border)] bg-surface-2/50 p-3 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-nhi-ghost shrink-0 mt-0.5" />
        <div className="text-[9px] text-nhi-ghost leading-relaxed">
          <span className="font-bold text-nhi-dim">Production architecture:</span> In production, continuous attestation runs as a Cloud Scheduler cron job
          calling <code className="text-cyan-400/70">POST /api/v1/workloads/continuous-attest</code> at the configured interval.
          The scheduler above runs server-side on the discovery service. For HA, use Cloud Scheduler → Cloud Run invocation with jitter, exponential backoff, and a 20-workload concurrency limit.
        </div>
      </div>
    </div>
  );
}


/* ════════════════════════════════════════════════════════════════
   Token Lifecycle — Monitoring Dashboard (auto-issued tokens)
   ════════════════════════════════════════════════════════════════ */

function TokenLifecycle() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [gatewayResult, setGatewayResult] = useState(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(iv);
  }, []);

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API}/tokens/status`);
      if (r.ok) {
        const text = await r.text();
        try { setData(JSON.parse(text)); } catch {}
      }
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { const iv = setInterval(load, 15000); return () => clearInterval(iv); }, [load]);

  const testGateway = async (wl) => {
    setGatewayResult(null);
    try {
      const r = await fetch(`${API}/gateway/evaluate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: wl.name, destination: 'production-api',
          method: 'POST', path: '/api/data',
          wid_token: wl.wid_token,
        }),
      });
      const text = await r.text();
      try { setGatewayResult(JSON.parse(text)); } catch {}
    } catch (e) { console.error(e); }
  };

  const reissueToken = async (wl) => {
    try {
      const r = await fetch(`${API}/workloads/${wl.id}/attest`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence: {} }),
      });
      if (r.ok) { toast.success(`Re-attested + token reissued for ${wl.name}`); load(); }
      else toast.error('Re-attestation failed');
    } catch (e) { toast.error(e.message); }
  };

  if (loading) return <div className="flex justify-center py-16"><Loader className="w-5 h-5 text-accent animate-spin" /></div>;

  const workloads = data?.workloads || [];
  const trustColors = { cryptographic: '#06b6d4', high: '#10b981', medium: '#f59e0b', low: '#f97316', none: '#64748b' };

  return (
    <div className="space-y-4">
      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard label="Active Tokens" value={data?.active || 0} color="#8b5cf6" icon={Shield} />
        <StatCard label="Expired" value={data?.expired || 0} sub="Need re-attestation" color="#ef4444" icon={AlertCircle} />
        <StatCard label="Revoked" value={data?.revoked || 0} sub="Manually revoked" color="#f97316" icon={Lock} />
        <StatCard label="No Token" value={data?.no_token || 0} sub="Pending attestation" color="#64748b" icon={Server} />
      </div>

      {/* Info banner */}
      <div className="rounded-xl border border-dashed border-[var(--border)] bg-surface-2/50 p-3 flex items-center gap-3">
        <Zap className="w-4 h-4 text-purple-400 shrink-0" />
        <span className="text-[9px] text-nhi-dim leading-relaxed">
          Tokens are <span className="text-purple-400 font-bold">auto-issued</span> after successful attestation. TTL is trust-based: cryptographic=1hr, high=30min, medium=15min, low=5min. Continuous attestation renews tokens before expiry.
        </span>
      </div>

      <div className="flex gap-3">
        {/* ── Left: Token List ── */}
        <div className="flex-1 space-y-1.5">
          {workloads.map(wl => {
            const ttlRem = wl.token_active ? Math.max(0, Math.floor((new Date(wl.token_expires_at) - Date.now()) / 1000)) : 0;
            const ttlTotal = wl.token_claims?.exp && wl.token_claims?.iat ? (wl.token_claims.exp - wl.token_claims.iat) : 1;
            const ttlPct = wl.token_active ? Math.min(100, (ttlRem / ttlTotal) * 100) : 0;
            const isSelected = selected?.id === wl.id;

            return (
              <div key={wl.id} onClick={() => { setSelected(wl); setGatewayResult(null); }}
                className={`rounded-xl border bg-surface-2 p-3 cursor-pointer transition-all ${
                  isSelected ? 'border-purple-500/30 bg-purple-500/[0.03]' :
                  !wl.has_token ? 'border-[var(--border)] opacity-60' :
                  wl.token_active ? 'border-purple-500/10 hover:border-purple-500/20' :
                  'border-red-500/15 hover:border-red-500/25'
                }`}>
                <div className="flex items-center gap-3">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                    !wl.has_token ? 'bg-surface-3' : wl.token_active ? 'bg-purple-500/10' : 'bg-red-500/10'
                  }`}>
                    <Shield className="w-3.5 h-3.5" style={{ color: !wl.has_token ? '#64748b' : wl.token_active ? '#8b5cf6' : '#ef4444' }} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-bold text-nhi-text truncate">{wl.name}</span>
                      <span className="text-[8px] text-nhi-ghost">{wl.type}</span>
                      {wl.is_ai_agent && <span className="text-[7px] px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 font-bold">AI</span>}
                      {wl.token_active && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">ACTIVE</span>}
                      {wl.has_token && !wl.token_active && !wl.token_revoked && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">EXPIRED</span>}
                      {wl.token_revoked && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400">REVOKED</span>}
                      {!wl.has_token && !wl.token_revoked && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-slate-500/10 text-slate-400">NO TOKEN</span>}
                    </div>
                    <div className="flex items-center gap-3 mt-0.5">
                      <span className="text-[8px] font-bold" style={{ color: trustColors[wl.trust_level] || '#64748b' }}>{wl.trust_level}</span>
                      {wl.spiffe_id && <span className="text-[8px] font-mono text-cyan-400/60 truncate max-w-[200px]">{wl.spiffe_id}</span>}
                      {wl.token_active && <span className="text-[8px] font-mono text-nhi-dim">{ttlRem}s</span>}
                    </div>
                    {wl.has_token && (
                      <div className="w-full h-1 bg-surface-3 rounded-full overflow-hidden mt-1">
                        <div className="h-full rounded-full transition-all duration-1000" style={{
                          width: `${ttlPct}%`,
                          background: ttlPct > 50 ? '#8b5cf6' : ttlPct > 20 ? '#f59e0b' : '#ef4444',
                        }} />
                      </div>
                    )}
                  </div>

                  {wl.has_token && !wl.token_active && (
                    <button onClick={(e) => { e.stopPropagation(); reissueToken(wl); }}
                      className="text-[8px] font-bold px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 flex items-center gap-1 shrink-0 transition-all">
                      <RotateCcw className="w-3 h-3" /> Re-attest
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* ── Right: Token Detail Panel ── */}
        {selected && (
          <div className="w-[380px] shrink-0 rounded-xl border border-[var(--border)] bg-surface-2 p-4 space-y-3 self-start sticky top-0">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-[12px] font-bold text-nhi-text">{selected.name}</span>
              </div>
              <button onClick={() => setSelected(null)} className="text-nhi-ghost hover:text-nhi-text p-1">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {selected.has_token ? (
              <>
                {/* Token Status */}
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${selected.token_active ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
                  <span className="text-[10px] font-bold" style={{ color: selected.token_active ? '#10b981' : '#ef4444' }}>
                    {selected.token_active ? 'Token Active' : 'Token Expired'}
                  </span>
                  {selected.token_active && (
                    <span className="text-[9px] font-mono text-nhi-dim ml-auto">
                      {Math.max(0, Math.floor((new Date(selected.token_expires_at) - Date.now()) / 1000))}s remaining
                    </span>
                  )}
                </div>

                {/* JWT Claims */}
                <div className="space-y-1.5">
                  <span className="text-[9px] font-bold text-nhi-dim uppercase tracking-wider">Token Claims</span>
                  <div className="space-y-1 text-[9px]">
                    <ClaimRow label="SPIFFE ID" value={selected.token_claims?.sub} color="#06b6d4" mono />
                    <ClaimRow label="Issuer" value={selected.token_claims?.iss} mono />
                    <ClaimRow label="Audience" value={selected.token_claims?.aud} mono />
                    <ClaimRow label="JTI" value={selected.token_jti} mono />
                    <ClaimRow label="Issued" value={selected.token_issued_at ? new Date(selected.token_issued_at).toLocaleString() : '—'} />
                    <ClaimRow label="Expires" value={selected.token_expires_at ? new Date(selected.token_expires_at).toLocaleString() : '—'} />
                  </div>
                </div>

                {/* WID Claims */}
                {selected.token_claims?.wid && (
                  <div className="space-y-1.5">
                    <span className="text-[9px] font-bold text-nhi-dim uppercase tracking-wider">Identity Claims</span>
                    <div className="space-y-1 text-[9px]">
                      <ClaimRow label="Trust Level" value={selected.token_claims.wid.trust_level} color={trustColors[selected.token_claims.wid.trust_level]} />
                      <ClaimRow label="Trust Score" value={selected.token_claims.wid.trust_score} />
                      <ClaimRow label="Attestation" value={selected.token_claims.wid.attestation_method} />
                      <ClaimRow label="Type" value={selected.token_claims.wid.workload_type} />
                      <ClaimRow label="Environment" value={selected.token_claims.wid.environment || '—'} />
                      {selected.token_claims.wid.is_ai_agent && <ClaimRow label="AI Agent" value="Yes" color="#a78bfa" />}
                      {selected.token_claims.wid.is_mcp_server && <ClaimRow label="MCP Server" value="Yes" color="#06b6d4" />}
                    </div>
                  </div>
                )}

                {/* Attestation Chain */}
                {selected.token_claims?.wid?.attestation_chain?.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[9px] font-bold text-nhi-dim uppercase tracking-wider">Attestation Chain</span>
                    <div className="space-y-1">
                      {selected.token_claims.wid.attestation_chain.map((a, i) => (
                        <div key={i} className="flex items-center gap-2 text-[8px] px-2 py-1 rounded bg-surface-3">
                          <CheckCircle className="w-3 h-3 text-emerald-400" />
                          <span className="text-nhi-text font-mono">{a.method}</span>
                          <span className="ml-auto text-nhi-ghost">tier {a.tier}</span>
                          <span style={{ color: trustColors[a.trust] || '#64748b' }}>{a.trust}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Gateway Test */}
                <div className="space-y-1.5 pt-2 border-t border-[var(--border)]">
                  <span className="text-[9px] font-bold text-nhi-dim uppercase tracking-wider">Gateway Simulation</span>
                  <button onClick={() => testGateway(selected)} disabled={!selected.token_active}
                    className="w-full text-[9px] font-bold px-3 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 disabled:opacity-30 flex items-center justify-center gap-2 transition-all">
                    <Activity className="w-3 h-3" /> Test Access → production-api
                  </button>
                  {gatewayResult && (
                    <div className={`rounded-lg p-2.5 text-[9px] ${
                      gatewayResult.verdict === 'allow' ? 'bg-emerald-500/5 border border-emerald-500/15' : 'bg-red-500/5 border border-red-500/15'
                    }`}>
                      <div className="flex items-center gap-2 mb-1">
                        {gatewayResult.verdict === 'allow' ? (
                          <><CheckCircle className="w-3.5 h-3.5 text-emerald-400" /><span className="font-bold text-emerald-400">ACCESS ALLOWED</span></>
                        ) : (
                          <><AlertCircle className="w-3.5 h-3.5 text-red-400" /><span className="font-bold text-red-400">ACCESS DENIED</span></>
                        )}
                      </div>
                      {gatewayResult.policy_name && <div className="text-nhi-ghost">Policy: <span className="text-nhi-dim">{gatewayResult.policy_name}</span></div>}
                      {gatewayResult.reason && <div className="text-nhi-ghost">Reason: <span className="text-nhi-dim">{gatewayResult.reason}</span></div>}
                      {gatewayResult.enforcement && <div className="text-nhi-ghost">Enforcement: <span className="text-nhi-dim">{gatewayResult.enforcement}</span></div>}
                    </div>
                  )}
                </div>

                {/* Revoke */}
                {selected.token_active && (
                  <div className="pt-2 border-t border-[var(--border)]">
                    <button onClick={async () => {
                      try {
                        const r = await fetch(`${API}/tokens/${selected.token_jti}/revoke`, {
                          method: 'POST', headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ revoked_by: 'admin@securebank.io', reason: 'Manual revocation from dashboard' }),
                        });
                        const text = await r.text();
                        try { const d = JSON.parse(text); if (d.revoked) { toast.success(`Token revoked for ${selected.name}`); load(); setSelected(null); } else { toast.error(d.error || 'Revoke failed'); } } catch { toast.error('Revoke endpoint not available'); }
                      } catch (e) { toast.error(e.message); }
                    }}
                      className="w-full text-[9px] font-bold px-3 py-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 flex items-center justify-center gap-2 transition-all">
                      <X className="w-3 h-3" /> Revoke Token
                    </button>
                  </div>
                )}

                {/* Token History */}
                <TokenHistory workloadId={selected.id} />

                {/* Raw Token (collapsible) */}
                <details className="text-[8px]">
                  <summary className="text-nhi-ghost cursor-pointer hover:text-nhi-dim">Raw JWT</summary>
                  <div className="mt-1 p-2 rounded bg-surface-3 font-mono text-nhi-ghost break-all max-h-[80px] overflow-auto leading-relaxed">
                    {selected.wid_token}
                  </div>
                </details>
              </>
            ) : (
              <div className="text-center py-6">
                <Server className="w-8 h-8 mx-auto text-nhi-ghost opacity-30 mb-2" />
                <div className="text-[10px] text-nhi-ghost">No token issued</div>
                <div className="text-[9px] text-nhi-ghost mt-1">Run attestation to auto-issue a token</div>
                <button onClick={() => reissueToken(selected)}
                  className="mt-3 text-[9px] font-bold px-4 py-2 rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 flex items-center gap-1.5 mx-auto transition-all">
                  <Fingerprint className="w-3 h-3" /> Attest Now
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function TokenHistory({ workloadId }) {
  const [history, setHistory] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open || !workloadId) return;
    fetch(`${API}/tokens/history/${workloadId}`)
      .then(r => r.ok ? r.text() : null)
      .then(text => { try { setHistory(JSON.parse(text)); } catch {} })
      .catch(() => {});
  }, [open, workloadId]);

  const statusColors = { active: '#10b981', revoked: '#ef4444', superseded: '#64748b', expired: '#f59e0b' };
  const statusIcons = { active: CheckCircle, revoked: X, superseded: RotateCcw, expired: Clock };

  return (
    <div className="pt-2 border-t border-[var(--border)]">
      <button onClick={() => setOpen(!open)} className="flex items-center gap-1.5 text-[9px] font-bold text-nhi-dim hover:text-nhi-text transition-colors">
        <Clock className="w-3 h-3" />
        Token History
        <ChevronDown className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && history?.tokens?.length > 0 && (
        <div className="mt-2 space-y-1 max-h-[200px] overflow-auto">
          {history.tokens.map((tk, i) => {
            const Icon = statusIcons[tk.status] || Clock;
            return (
              <div key={i} className="flex items-center gap-2 text-[8px] px-2 py-1.5 rounded bg-surface-3">
                <Icon className="w-3 h-3 shrink-0" style={{ color: statusColors[tk.status] || '#64748b' }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-nhi-ghost truncate">{tk.jti?.slice(0, 20)}…</span>
                    <span className="font-bold" style={{ color: statusColors[tk.status] }}>{tk.status}</span>
                  </div>
                  <div className="text-nhi-ghost mt-0.5">
                    {tk.trust_level} · {tk.ttl_seconds}s TTL · {new Date(tk.issued_at).toLocaleString()}
                    {tk.revoked_at && <span className="text-red-400"> · revoked {new Date(tk.revoked_at).toLocaleTimeString()} by {tk.revoked_by}</span>}
                    {tk.superseded_by && <span className="text-slate-400"> · replaced</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {open && (!history?.tokens?.length) && (
        <div className="mt-2 text-[8px] text-nhi-ghost px-2">No token history yet — tokens are recorded after the next attestation.</div>
      )}
    </div>
  );
}

function ClaimRow({ label, value, color, mono }) {
  return (
    <div className="flex items-center gap-2 py-0.5">
      <span className="text-nhi-ghost w-[72px] shrink-0">{label}</span>
      <span className={`truncate ${mono ? 'font-mono' : ''}`} style={{ color: color || '#cbd5e1' }}>{value || '—'}</span>
    </div>
  );
}


/* ── Shared Components ── */

function StatCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-surface-2 p-3">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[9px] font-bold text-nhi-dim uppercase tracking-wider">{label}</span>
        {Icon && <Icon className="w-3.5 h-3.5" style={{ color }} />}
      </div>
      <div className="text-xl font-bold" style={{ color }}>{value}</div>
      {sub && <div className="text-[9px] text-nhi-ghost mt-0.5">{sub}</div>}
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div className="text-center">
      <div className="text-lg font-bold" style={{ color }}>{value}</div>
      <div className="text-[8px] text-nhi-ghost">{label}</div>
    </div>
  );
}
