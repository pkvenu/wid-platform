import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, ScanSearch, RefreshCw, Filter, Server, ShieldCheck,
  AlertTriangle, Clock, Check, Loader, X, Eye, User, Bot,
  Plug, Cpu, Info, ChevronDown, ChevronUp, GitBranch,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { enrichWorkload, timeAgo, formatAge } from '../utils/enrichment';
import { AIEnrichmentPanel } from '../components/AIEnrichmentPanel';

/* ════════════════════════════════════════════
   UI Atoms
   ════════════════════════════════════════════ */

const ProviderIcon = ({ provider }) => {
  const p = (provider || '').toLowerCase();
  const map = {
    aws: { bg: '#ff9900', label: 'AWS' }, azure: { bg: '#0078d4', label: 'AZ' },
    gcp: { bg: '#4285f4', label: 'GCP' }, github: { bg: '#8b949e', label: 'GH' },
    docker: { bg: '#2496ed', label: 'DK' }, k8s: { bg: '#326ce5', label: 'K8' },
  };
  const e = map[p] || { bg: '#7c6ff0', label: p.slice(0, 2).toUpperCase() || '??' };
  return (
    <span className="inline-flex items-center justify-center w-[22px] h-[22px] rounded text-[8px] font-extrabold text-white shrink-0"
      style={{ background: e.bg }} title={provider}>{e.label}</span>
  );
};

const TrustDots = ({ level = 0 }) => (
  <span className="font-mono text-[11px] tracking-[0.1em]">
    <span className="text-accent-light">{'●'.repeat(Math.min(level, 5))}</span>
    <span className="text-nhi-ghost">{'○'.repeat(Math.max(0, 5 - level))}</span>
  </span>
);

const RiskBadge = ({ risk, score }) => {
  const r = (risk || '').toUpperCase();
  if (r === 'LOW' && score >= 80) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">SECURE</span>
        {score != null && <span className="text-[10px] text-nhi-faint font-mono">{score}</span>}
      </div>
    );
  }
  const cls = { critical: 'nhi-badge-critical', high: 'nhi-badge-high', medium: 'nhi-badge-medium', low: 'nhi-badge-low' };
  return (
    <div className="flex items-center gap-1.5">
      <span className={cls[(risk || '').toLowerCase()] || 'nhi-badge-info'}>{risk}</span>
      {score != null && <span className="text-[10px] text-nhi-faint font-mono">{score}</span>}
    </div>
  );
};

const EnvBadge = ({ env }) => {
  const e = (env || '').toLowerCase();
  if (e === 'production') return <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded">PROD</span>;
  if (e === 'staging') return <span className="text-[10px] font-bold uppercase tracking-wider text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">STG</span>;
  if (e === 'development' || e === 'dev') return <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 bg-emerald-400/10 px-1.5 py-0.5 rounded">DEV</span>;
  return <span className="text-[10px] text-nhi-faint">—</span>;
};

const HealthDot = ({ health }) => {
  if (!health) return null;
  const colors = { healthy: 'bg-emerald-400', running: 'bg-blue-400', unhealthy: 'bg-red-400' };
  return <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${colors[health] || 'bg-nhi-ghost'}`} title={health} />;
};

const StatCard = ({ icon: Icon, label, value, color }) => (
  <div className="nhi-card p-4 flex items-center gap-3 animate-fadeInUp">
    <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: `${color}15` }}>
      <Icon className="w-[18px] h-[18px]" style={{ color }} />
    </div>
    <div>
      <div className="text-[22px] font-bold text-nhi-text font-mono leading-none">{value}</div>
      <div className="text-[11px] text-nhi-dim font-medium mt-0.5">{label}</div>
    </div>
  </div>
);

const FilterPill = ({ label, count, active, onClick }) => (
  <button onClick={onClick}
    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 border flex items-center gap-1.5 ${
      active ? 'bg-accent/[0.12] border-accent/25 text-accent-light' : 'bg-white/[0.02] border-white/[0.06] text-nhi-dim hover:text-nhi-muted hover:border-white/[0.1]'
    }`}>
    {label}
    {count != null && <span className={`text-[10px] font-mono ${active ? 'text-accent' : 'text-nhi-faint'}`}>{count}</span>}
  </button>
);

/* ── Trust level colors ── */
const TRUST_COLORS = {
  cryptographic: { bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.3)', text: '#10b981' },
  'very-high': { bg: 'rgba(34,211,238,0.1)', border: 'rgba(34,211,238,0.25)', text: '#22d3ee' },
  high: { bg: 'rgba(59,130,246,0.1)', border: 'rgba(59,130,246,0.25)', text: '#3b82f6' },
  medium: { bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.25)', text: '#f59e0b' },
  low: { bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.25)', text: '#f97316' },
  none: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', text: '#ef4444' },
};

const TIER_COLORS = { 1: '#10b981', 2: '#22d3ee', 3: '#f59e0b', 4: '#94a3b8' };
const TIER_ICONS = { 1: '🔐', 2: '🎟️', 3: '🧬', 4: '📋' };

const TrustBadge = ({ level }) => {
  const c = TRUST_COLORS[level] || TRUST_COLORS.none;
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest"
      style={{ background: c.bg, border: `1px solid ${c.border}`, color: c.text }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.text, boxShadow: `0 0 6px ${c.text}` }} />
      {level}
    </span>
  );
};

const TrustGauge = ({ level }) => {
  const levels = ['none', 'low', 'medium', 'high', 'very-high', 'cryptographic'];
  const idx = levels.indexOf(level);
  return (
    <div className="flex items-center gap-0.5">
      {levels.map((l, i) => {
        const c = TRUST_COLORS[l];
        return <div key={l} style={{ width: 14 + i * 3, height: 6, borderRadius: 2,
          background: i <= idx ? c.text : 'rgba(255,255,255,0.04)',
          boxShadow: i <= idx ? `0 0 4px ${c.text}40` : 'none',
          transition: 'all 0.4s ease', transitionDelay: `${i * 60}ms` }} title={l} />;
      })}
    </div>
  );
};

const TierTag = ({ tier }) => (
  <span className="inline-flex items-center gap-0.5 px-1 py-0.5 rounded text-[8px] font-bold tracking-wider"
    style={{ color: TIER_COLORS[tier], border: `1px solid ${TIER_COLORS[tier]}33`, background: `${TIER_COLORS[tier]}0d` }}>
    {TIER_ICONS[tier]} T{tier}
  </span>
);

/* ── Two-Axis NHI Classification: Identity Integrity × Governance ── */
const NHI_CLASSIFICATIONS = {
  TRUSTED:       { label: 'TRUSTED NHI',    color: '#10b981' },
  SHADOW:        { label: 'SHADOW NHI',     color: '#f97316' },
  MISCONFIGURED: { label: 'MISCONFIGURED',  color: '#f59e0b' },
  ROGUE:         { label: 'ROGUE',          color: '#ef4444' },
};

const classifyNHI = (w, attest) => {
  if (w.type === 'credential' || w.type === 'external-resource') return null;

  const identityVerified = attest?.attested === true;

  const hasOwner = !!w.owner;
  const hasTeam = !!w.team;
  const hasEnv = !!w.environment && w.environment !== 'unknown';
  const labels = w._labels || (typeof w.labels === 'object' ? w.labels : {});
  const hasLabels = Object.keys(labels).length >= 2;
  const hasNamespace = !!w.namespace;

  const governed = hasOwner && hasTeam && hasEnv;

  const govChecks = [
    { key: 'owner',     label: 'Owner assigned',  weight: 35, passed: hasOwner },
    { key: 'team',      label: 'Team tagged',      weight: 30, passed: hasTeam },
    { key: 'env',       label: 'Environment set',   weight: 20, passed: hasEnv },
    { key: 'labels',    label: '2+ labels',         weight: 10, passed: hasLabels },
    { key: 'namespace', label: 'Namespace set',     weight: 5,  passed: hasNamespace },
  ];
  const govScore = govChecks.reduce((s, c) => s + (c.passed ? c.weight : 0), 0);
  const govMissing = govChecks.filter(c => !c.passed);

  let classification;
  if (identityVerified && governed)   classification = 'TRUSTED';
  else if (identityVerified && !governed) classification = 'SHADOW';
  else if (!identityVerified && governed) classification = 'MISCONFIGURED';
  else                                    classification = 'ROGUE';

  const meta = NHI_CLASSIFICATIONS[classification];
  return {
    classification, label: meta.label, color: meta.color,
    identityVerified, governed, govScore, govChecks, govMissing,
  };
};

const CategoryPill = ({ category }) => {
  if (!category) return null;
  const map = {
    identity:   { label: 'Identity',   color: '#3b82f6' },
    governance: { label: 'Governance', color: '#8b5cf6' },
    mixed:      { label: 'Mixed',      color: '#f59e0b' },
  };
  const c = map[category] || map.mixed;
  return (
    <span className="text-[8px] font-bold px-1 py-0 rounded-full ml-1"
      style={{ color: c.color, background: `${c.color}15`, border: `1px solid ${c.color}25` }}>
      {c.label}
    </span>
  );
};

/* ── Posture Actions — grouped into Required / Recommended / Optional ── */
const computePostureActions = (w, attest) => {
  const required = [];
  const recommended = [];
  const optional = []; // { method, description, needs, tier }

  // ── Required: blocks full security posture ──
  if (!w.owner) required.push({ id: 'owner', issue: 'No owner assigned', fix: 'Assign an owner for accountability', impact: '+15 score', fixable: 'owner', category: 'governance' });
  if (!w.team) required.push({ id: 'team', issue: 'No team assigned', fix: 'Tag with the responsible team', impact: '+10 score', fixable: 'team', category: 'governance' });
  const cls = classifyNHI(w, attest);
  if (cls && (cls.classification === 'SHADOW' || cls.classification === 'ROGUE')) {
    required.push({
      id: 'shadow',
      issue: cls.classification === 'SHADOW' ? 'Shadow NHI — attested but ungoverned' : 'Rogue — unverified and ungoverned',
      fix: 'Assign owner, team, and environment to clear governance gap',
      impact: 'Clears shadow', category: 'governance'
    });
  }
  if (!attest) required.push({ id: 'attest', issue: 'Not attested', fix: 'Run attestation to verify identity', impact: 'Enables trust', category: 'identity' });

  // ── Recommended: improves security posture ──
  if (!w._labels || Object.keys(w._labels).length < 2) recommended.push({ id: 'labels', issue: 'Missing labels', fix: 'Add environment, service, and purpose labels', impact: '+5 score', category: 'governance' });
  if (!w.environment || w.environment === 'unknown') recommended.push({ id: 'env', issue: 'Unknown environment', fix: 'Set environment for policy enforcement', impact: '+5 score', fixable: 'environment', category: 'governance' });

  if (attest) {
    if (attest.trust_level === 'low' || attest.trust_level === 'medium') {
      const hasSpire = attest.attestation_chain?.some(s => s.claims?.spire_verified_by || s.claims?.spire_entry_id);
      if (!hasSpire) {
        recommended.push({ id: 'trust', issue: `Trust: ${attest.trust_level}`, fix: 'Provide platform tokens or deploy SPIRE', impact: 'Upgrade trust', category: 'identity' });
      }
    }

    // Categorize non-passing attestation methods
    if (attest.results && Array.isArray(attest.results)) {
      const isSpireVerified = attest.attestation_chain?.some(s => s.claims?.spire_verified_by || s.claims?.spire_entry_id);
      for (const r of attest.results) {
        if (r.success) continue;
        if (r.success === null) continue; // null = skipped (e.g. OPA unavailable)
        const reason = (r.reason || '').toLowerCase();
        const method = r.method || '';

        // Skip environment-dependent checks
        if (['container-verified', 'network-verified', 'process-attested'].includes(method)) continue;

        // ABAC score → recommended (auto-resolves when owner/team/labels fixed)
        if (method === 'abac-multi-signal' && /insufficient/i.test(reason)) {
          const scoreMatch = reason.match(/score:\s*(\d+)/);
          const score = scoreMatch ? scoreMatch[1] : '?';
          recommended.push({ id: 'abac', issue: `ABAC Score: ${score}/100`, fix: 'Auto-improves when you fix owner, team, and labels above', impact: 'Auto-resolves', category: 'mixed' });
          continue;
        }

        // GCP metadata JWT failure on service accounts = not applicable, not a failure
        if (method === 'gcp-metadata-jwt' && /no gcp identity token/i.test(reason)) {
          optional.push({ method: 'GCP Metadata JWT', description: 'Platform identity token verification', needs: 'Only available on running compute', tier: 1, category: 'identity' });
          continue;
        }

        // Don't show "Deploy SPIRE" if SPIRE already verified this workload
        if (method === 'spiffe-jwt-svid' && /no jwt-svid/i.test(reason)) {
          if (!isSpireVerified) {
            optional.push({ method: 'SPIFFE JWT-SVID', description: 'Cryptographic JWT identity', needs: 'Deploy SPIRE', tier: 1, category: 'identity' });
          }
        } else if (method === 'spiffe-x509-svid' && /no spiffe/i.test(reason)) {
          // Covered by "No SPIFFE ID" above if applicable
        } else if (method === 'policy-approved') {
          optional.push({ method: 'OPA Policy', description: 'Automated policy evaluation', needs: 'Deploy OPA engine', tier: 4, category: 'governance' });
        } else if (method === 'vault-token-lookup') {
          optional.push({ method: 'Vault Lookup', description: 'Secret management verification', needs: 'Deploy Vault', tier: 2, category: 'identity' });
        } else if (method === 'k8s-token-review') {
          optional.push({ method: 'K8s TokenReview', description: 'Kubernetes service account', needs: 'Deploy in K8s', tier: 2, category: 'identity' });
        }
        // All other failures → silently skip (don't show as actionable)
      }
    }
  }

  if (!w.spiffe_id) recommended.push({ id: 'spiffe', issue: 'No SPIFFE ID', fix: 'Register in SPIRE for cryptographic identity', impact: 'Tier 1 attestation', category: 'identity' });

  return { required, recommended, optional };
};

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#60a5fa', info: '#94a3b8' };
const TIER_COLORS_MAP = { 1: '#10b981', 2: '#22d3ee', 3: '#f59e0b', 4: '#94a3b8' };

/* ── Attestation Detail Panel — No duplicate name, with actions ── */
// ── Audit Log Component ──
const AuditLog = ({ workloadId }) => {
  const [open, setOpen] = React.useState(false);
  const [logs, setLogs] = React.useState([]);
  const [loading, setLoading] = React.useState(false);

  const fetchLogs = async () => {
    if (logs.length > 0) { setOpen(!open); return; }
    setLoading(true);
    setOpen(true);
    try {
      const res = await fetch(`/api/v1/workloads/${workloadId}/audit-log`);
      const data = await res.json();
      setLogs(data.history || []);
    } catch { setLogs([]); }
    finally { setLoading(false); }
  };

  const sourceColors = {
    'single-attest': '#3b82f6',
    'auto-attest': '#10b981',
    'auto-attest-manual-review': '#f59e0b',
    'manual-approval': '#a78bfa',
    'bulk-attest': '#22d3ee',
  };

  return (
    <div className="mt-3 border-t border-white/[0.04] pt-2">
      <button onClick={fetchLogs}
        className="flex items-center gap-2 text-[11px] text-nhi-ghost hover:text-nhi-dim transition-colors">
        <Clock className="w-3.5 h-3.5" />
        <span className="font-semibold uppercase tracking-wider">Audit Log</span>
        <span className="text-nhi-faint">{open ? '▾' : '▸'}</span>
        {logs.length > 0 && <span className="text-[10px] text-nhi-faint">({logs.length} events)</span>}
      </button>
      {open && (
        <div className="mt-2 max-h-48 overflow-y-auto">
          {loading && <div className="text-[11px] text-nhi-ghost py-2">Loading audit history...</div>}
          {!loading && logs.length === 0 && (
            <div className="text-[11px] text-nhi-ghost py-2">No attestation events recorded yet. Attest this identity to start building an audit trail.</div>
          )}
          {logs.map((log, i) => {
            const data = typeof log.attestation_data === 'string' ? JSON.parse(log.attestation_data) : (log.attestation_data || {});
            let src = data.source || log.primary_method || 'unknown';
            // Fix display: if trust is cryptographic/very-high, show as auto-attest not manual review
            if ((log.trust_level === 'cryptographic' || log.trust_level === 'very-high') && src === 'auto-attest-manual-review') {
              src = 'auto-attest';
            }
            return (
              <div key={log.id || i} className="flex items-start gap-3 py-1.5 border-b border-white/[0.02] last:border-0">
                <div className="text-[10px] text-nhi-faint w-32 shrink-0 font-mono">
                  {new Date(log.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                      style={{ color: sourceColors[src] || '#888', background: `${sourceColors[src] || '#888'}15`, border: `1px solid ${sourceColors[src] || '#888'}30` }}>
                      {src.replace(/-/g, ' ')}
                    </span>
                    <span className="text-[11px] font-semibold" style={{ color: TRUST_COLORS[log.trust_level]?.text || '#888' }}>
                      {log.trust_level?.replace('-', ' ')}
                    </span>
                    <span className="text-[10px] text-nhi-ghost">
                      {log.methods_passed}/{(log.methods_passed || 0) + (log.methods_failed || 0)} methods
                    </span>
                  </div>
                  {data.reasons?.length > 0 && !(log.trust_level === 'cryptographic' || log.trust_level === 'very-high') && (
                    <div className="text-[10px] text-nhi-ghost mt-0.5">{data.reasons[0]}</div>
                  )}
                  {data.missing?.length > 0 && !(log.trust_level === 'cryptographic' || log.trust_level === 'very-high') && (
                    <div className="text-[10px] text-amber-400/70 mt-0.5">{data.missing.length} action{data.missing.length > 1 ? 's' : ''} needed</div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const DetailPanel = ({ w, onRefresh, navigate }) => {
  const [attestResult, setAttestResult] = React.useState(null);
  const [attesting, setAttesting] = React.useState(false);
  const [inspectIdx, setInspectIdx] = React.useState(null);
  const [manualOpen, setManualOpen] = React.useState(false);
  const [manualName, setManualName] = React.useState('');
  const [manualReason, setManualReason] = React.useState('');
  const [verifying, setVerifying] = React.useState(false);
  // Owner/Team assignment
  const [editingField, setEditingField] = React.useState(null);
  const [fieldValue, setFieldValue] = React.useState('');
  const [saving, setSaving] = React.useState(false);

  const attest = attestResult || (() => {
    if (!w.attestation_data) return null;
    if (typeof w.attestation_data === 'string') {
      try { return JSON.parse(w.attestation_data); } catch { return null; }
    }
    return typeof w.attestation_data === 'object' ? w.attestation_data : null;
  })();

  const runAttestation = async () => {
    setAttesting(true); setAttestResult(null); setInspectIdx(null);
    try {
      const res = await fetch(`/api/v1/workloads/${w.id}/attest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ evidence: {} }) });
      const data = await res.json();
      setAttestResult(data);
      toast.success(`${data.trust_level} trust · ${data.methods_passed}/${data.methods_attempted} passed`);
      if (onRefresh) setTimeout(onRefresh, 500);
    } catch (e) { toast.error('Attestation failed'); }
    finally { setAttesting(false); }
  };

  const runManualApproval = async () => {
    if (!manualName || !manualReason) return;
    try {
      await fetch(`/api/v1/workloads/${w.id}/attest/manual`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ approved_by: manualName, reason: manualReason }) });
      toast.success('Manual approval recorded');
      setManualOpen(false); setManualName(''); setManualReason('');
      if (onRefresh) setTimeout(onRefresh, 500);
    } catch (e) { toast.error('Approval failed'); }
  };

  const saveField = async (field, value) => {
    if (!value.trim()) return;
    setSaving(true);
    try {
      const res = await fetch(`/api/v1/workloads/${w.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [field]: value.trim() })
      });
      if (res.ok) {
        toast.success(`${field} updated to "${value.trim()}"`);
        setEditingField(null); setFieldValue('');
        if (onRefresh) setTimeout(onRefresh, 300);
      } else { toast.error('Failed to update'); }
    } catch (e) { toast.error('Error saving'); }
    finally { setSaving(false); }
  };

  const startEdit = (field, currentVal) => {
    setEditingField(field);
    setFieldValue(currentVal || '');
  };

  const trustLevel = attest?.trust_level || w.trust_level || 'none';
  const posture = computePostureActions(w, attest);
  const totalActionable = posture.required.length + posture.recommended.length;

  return (
    <div className="col-span-full px-5 py-3 bg-surface-0/50 border-b border-white/[0.03] animate-fadeIn">

      {/* ── Credential / Resource Detail Panel ── */}
      {(w.type === 'credential' || w.type === 'external-resource') ? (() => {
        const m = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
        const riskFlags = m.risk_flags || [];
        const riskLevel = m.risk_level || 'low';
        const scope = m.scope || [];
        const riskColors = { low: '#10b981', medium: '#f59e0b', high: '#ef4444', critical: '#dc2626' };

        return (<>
          {/* Header */}
          <div className="flex items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-2 min-w-0 flex-1">
              {w.spiffe_id && <span className="text-[11px] text-nhi-dim/80 font-mono truncate bg-white/[0.03] px-2 py-1 rounded border border-white/[0.06]">{w.spiffe_id}</span>}
              <span className="text-[11px] text-nhi-ghost">{w.type === 'credential' ? '🔑 Credential' : '🔗 External Resource'} · {m.provider || 'Unknown'}</span>
            </div>
            {m.parent_identity && (
              <span className="text-[11px] text-violet-400 bg-violet-400/8 border border-violet-400/15 px-2 py-0.5 rounded">
                Used by: <span className="font-semibold">{m.parent_identity}</span>
              </span>
            )}
          </div>

          {w.type === 'credential' ? (<>
            <div className="grid grid-cols-3 gap-4">
              {/* Column 1: Credential Identity */}
              <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                <div className="text-[10px] font-bold text-nhi-faint uppercase tracking-wider mb-2">Credential Details</div>
                <div className="space-y-1.5">
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Type</span><span className="text-[11px] text-nhi-muted font-medium">{m.credential_type || m.subcategory || 'API Key'}</span></div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Provider</span><span className="text-[11px] text-nhi-muted font-medium">{m.provider || '—'}</span></div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Storage</span><span className="text-[11px] text-nhi-muted font-medium">{(m.storage_method || 'unknown').replace(/-/g, ' ')}</span></div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Status</span>
                    <span className="text-[11px] font-bold" style={{ color: m.lifecycle_status === 'revoked' ? '#ef4444' : m.lifecycle_status === 'expired' ? '#f59e0b' : '#10b981' }}>
                      {(m.lifecycle_status || 'active').toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Column 2: Lifecycle */}
              <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                <div className="text-[10px] font-bold text-nhi-faint uppercase tracking-wider mb-2">Lifecycle</div>
                <div className="space-y-1.5">
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Created</span><span className="text-[11px] text-nhi-muted">{m.created_at ? new Date(m.created_at).toLocaleDateString() : '—'}</span></div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Expires</span>
                    <span className={`text-[11px] font-medium ${m.never_expires ? 'text-red-400' : 'text-nhi-muted'}`}>{m.never_expires ? '⚠ Never' : (m.expires_at ? new Date(m.expires_at).toLocaleDateString() : '—')}</span>
                  </div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Last Rotated</span>
                    <span className={`text-[11px] font-medium ${!m.last_rotated ? 'text-amber-400' : 'text-nhi-muted'}`}>{m.last_rotated ? new Date(m.last_rotated).toLocaleDateString() : '⚠ Never'}</span>
                  </div>
                  <div className="flex justify-between"><span className="text-[11px] text-nhi-ghost">Last Used</span><span className="text-[11px] text-nhi-muted">{m.last_used ? new Date(m.last_used).toLocaleDateString() : '—'}</span></div>
                </div>
              </div>

              {/* Column 3: Risk Posture */}
              <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                <div className="text-[10px] font-bold text-nhi-faint uppercase tracking-wider mb-2">Risk Posture</div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded" style={{ color: riskColors[riskLevel], background: `${riskColors[riskLevel]}15`, border: `1px solid ${riskColors[riskLevel]}25` }}>
                    {riskLevel.toUpperCase()} RISK
                  </span>
                  <span className="text-[10px] text-nhi-ghost">Score: {(() => { const _ad = (() => { if (!w.attestation_data) return null; if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } } return w.attestation_data; })(); return _ad?.correlated?.security_score ?? w.security_score ?? '—'; })()}</span>
                </div>
                {riskFlags.length > 0 && (
                  <div className="space-y-1">
                    {riskFlags.map((f, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                        <span className="text-[11px] text-red-400/80">{f.replace(/-/g, ' ').replace(/^\w/, c => c.toUpperCase())}</span>
                      </div>
                    ))}
                  </div>
                )}
                {riskFlags.length === 0 && <span className="text-[11px] text-emerald-400">✓ No risk flags</span>}
                {scope.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-white/[0.04]">
                    <div className="text-[10px] font-bold text-nhi-faint uppercase tracking-wider mb-1">Scope / Permissions</div>
                    <div className="flex flex-wrap gap-1">
                      {scope.map((s, i) => <span key={i} className="text-[10px] text-nhi-dim bg-white/[0.04] px-1.5 py-0.5 rounded font-mono">{s}</span>)}
                    </div>
                  </div>
                )}
              </div>
            </div>
            {/* Graph button — view this workload's identity in the graph */}
            <div className="flex items-center justify-end mt-3 pt-3 border-t border-white/[0.04]">
              {m.parent_identity && (
                <span className="text-[11px] text-nhi-dim mr-auto">
                  via <span className="text-violet-400 font-semibold">{m.parent_identity}</span>
                </span>
              )}
              <button onClick={(e) => { e.stopPropagation(); navigate(`/graph?focus=${encodeURIComponent(w.name)}`); }}
                className="text-[11px] font-bold text-nhi-dim bg-white/[0.04] border border-white/[0.08] px-3 py-1.5 rounded-md hover:bg-white/[0.08] hover:text-cyan-400 transition-colors flex items-center gap-1.5">
                <GitBranch className="w-3 h-3" /> View in Graph
              </button>
            </div>
          </>) : (() => {
            /* External Resource detail — 5-Tier Verification */
            const verification = m.verification;
            const vScore = verification?.composite_score;
            const vStatus = verification?.composite_status;
            const tierStatusColors = { verified: '#10b981', partial: '#f59e0b', unverified: '#ef4444', pending: '#6b7280', unknown: '#6b7280' };
            const checkStatusIcons = { pass: '✓', fail: '✗', warn: '⚠', pending: '○', unknown: '?', info: 'ℹ' };
            const checkStatusColors = { pass: '#10b981', fail: '#ef4444', warn: '#f59e0b', pending: '#6b7280', unknown: '#6b7280', info: '#60a5fa' };

            // verifying state is declared at DetailPanel top level
            const runVerify = async () => {
              setVerifying(true);
              try {
                await fetch(`/api/v1/workloads/resources/${w.id}/verify`, { method: 'POST' });
                if (onRefresh) setTimeout(onRefresh, 500);
              } catch {}
              finally { setVerifying(false); }
            };

            return (
            <div>
              {/* Header — verification score + verify button */}
              <div className="flex items-center justify-between gap-3 mb-4">
                <div className="flex items-center gap-3">
                  {w.spiffe_id && <span className="text-[11px] text-nhi-dim/80 font-mono truncate bg-white/[0.03] px-2 py-1 rounded border border-white/[0.06]">{w.spiffe_id}</span>}
                  {vScore !== undefined && vScore !== null ? (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded" style={{ color: tierStatusColors[vStatus] || '#888', background: `${tierStatusColors[vStatus] || '#888'}15`, border: `1px solid ${tierStatusColors[vStatus] || '#888'}30` }}>
                      {vStatus === 'verified' ? '✅' : vStatus === 'partially-verified' ? '⚠️' : '❌'} Verification Score: {vScore}/100
                    </span>
                  ) : (
                    <span className="text-[11px] text-nhi-ghost italic">Not yet verified</span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={(e) => { e.stopPropagation(); navigate(`/graph?focus=${encodeURIComponent(w.name)}`); }}
                    className="text-[11px] font-bold text-nhi-dim bg-white/[0.04] border border-white/[0.08] px-3 py-1.5 rounded-md hover:bg-white/[0.08] transition-colors flex items-center gap-1">
                    <GitBranch className="w-3 h-3" /> View in Graph
                  </button>
                  <button onClick={runVerify} disabled={verifying}
                    className="text-[11px] font-bold text-cyan-400 bg-cyan-400/10 border border-cyan-400/20 px-3 py-1.5 rounded-md hover:bg-cyan-400/20 transition-colors disabled:opacity-50">
                    {verifying ? '⏳ Verifying...' : '🔍 Verify Resource'}
                  </button>
                </div>
              </div>
              {/* Resource summary row */}
              <div className="flex items-center gap-6 mb-4 px-2">
                <div className="text-[11px]"><span className="text-nhi-ghost">Provider: </span><span className="text-nhi-muted font-medium">{m.provider || '—'}</span></div>
                <div className="text-[11px]"><span className="text-nhi-ghost">Domain: </span><span className="text-nhi-muted font-mono">{verification?.domain || '—'}</span></div>
                <div className="text-[11px]"><span className="text-nhi-ghost">Connected via: </span><span className="text-violet-400 font-medium">{m.parent_identity || '—'}</span></div>
                <div className="text-[11px]"><span className="text-nhi-ghost">Trust Domain: </span><span className="text-nhi-muted font-mono">{m.federation?.source_domain || w.namespace || '—'}</span></div>
              </div>

              {/* 5-Tier verification grid */}
              {verification?.tiers ? (
                <div className="space-y-2">
                  {verification.tiers.map((tier, ti) => {
                    const tColor = tierStatusColors[tier.status] || '#6b7280';
                    return (
                      <div key={ti} className="bg-white/[0.02] rounded-lg border border-white/[0.04] overflow-hidden">
                        {/* Tier header */}
                        <div className="flex items-center justify-between px-3 py-2 border-b border-white/[0.03]">
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] font-bold" style={{ color: tColor }}>Tier {tier.tier}</span>
                            <span className="text-[11px] text-nhi-muted font-medium">{tier.label}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {tier.score !== null && tier.score !== undefined ? (
                              <>
                                <div className="w-20 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                                  <div className="h-full rounded-full transition-all" style={{ width: `${tier.score}%`, background: tColor }} />
                                </div>
                                <span className="text-[11px] font-bold" style={{ color: tColor }}>{tier.score}/100</span>
                              </>
                            ) : (
                              <span className="text-[10px] text-nhi-ghost italic">{tier.status === 'pending' ? 'Pending Setup' : 'N/A'}</span>
                            )}
                          </div>
                        </div>
                        {/* Tier checks */}
                        <div className="px-3 py-1.5 space-y-0.5">
                          {tier.checks.map((c, ci) => (
                            <div key={ci} className="flex items-center justify-between py-0.5">
                              <div className="flex items-center gap-1.5">
                                <span className="text-[11px] w-3 text-center" style={{ color: checkStatusColors[c.status] }}>{checkStatusIcons[c.status]}</span>
                                <span className="text-[11px] text-nhi-dim">{c.check}</span>
                              </div>
                              <span className="text-[10px] text-nhi-ghost">{c.detail}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-6 bg-white/[0.02] rounded-lg border border-white/[0.04]">
                  <span className="text-[11px] text-nhi-ghost">Click "Verify Resource" to run the 5-tier verification assessment</span>
                </div>
              )}
            </div>
            );
          })()}
        </>);
      })() : (<>

      {/* ── Standard Identity Detail Panel ── */}
      {/* Header: SPIFFE + Trust gauge + Attest — NO name (already visible in row above) */}
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          {w.spiffe_id && <span className="text-[11px] text-nhi-dim/80 font-mono truncate bg-white/[0.03] px-2 py-1 rounded border border-white/[0.06]">{w.spiffe_id}</span>}
          {!w.spiffe_id && <span className="text-[11px] text-red-400/60 bg-red-400/5 px-2 py-1 rounded border border-red-400/10">No SPIFFE ID</span>}
          <span className="text-[11px] text-nhi-ghost">{w.type} · {w.discovered_by}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <TrustBadge level={trustLevel} />
          {attest?.multi_signal_bonus && <span className="text-[10px] text-cyan-400 bg-cyan-400/8 border border-cyan-400/15 px-1.5 py-0.5 rounded font-bold">✦ BONUS</span>}
          <TrustGauge level={trustLevel} />
          <button onClick={(e) => { e.stopPropagation(); navigate(`/graph?focus=${encodeURIComponent(w.name)}`); }}
            className="px-2.5 py-1.5 rounded text-[10px] font-bold text-nhi-dim bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] transition-all flex items-center gap-1">
            <GitBranch className="w-3 h-3" /> Graph
          </button>
          <button onClick={runAttestation} disabled={attesting}
            className={`px-3 py-1.5 rounded text-[10px] font-bold uppercase tracking-wider transition-all hover:scale-105 disabled:opacity-50 flex items-center gap-1.5 ${
              attest?.attested ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400' : 'bg-blue-500/15 border border-blue-500/25 text-blue-400'
            }`}>
            {attesting
              ? <><Loader className="w-3 h-3 animate-spin" /> Attesting...</>
              : attest?.attested
              ? <><RefreshCw className="w-3 h-3" /> Re-Attest</>
              : <><ShieldCheck className="w-3 h-3" /> Attest</>}
          </button>
        </div>
      </div>

      {/* Classification Alert — shows for non-TRUSTED classifications */}
      {(() => {
        const _cls = classifyNHI(w, attest);
        if (!_cls || _cls.classification === 'TRUSTED') return null;
        const alertCfg = {
          SHADOW:        { icon: Eye, color: '#f97316', title: 'SHADOW NHI', desc: 'Identity verified but ungoverned — highest risk: passes zero-trust checks but invisible to governance' },
          ROGUE:         { icon: AlertTriangle, color: '#ef4444', title: 'ROGUE', desc: 'Neither identity verified nor governed — unknown workload' },
          MISCONFIGURED: { icon: AlertTriangle, color: '#f59e0b', title: 'MISCONFIGURED', desc: 'Governed but identity not verified — organizational controls present but cryptographic identity missing' },
        };
        const cfg = alertCfg[_cls.classification];
        const AlertIcon = cfg.icon;
        return (
          <div className="mb-3 p-3 rounded-lg" style={{ background: `${cfg.color}0a`, border: `1px solid ${cfg.color}33` }}>
            <div className="flex items-center gap-2 mb-1.5">
              <AlertIcon className="w-3.5 h-3.5" style={{ color: cfg.color }} />
              <span className="text-[10px] uppercase tracking-widest font-bold" style={{ color: cfg.color }}>{cfg.title}</span>
              <span className="text-[9px] font-mono" style={{ color: `${cfg.color}99` }}>gov: {_cls.govScore}/100</span>
            </div>
            <p className="text-[11px] mb-2" style={{ color: `${cfg.color}cc` }}>{cfg.desc}</p>
            <div className="flex flex-wrap gap-1.5">
              {!_cls.identityVerified && (
                <span className="text-[10px] font-medium px-2 py-0.5 rounded-full" style={{ color: '#ef4444', background: '#ef444412', border: '1px solid #ef444420' }}>Not attested</span>
              )}
              {_cls.govMissing.map(g => (
                <span key={g.key} className="text-[10px] font-medium px-2 py-0.5 rounded-full" style={{ color: cfg.color, background: `${cfg.color}0c`, border: `1px solid ${cfg.color}20` }}>✗ {g.label}</span>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Unified AI Enrichment — shown for AI agents, MCP servers, and AI-related workloads */}
      {(w.is_ai_agent || w.is_mcp_server || w.category === 'ai-service') && (
        <AIEnrichmentPanel workloadId={w.id} workloadName={w.name} workload={w} inline />
      )}

      {/* Attestation Narrative — explains what happened and why */}
      {attest && (
        <div className="mb-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
          <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-2">Attestation Summary</div>
          <div className="text-[12px] text-nhi-dim leading-relaxed space-y-1.5">
            {/* Opening statement — use enriched summary if available */}
            <p>
              <span className="font-semibold" style={{ color: TRUST_COLORS[trustLevel]?.text }}>
                {trustLevel.replace('-', ' ').toUpperCase()}
              </span>
              {' '}trust achieved — {attest.methods_passed} attestation method{attest.methods_passed !== 1 ? 's' : ''} passed.
              {attest.methods_passed > 0 && attest.methods_attempted > attest.methods_passed && (
                <span className="text-nhi-ghost"> ({attest.methods_attempted - attest.methods_passed} not applicable for this workload type)</span>
              )}
            </p>

            {/* What methods ran and why */}
            {attest.attestation_chain && (
              <p className="text-nhi-muted">
                <span className="text-nhi-muted">Methods evaluated: </span>
                {[...attest.attestation_chain].sort((a, b) => (a.tier || 99) - (b.tier || 99)).map((step, i) => {
                  const passed = step.trust !== 'none';
                  return (
                    <span key={i}>
                      {i > 0 && ', '}
                      <span style={{ color: passed ? TRUST_COLORS[step.trust]?.text : '#ef4444' }}>
                        {step.label} {passed ? '✓' : '✗'}
                      </span>
                    </span>
                  );
                })}
              </p>
            )}

            {/* Multi-signal bonus explanation */}
            {attest.multi_signal_bonus && (
              <p>
                <span className="text-cyan-400 font-semibold">✦ Multi-signal bonus applied</span>
                <span className="text-nhi-ghost"> — {attest.methods_passed}+ methods passed, trust level boosted by one tier.
                  Like multi-factor auth for humans, multiple independent verification signals strengthen identity confidence.</span>
              </p>
            )}

            {/* Per-method highlights */}
            {attest.attestation_chain?.map((step, i) => {
              if (step.trust === 'none') return null;
              const claims = step.claims || {};
              if (claims.upgrade_to) {
                return (
                  <p key={i} className="text-nhi-muted">
                    <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                    {claims.verification || claims.current_trust || 'Passed'}.{' '}
                    <span className="text-amber-400/80">↑ Upgrade to {claims.upgrade_to}</span>
                    {claims.action_required && (
                      <span className="text-nhi-ghost"> — {claims.action_required.substring(0, 120)}{claims.action_required.length > 120 ? '...' : ''}</span>
                    )}
                  </p>
                );
              }
              if (claims.spiffe_id) {
                const isSpireVerified = claims.spire_verified_by || claims.spire_entry_id;
                return (
                  <div key={i} className="text-nhi-muted">
                    <p>
                      <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                      Identity <span className="font-mono text-[11px]">{claims.spiffe_id}</span> verified in trust domain <span className="font-semibold text-nhi-dim">{claims.spire_trust_domain || claims.trust_domain}</span>.
                      {isSpireVerified && <span className="text-emerald-400"> SPIRE Server cryptographically verified.</span>}
                    </p>
                    {isSpireVerified && (
                      <div className="ml-3 mt-1 text-[11px] text-nhi-ghost space-y-0.5">
                        {claims.spire_node_attestation && <p>Node attestation: <span className="text-nhi-dim font-mono">{claims.spire_node_attestation}</span></p>}
                        {claims.spire_entry_id && <p>Entry: <span className="font-mono">{claims.spire_entry_id}</span></p>}
                        {claims.node_identity && <p>Agent: <span className="font-mono text-[10px]">{claims.node_identity}</span></p>}
                        {claims.attestation_flow && <p className="text-emerald-400/60">Flow: {claims.attestation_flow}</p>}
                        {claims.certificate_authority && <p>CA: {claims.certificate_authority}</p>}
                      </div>
                    )}
                  </div>
                );
              }
              if (claims.arn) return (
                <p key={i} className="text-nhi-muted">
                  <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                  AWS ARN <span className="font-mono text-[11px]">{claims.arn}</span> verified in account <span className="font-semibold text-nhi-dim">{claims.account_id}</span>.
                </p>
              );
              if (claims.matched_name !== undefined) return (
                <p key={i} className="text-nhi-muted">
                  <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                  {claims.matched_name ? `Workload matches known "${w._category}" pattern in service catalog.` : 'No catalog match found.'}
                </p>
              );
              if (claims.score !== undefined && claims.signals_matched !== undefined) return (
                <p key={i} className="text-nhi-muted">
                  <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                  Scored {claims.score}/100 across {claims.signals_matched} attribute signals (threshold: {claims.threshold || 50}).
                  {claims.signals && Array.isArray(claims.signals) && <span className="text-[11px] text-nhi-ghost"> Signals: {claims.signals.map(s => s.attribute || s).join(', ')}</span>}
                </p>
              );
              // GCP metadata claims
              if (claims.service_account) return (
                <p key={i} className="text-nhi-muted">
                  <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                  Service account <span className="font-mono text-[11px]">{claims.service_account}</span> verified in project <span className="font-semibold text-nhi-dim">{claims.project_id}</span>.
                  {claims.signature_verified && <span className="text-emerald-400"> Signature cryptographically verified.</span>}
                </p>
              );
              if (claims.email) return (
                <p key={i} className="text-nhi-muted">
                  <span className="text-nhi-muted font-semibold">{step.label}:</span>{' '}
                  Identity token for <span className="font-mono text-[11px]">{claims.email}</span> verified.
                  {claims.signature_verified && <span className="text-emerald-400"> Google JWKS signature verified.</span>}
                  {claims.project_id && <span className="text-nhi-ghost"> Project: {claims.project_id}</span>}
                </p>
              );
              return null;
            })}

            {/* Correlated updates */}
            {attest.correlated && (
              <p className="text-nhi-muted pt-1 border-t border-white/[0.03] mt-1">
                <span className="text-nhi-muted font-semibold">Identity score impact:</span>{' '}
                Security score set to <span className="font-bold text-nhi-dim">{attest.correlated.security_score}/100</span>
              </p>
            )}

            {/* Expiry + Continuous Attestation Timer */}
            {attest.expires_at && (() => {
              const expiresAt = new Date(attest.expires_at);
              const now = new Date();
              const msLeft = expiresAt - now;
              const minsLeft = Math.max(0, Math.floor(msLeft / 60000));
              const hoursLeft = Math.floor(minsLeft / 60);
              const remainMins = minsLeft % 60;
              const timeStr = hoursLeft > 0 ? `${hoursLeft}h ${remainMins}m` : `${remainMins}m`;
              const isUrgent = msLeft < 600000;
              const isExpired = msLeft <= 0;
              return (
                <div className="mt-1 pt-1 border-t border-white/[0.03]">
                  <div className="flex items-center gap-2">
                    <Clock className={`w-3.5 h-3.5 ${isExpired ? 'text-red-400' : isUrgent ? 'text-amber-400' : 'text-emerald-400'}`} />
                    <span className="text-[12px] text-nhi-muted font-semibold">Next re-attestation:</span>
                    <span className={`text-[12px] font-bold font-mono ${isExpired ? 'text-red-400' : isUrgent ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {isExpired ? 'EXPIRED' : timeStr}
                    </span>
                    <span className="text-[11px] text-nhi-ghost">({expiresAt.toLocaleTimeString()})</span>
                  </div>
                </div>
              );
            })()}

            {/* WID Token — show if workload has an active token */}
            {w.wid_token && (() => {
              const tokenExp = w.token_expires_at ? new Date(w.token_expires_at) : null;
              const tokenActive = tokenExp && tokenExp > new Date();
              const tokenClaims = (() => { try { return typeof w.token_claims === 'string' ? JSON.parse(w.token_claims) : w.token_claims; } catch { return null; } })();
              return (
                <div className="mt-1 pt-1 border-t border-white/[0.03]">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-nhi-muted font-semibold text-[12px]">WID Token:</span>
                    <Info className="w-3 h-3 text-nhi-ghost cursor-help"
                      title="WID Token: Short-lived (5min) SPIFFE-bound JWT issued after attestation. EXPIRED is normal — a fresh token is issued on each authenticated request through the Edge Gateway." />
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${tokenActive ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400'}`}>
                      {tokenActive ? 'ACTIVE' : 'EXPIRED'}
                    </span>
                    {!tokenActive && <span className="text-[9px] text-nhi-ghost">(rotated on demand)</span>}
                    {tokenClaims?.trust_level && (
                      <span className="text-[10px] text-nhi-ghost">Trust: {tokenClaims.trust_level}</span>
                    )}
                    {w.token_jti && (
                      <span className="text-[10px] font-mono text-nhi-ghost/50 truncate max-w-[120px]">{w.token_jti}</span>
                    )}
                  </div>
                  {tokenClaims?.spiffe_id && (
                    <p className="text-[11px] text-nhi-ghost">
                      SPIFFE: <span className="font-mono">{tokenClaims.spiffe_id}</span>
                      {tokenClaims.ttl && <span> · TTL: {tokenClaims.ttl}s</span>}
                    </p>
                  )}
                </div>
              );
            })()}

            {/* Manual review required — only shown when NOT cryptographic */}
            {attest.requires_manual_review && trustLevel !== 'cryptographic' && trustLevel !== 'very-high' && (
              <div className="mt-1 pt-1 border-t border-red-400/10">
                <div className="flex items-center justify-between">
                  <p className="text-red-400 font-semibold">⚠ Manual review required</p>
                  {attest.confidence?.risk_weight && (
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      attest.confidence.risk_weight === 'critical' ? 'bg-red-500/15 text-red-400'
                      : attest.confidence.risk_weight === 'high' ? 'bg-orange-500/15 text-orange-400'
                      : 'bg-amber-500/15 text-amber-400'
                    }`}>
                      {attest.confidence.risk_weight} risk
                    </span>
                  )}
                </div>
                {attest.confidence?.reasons?.map((r, i) => (
                  <p key={`r${i}`} className="text-nhi-muted text-[11px]">• {r}</p>
                ))}
                {attest.confidence?.missing?.length > 0 && (
                  <>
                    <p className="text-amber-400/80 font-semibold mt-1">Actions needed to enable auto-attestation:</p>
                    {attest.confidence.missing.map((m, i) => (
                      <p key={`m${i}`} className="text-nhi-muted text-[11px]">→ {m}</p>
                    ))}
                  </>
                )}
              </div>
            )}

            {/* Confidence level for auto-attested */}
            {!attest.requires_manual_review && attest.confidence && (
              <p className="text-nhi-muted">
                <span className="text-nhi-muted font-semibold">Confidence:</span>{' '}
                <span style={{ color: attest.confidence.confidence_level === 'high' ? '#10b981' : '#f59e0b' }}>
                  {attest.confidence.confidence_level}
                </span>
                {attest.confidence.reasons?.length > 0 && <span> — {attest.confidence.reasons[0].replace(/Shadow status auto-cleared — /i, '')}</span>}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Governance Status — separate from attestation (identity) */}
      {(() => {
        const _cls = classifyNHI(w, attest);
        if (!_cls) return null;
        const quadrants = [
          { key: 'ROGUE',         label: 'R',  row: 0, col: 0 },
          { key: 'MISCONFIGURED', label: 'M',  row: 0, col: 1 },
          { key: 'SHADOW',        label: 'S',  row: 1, col: 0 },
          { key: 'TRUSTED',       label: 'T',  row: 1, col: 1 },
        ];
        return (
          <div className="mb-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold">Governance Status</span>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded" style={{ color: _cls.color, background: `${_cls.color}15`, border: `1px solid ${_cls.color}30` }}>{_cls.label}</span>
              </div>
              <span className="text-[11px] font-bold font-mono" style={{ color: _cls.govScore >= 85 ? '#10b981' : _cls.govScore >= 50 ? '#f59e0b' : '#ef4444' }}>{_cls.govScore}/100</span>
            </div>
            {/* Editable governance attributes */}
            <div className="grid grid-cols-3 gap-2 mb-2 pb-2 border-b border-white/[0.04]">
              {[
                { field: 'owner', label: 'Owner', value: w.owner, placeholder: 'user@company.com' },
                { field: 'team', label: 'Team', value: w.team, placeholder: 'platform-team' },
                { field: 'environment', label: 'Environment', value: w.environment && w.environment !== 'unknown' ? w.environment : null, placeholder: 'Select...' },
              ].map(attr => (
                <div key={attr.field}>
                  <div className="text-[9px] text-nhi-ghost uppercase tracking-wider font-bold mb-0.5">{attr.label}</div>
                  {editingField === `gov_${attr.field}` ? (
                    <div className="flex gap-1">
                      {attr.field === 'environment' ? (
                        <select value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                          className="flex-1 px-1.5 py-1 rounded text-[11px] bg-black/30 border border-white/[0.08] text-nhi-dim outline-none">
                          <option value="">Select...</option>
                          <option value="production">Production</option>
                          <option value="staging">Staging</option>
                          <option value="development">Development</option>
                          <option value="testing">Testing</option>
                        </select>
                      ) : (
                        <input type="text" value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                          placeholder={attr.placeholder} autoFocus
                          onKeyDown={e => e.key === 'Enter' && fieldValue.trim() && saveField(attr.field, fieldValue)}
                          className="flex-1 px-1.5 py-1 rounded text-[11px] bg-black/30 border border-white/[0.08] text-nhi-dim placeholder-nhi-ghost outline-none min-w-0" />
                      )}
                      <button onClick={() => saveField(attr.field, fieldValue)} disabled={!fieldValue.trim() || saving}
                        className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 disabled:opacity-30">
                        {saving ? '...' : '✓'}
                      </button>
                      <button onClick={() => { setEditingField(null); setFieldValue(''); }}
                        className="px-1 py-0.5 rounded text-[9px] text-nhi-ghost hover:text-nhi-dim">✕</button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 group/attr cursor-pointer"
                      onClick={() => { setEditingField(`gov_${attr.field}`); setFieldValue(attr.value || ''); }}>
                      {attr.value ? (
                        <span className="text-[11px] text-nhi-muted font-medium truncate">{attr.value}</span>
                      ) : (
                        <span className="text-[11px] text-nhi-ghost italic">Not set</span>
                      )}
                      <span className="text-[9px] text-nhi-ghost opacity-0 group-hover/attr:opacity-100 transition-opacity">✎</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
            <div className="flex gap-4">
              {/* Governance checklist */}
              <div className="flex-1 grid grid-cols-2 gap-x-4 gap-y-1">
                {_cls.govChecks.map(c => (
                  <div key={c.key} className="flex items-center gap-1.5">
                    <span className="text-[11px]" style={{ color: c.passed ? '#10b981' : '#ef4444' }}>{c.passed ? '✓' : '✗'}</span>
                    <span className="text-[11px] text-nhi-dim">{c.label}</span>
                    {!c.passed && <span className="text-[9px] text-nhi-ghost font-mono">+{c.weight}</span>}
                  </div>
                ))}
              </div>
              {/* Compact 2x2 matrix */}
              <div className="shrink-0">
                <div className="grid grid-cols-2 gap-px" style={{ width: 52, height: 36 }}>
                  {quadrants.map(q => {
                    const active = q.key === _cls.classification;
                    const qColor = NHI_CLASSIFICATIONS[q.key].color;
                    return (
                      <div key={q.key} className="flex items-center justify-center rounded-sm text-[7px] font-bold"
                        style={{
                          background: active ? `${qColor}30` : 'rgba(255,255,255,0.02)',
                          color: active ? qColor : '#888',
                          border: active ? `1px solid ${qColor}50` : '1px solid rgba(255,255,255,0.04)',
                        }}>
                        {q.label}
                      </div>
                    );
                  })}
                </div>
                <div className="text-[7px] text-nhi-ghost text-center mt-0.5" style={{ width: 52 }}>
                  {_cls.identityVerified ? '✓' : '✗'} Id · {_cls.governed ? '✓' : '✗'} Gov
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Content: 3-column grid */}
      <div className={`grid ${attest?.requires_manual_review && trustLevel !== 'cryptographic' && trustLevel !== 'very-high' ? 'grid-cols-[1fr_1fr_1fr]' : 'grid-cols-[1.2fr_1fr_0.8fr]'} gap-4 min-w-0 overflow-hidden`}>

        {/* Col 1: Attestation Chain or Identity Details */}
        <div>
          {attest?.attestation_chain ? (() => {
            // Sort by tier but preserve original index for detail panel lookup
            const sorted = attest.attestation_chain.map((step, origIdx) => ({ ...step, _origIdx: origIdx }))
              .sort((a, b) => (a.tier || 99) - (b.tier || 99));
            return (
            <>
              <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-2">Attestation Chain</div>
              <div className="space-y-1.5">
                {sorted.map((step, i) => {
                  const c = TRUST_COLORS[step.trust] || TRUST_COLORS.none;
                  const passed = step.trust !== 'none';
                  return (
                    <div key={i} onClick={() => setInspectIdx(inspectIdx === step._origIdx ? null : step._origIdx)}
                      className="cursor-pointer hover:brightness-125 transition-all flex items-center justify-between py-1.5 px-2.5 rounded-r"
                      style={{ borderLeft: `2px solid ${passed ? c.text : '#555'}`, background: inspectIdx === step._origIdx ? `linear-gradient(90deg, ${c.bg}, ${c.bg}80)` : passed ? `linear-gradient(90deg, ${c.bg}, transparent)` : 'transparent' }}>
                      <div className="flex items-center gap-2">
                        <TierTag tier={step.tier} />
                        <span className="text-[12px] font-medium" style={{ color: passed ? c.text : '#888' }}>{step.label}</span>
                      </div>
                      <span className="text-[11px]" style={{ color: passed ? c.text : '#ef4444' }}>{passed ? '✓' : '✗'}</span>
                    </div>
                  );
                })}
              </div>
            </>
            );
          })() : (
            <>
              <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-2">Details</div>
              <div className="space-y-1.5 text-[12px]">
                {w._vendor && <div><span className="text-nhi-ghost">Vendor:</span> <span className="text-nhi-muted font-semibold">{w._vendor}</span></div>}
                {w.metadata?.image && <div><span className="text-nhi-ghost">Image:</span> <span className="text-nhi-muted font-mono text-[11px]">{w.metadata.image}</span></div>}
                {w.metadata?.runtime && <div><span className="text-nhi-ghost">Runtime:</span> <span className="text-nhi-muted">{w.metadata.runtime}</span></div>}
                {w._ports && <div><span className="text-nhi-ghost">Ports:</span> <span className="text-nhi-dim font-mono">{w._ports.join(', ')}</span></div>}
                {w.metadata?.memory_size && <div><span className="text-nhi-ghost">Memory:</span> <span className="text-nhi-muted">{w.metadata.memory_size}MB</span></div>}
                {w.metadata?.handler && <div><span className="text-nhi-ghost">Handler:</span> <span className="text-nhi-muted font-mono text-[11px]">{w.metadata.handler}</span></div>}
                {w.metadata?.role && <div><span className="text-nhi-ghost">Role:</span> <span className="text-nhi-dim font-mono text-[11px] break-all">{w.metadata.role}</span></div>}
              </div>
            </>
          )}
        </div>

        {/* Col 2: Posture Actions — Grouped: Required / Recommended / Optional */}
        <div className="min-w-0 overflow-hidden">
          <div className="flex items-center justify-between mb-2 flex-wrap gap-1">
            <span className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold">Posture Actions</span>
            {totalActionable > 0 ? (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full" style={{
                background: posture.required.length > 0 ? '#ef444418' : '#f59e0b18',
                color: posture.required.length > 0 ? '#ef4444' : '#f59e0b',
              }}>{totalActionable} action{totalActionable !== 1 ? 's' : ''}</span>
            ) : (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-emerald-400/10 text-emerald-400">✓ clean</span>
            )}
          </div>

          {totalActionable === 0 && posture.optional.length === 0 ? (
            <div className="text-[12px] text-emerald-400/70 flex items-center gap-1.5 py-4"><Check className="w-3.5 h-3.5" /> All checks passed</div>
          ) : (
            <div className="space-y-3">

              {/* Required section */}
              {posture.required.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    <span className="text-[8px] font-bold uppercase tracking-widest text-red-400">Required</span>
                  </div>
                  <div className="space-y-1">
                    {posture.required.map((a, i) => {
                      const isEditing = a.fixable && editingField === a.fixable;
                      return (
                        <div key={a.id} className="py-1.5 px-2 rounded" style={{ borderLeft: '2px solid #ef4444', background: '#ef444408' }}>
                          <div className="flex items-start justify-between gap-2 flex-wrap">
                            <span className="text-[11px] font-semibold text-red-400 min-w-0 break-words">{a.issue}<CategoryPill category={a.category} /></span>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-[9px] text-emerald-400 font-mono">{a.impact}</span>
                              {a.fixable && !isEditing && (
                                <button onClick={() => startEdit(a.fixable, '')}
                                  className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-accent hover:bg-accent/10 transition-colors">
                                  Fix →
                                </button>
                              )}
                            </div>
                          </div>
                          {isEditing ? (
                            <div className="flex gap-1.5 mt-1.5">
                              <input type="text" value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                                placeholder={a.fixable === 'owner' ? 'user@company.com' : 'platform-team'}
                                autoFocus onKeyDown={e => e.key === 'Enter' && saveField(a.fixable, fieldValue)}
                                className="flex-1 px-2 py-1.5 rounded text-[11px] bg-black/30 border border-white/[0.08] text-nhi-dim placeholder-nhi-ghost outline-none" />
                              <button onClick={() => saveField(a.fixable, fieldValue)} disabled={!fieldValue.trim() || saving}
                                className="px-2 py-1 rounded text-[9px] font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 disabled:opacity-30">
                                {saving ? '...' : 'Save'}
                              </button>
                              <button onClick={() => { setEditingField(null); setFieldValue(''); }}
                                className="px-1.5 py-1 rounded text-[9px] text-nhi-ghost hover:text-nhi-dim">✕</button>
                            </div>
                          ) : (
                            <span className="text-[9px] text-nhi-ghost block mt-0.5">{a.fix}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Recommended section */}
              {posture.recommended.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                    <span className="text-[8px] font-bold uppercase tracking-widest text-amber-400">Recommended</span>
                  </div>
                  <div className="space-y-1">
                    {posture.recommended.map((a, i) => {
                      const isEditing = a.fixable && editingField === a.fixable;
                      return (
                        <div key={a.id} className="py-1.5 px-2 rounded" style={{ borderLeft: '2px solid #f59e0b', background: '#f59e0b06' }}>
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-medium text-amber-400">{a.issue}<CategoryPill category={a.category} /></span>
                            <div className="flex items-center gap-2">
                              <span className="text-[9px] font-mono" style={{ color: a.impact === 'Auto-resolves' ? '#22d3ee' : '#10b981' }}>{a.impact}</span>
                              {a.fixable && !isEditing && (
                                <button onClick={() => startEdit(a.fixable, '')}
                                  className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-accent hover:bg-accent/10 transition-colors">
                                  Fix →
                                </button>
                              )}
                            </div>
                          </div>
                          {isEditing ? (
                            <div className="flex gap-1.5 mt-1.5">
                              {a.fixable === 'environment' ? (
                                <select value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                                  className="flex-1 px-2 py-1.5 rounded text-[11px] bg-black/30 border border-white/[0.08] text-nhi-dim outline-none">
                                  <option value="">Select...</option>
                                  <option value="production">Production</option>
                                  <option value="staging">Staging</option>
                                  <option value="development">Development</option>
                                  <option value="testing">Testing</option>
                                </select>
                              ) : (
                                <input type="text" value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                                  placeholder="value" autoFocus onKeyDown={e => e.key === 'Enter' && saveField(a.fixable, fieldValue)}
                                  className="flex-1 px-2 py-1.5 rounded text-[11px] bg-black/30 border border-white/[0.08] text-nhi-dim placeholder-nhi-ghost outline-none" />
                              )}
                              <button onClick={() => saveField(a.fixable, fieldValue)} disabled={!fieldValue.trim() || saving}
                                className="px-2 py-1 rounded text-[9px] font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 disabled:opacity-30">
                                {saving ? '...' : 'Save'}
                              </button>
                              <button onClick={() => { setEditingField(null); setFieldValue(''); }}
                                className="px-1.5 py-1 rounded text-[9px] text-nhi-ghost hover:text-nhi-dim">✕</button>
                            </div>
                          ) : (
                            <span className="text-[9px] text-nhi-ghost block mt-0.5">{a.fix}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Optional upgrades section */}
              {posture.optional.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                    <span className="text-[8px] font-bold uppercase tracking-widest text-slate-400">Optional Upgrades</span>
                  </div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {posture.optional.map((o, i) => (
                      <div key={i} className="py-1.5 px-2 rounded bg-white/[0.02] border border-white/[0.04]">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span className="text-[7px] font-bold px-1 py-0 rounded"
                            style={{ color: TIER_COLORS_MAP[o.tier] || '#94a3b8', border: `1px solid ${(TIER_COLORS_MAP[o.tier] || '#94a3b8')}33`, background: `${(TIER_COLORS_MAP[o.tier] || '#94a3b8')}0d` }}>
                            T{o.tier}
                          </span>
                          <span className="text-[9px] font-semibold text-nhi-dim">{o.method}<CategoryPill category={o.category} /></span>
                        </div>
                        <span className="text-[8px] text-nhi-ghost block">{o.description}</span>
                        <span className="text-[8px] text-slate-400 font-medium block mt-0.5">⚡ {o.needs}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          {/* Manual Approval — handled in Col 3 review panel */}
        </div>

        {/* Col 3: Method Details (when inspecting) OR Manual Review Panel OR Labels */}
        <div className="min-w-0">
          {inspectIdx !== null && attest?.attestation_chain?.[inspectIdx] ? (
            <div className="p-3 rounded-lg bg-blue-500/[0.03] border border-blue-500/15">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <TierTag tier={attest.attestation_chain[inspectIdx].tier} />
                  <span className="text-[12px] font-bold text-blue-400">{attest.attestation_chain[inspectIdx].label}</span>
                </div>
                <button onClick={() => setInspectIdx(null)} className="text-[10px] text-nhi-ghost hover:text-nhi-dim px-1.5 py-0.5 rounded hover:bg-white/[0.06]">
                  <X className="w-3 h-3" />
                </button>
              </div>
              <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-1.5">Method Details</div>
              {attest.attestation_chain[inspectIdx].trust && (
                <div className="flex items-center gap-2 mb-2 py-1 px-2 rounded bg-white/[0.02]">
                  <span className="text-[10px] text-nhi-ghost">Trust Level:</span>
                  <TrustBadge level={attest.attestation_chain[inspectIdx].trust} />
                </div>
              )}
              {attest.attestation_chain[inspectIdx].claims && Object.keys(attest.attestation_chain[inspectIdx].claims).length > 0 ? (
                <div className="space-y-1">
                  <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-1">Claims / Attributes</div>
                  {Object.entries(attest.attestation_chain[inspectIdx].claims).map(([k, v]) => (
                    <div key={k} className="py-1 px-2 rounded bg-white/[0.02] border border-white/[0.03]">
                      <div className="text-[9px] text-nhi-ghost font-mono uppercase tracking-wider">{k}</div>
                      <div className="text-[11px] text-nhi-muted font-mono break-all">{typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-nhi-ghost">No claims available for this method.</p>
              )}
              {attest.attestation_chain[inspectIdx].evidence && (
                <div className="mt-2">
                  <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-1">Evidence</div>
                  <pre className="text-[10px] text-nhi-dim font-mono bg-black/30 p-2 rounded border border-white/[0.04] overflow-auto max-h-40 break-all whitespace-pre-wrap">
                    {JSON.stringify(attest.attestation_chain[inspectIdx].evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : attest?.requires_manual_review && trustLevel !== 'cryptographic' && trustLevel !== 'very-high' ? (
            <div className="p-3 rounded-lg bg-amber-500/[0.04] border border-amber-500/20">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-[13px] font-bold text-amber-400">Manual Review Required</span>
              </div>
              {attest.confidence?.reasons?.map((r, i) => (
                <p key={`r${i}`} className="text-[11px] text-nhi-muted mb-1">• {r}</p>
              ))}
              {attest.confidence?.missing?.length > 0 && (
                <div className="mt-2 mb-3">
                  <p className="text-[10px] text-amber-400/80 font-semibold mb-1">To enable auto-attestation:</p>
                  {attest.confidence.missing.map((m, i) => (
                    <p key={`m${i}`} className="text-[11px] text-nhi-ghost">→ {m}</p>
                  ))}
                </div>
              )}
              <div className="flex gap-2 mt-3">
                <button onClick={() => setManualOpen(true)}
                  className="flex-1 px-3 py-2 rounded text-[11px] font-bold bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/20 transition-colors flex items-center justify-center gap-1.5">
                  <Check className="w-3.5 h-3.5" /> Approve
                </button>
                <button onClick={runAttestation} disabled={attesting}
                  className="flex-1 px-3 py-2 rounded text-[11px] font-bold bg-blue-500/10 border border-blue-500/25 text-blue-400 hover:bg-blue-500/20 transition-colors flex items-center justify-center gap-1.5">
                  <RefreshCw className={`w-3.5 h-3.5 ${attesting ? 'animate-spin' : ''}`} /> Re-Attest
                </button>
              </div>
              {manualOpen && (
                <div className="mt-3 pt-3 border-t border-white/[0.06]">
                  <input type="text" placeholder="Your name" value={manualName} onChange={e => setManualName(e.target.value)}
                    className="w-full px-2 py-1.5 rounded text-[11px] bg-black/30 border border-white/[0.06] text-nhi-dim placeholder-nhi-ghost outline-none mb-1.5" />
                  <input type="text" placeholder="Reason for approval" value={manualReason} onChange={e => setManualReason(e.target.value)}
                    className="w-full px-2 py-1.5 rounded text-[11px] bg-black/30 border border-white/[0.06] text-nhi-dim placeholder-nhi-ghost outline-none mb-1.5" />
                  <div className="flex gap-1.5">
                    <button onClick={runManualApproval} disabled={!manualName || !manualReason}
                      className="px-3 py-1.5 rounded text-[10px] font-bold bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 disabled:opacity-30">Confirm Approval</button>
                    <button onClick={() => setManualOpen(false)} className="px-2.5 py-1 rounded text-[10px] text-nhi-ghost hover:text-nhi-dim">Cancel</button>
                  </div>
                </div>
              )}
              {/* Labels below review panel */}
              <div className="mt-3 pt-2 border-t border-white/[0.04]">
                <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-1">Labels</div>
                {w._labels ? (
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(w._labels).map(([k, v]) => (
                      <span key={k} className="inline-flex items-center gap-0.5 text-[10px] bg-white/[0.03] border border-white/[0.05] rounded px-1.5 py-0.5">
                        <span className="text-nhi-ghost">{k}:</span><span className="text-nhi-muted">{v}</span>
                      </span>
                    ))}
                  </div>
                ) : <span className="text-nhi-ghost text-[11px]">No labels</span>}
              </div>
            </div>
          ) : (
            <>
              <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-2">Labels</div>
              {w._labels ? (
                <div className="flex flex-wrap gap-1">
                  {Object.entries(w._labels).map(([k, v]) => (
                    <span key={k} className="inline-flex items-center gap-0.5 text-[10px] bg-white/[0.03] border border-white/[0.05] rounded px-1.5 py-0.5">
                      <span className="text-nhi-ghost">{k}:</span><span className="text-nhi-muted">{v}</span>
                    </span>
                  ))}
                </div>
              ) : <span className="text-nhi-ghost text-[11px]">No labels</span>}
              {attest?.attestation_chain && (w.metadata?.image || w.metadata?.handler || w._vendor || w._runtime) && (
                <div className="mt-2">
                  <div className="text-[10px] text-nhi-ghost uppercase tracking-widest font-bold mb-1">Infrastructure</div>
                  <div className="space-y-0.5 text-[11px]">
                    {w._vendor && <div className="text-nhi-ghost">{w._vendor}</div>}
                    {w._runtime && <div className="text-nhi-ghost font-mono">{w._runtime}</div>}
                    {w.metadata?.image && <div className="text-nhi-ghost font-mono truncate" title={w.metadata.image}>{w.metadata.image}</div>}
                    {w._ports && <div className="text-nhi-ghost font-mono">{w._ports.join(', ')}</div>}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Audit Log — collapsible attestation history */}
      <AuditLog workloadId={w.id} />

      </>)}
    </div>
  );
};

/* ════════════════════════════════════════════
   Main Component
   ════════════════════════════════════════════ */

const Workloads = () => {
  const navigate = useNavigate();
  const [workloads, setWorkloads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);


  const fetchWorkloads = async () => {
    try {
      const res = await fetch('/api/v1/workloads', { credentials: 'include' });
      const data = await res.json();
      setWorkloads(data.workloads || []);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch workloads:', err);
      toast.error('Failed to load workloads');
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWorkloads();
    const interval = setInterval(fetchWorkloads, 30000);
    return () => clearInterval(interval);
  }, []);

  const triggerDiscovery = async () => {
    setScanning(true);
    toast.loading('Scanning...', { id: 'scan' });
    try {
      await fetch('/api/v1/workloads/scan', { method: 'POST', credentials: 'include' });
      toast.loading('Scan complete — auto-attesting...', { id: 'scan' });
      // Wait for scan to finish writing to DB, then auto-attest
      await new Promise(r => setTimeout(r, 2000));
      const attestRes = await fetch('/api/v1/workloads/auto-attest', { method: 'POST', credentials: 'include' });
      const attestData = await attestRes.json();
      const msg = attestData.manual_review > 0
        ? `${attestData.attested} attested · ${attestData.manual_review} need manual review`
        : `${attestData.attested} identities attested`;
      toast.success(msg, { id: 'scan' });
      fetchWorkloads();
    } catch { toast.error('Scan failed', { id: 'scan' }); }
    finally { setScanning(false); }
  };

  const verifyWorkload = async (id) => {
    try {
      const res = await fetch(`/api/v1/workloads/${id}/verify`, { method: 'POST' });
      res.ok ? (toast.success('Verified!'), fetchWorkloads()) : toast.error('Failed');
    } catch { toast.error('Error'); }
  };

  // Enrich all workloads
  const enriched = workloads.map(enrichWorkload);

  // Coerce AI/MCP flags — DB may return string "true", "1", or integer 1
  enriched.forEach(w => {
    w.is_ai_agent = w.is_ai_agent === true || w.is_ai_agent === 'true' || w.is_ai_agent === 1 || w.is_ai_agent === '1';
    w.is_mcp_server = w.is_mcp_server === true || w.is_mcp_server === 'true' || w.is_mcp_server === 1 || w.is_mcp_server === '1';
    w.is_shadow = w.is_shadow === true || w.is_shadow === 'true' || w.is_shadow === 1 || w.is_shadow === '1';
    w.is_dormant = w.is_dormant === true || w.is_dormant === 'true' || w.is_dormant === 1 || w.is_dormant === '1';
    w.is_rogue = w.is_rogue === true || w.is_rogue === 'true' || w.is_rogue === 1 || w.is_rogue === '1';
    w.is_orphan = w.is_orphan === true || w.is_orphan === 'true' || w.is_orphan === 1 || w.is_orphan === '1';
    w.is_publicly_exposed = w.is_publicly_exposed === true || w.is_publicly_exposed === 'true' || w.is_publicly_exposed === 1 || w.is_publicly_exposed === '1';
    w.is_unused_iam = w.is_unused_iam === true || w.is_unused_iam === 'true' || w.is_unused_iam === 1 || w.is_unused_iam === '1';
  });

  // Filter
  const filtered = enriched.filter(w => {
    if (filter === 'verified' && !w.verified) return false;
    if (filter === 'federated' && w.discovered_by !== 'federation-discovery') return false;
    if (filter === 'shadow') { const _ad = (() => { if (!w.attestation_data) return null; if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } } return w.attestation_data; })(); const _c = classifyNHI(w, _ad); if (!_c || _c.classification !== 'SHADOW') return false; }
    if (filter === 'zombie' && !w.is_dormant) return false;
    if (filter === 'rogue' && !w.is_rogue) return false;
    if (filter === 'orphan' && !w.is_orphan) return false;
    if (filter === 'public' && !w.is_publicly_exposed) return false;
    if (filter === 'unused-iam' && !w.is_unused_iam) return false;
    if (filter === 'ai' && !w.is_ai_agent && !w.is_mcp_server) return false;
    if (filter === 'critical' && w._risk !== 'Critical' && w._risk !== 'High') return false;
    if (filter === 'credentials' && w.type !== 'credential') return false;
    if (filter === 'resources' && w.type !== 'external-resource') return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return [w.name, w.spiffe_id, w._category, w._subcategory, w.cloud_provider, w._owner, w._runtime, w._vendor, w.region]
        .some(field => field?.toLowerCase().includes(q));
    }
    return true;
  }).sort((a, b) => {
    // Sort: identities first → credentials → resources
    const bucketOrder = { identity: 0, credential: 1, resource: 2 };
    const aBucket = a.type === 'credential' ? 1 : a.type === 'external-resource' ? 2 : 0;
    const bBucket = b.type === 'credential' ? 1 : b.type === 'external-resource' ? 2 : 0;
    if (aBucket !== bBucket) return aBucket - bBucket;
    // Within identities: attested first, then by score desc
    if (a.verified !== b.verified) return a.verified ? -1 : 1;
    return (b.security_score || 0) - (a.security_score || 0);
  });

  const counts = {
    total: enriched.length,
    verified: enriched.filter(w => w.verified).length,
    federated: enriched.filter(w => w.discovered_by === 'federation-discovery').length,
    shadow: enriched.filter(w => { const _ad = (() => { if (!w.attestation_data) return null; if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } } return w.attestation_data; })(); const _c = classifyNHI(w, _ad); return _c?.classification === 'SHADOW'; }).length,
    zombie: enriched.filter(w => w.is_dormant).length,
    rogue: enriched.filter(w => w.is_rogue).length,
    orphan: enriched.filter(w => w.is_orphan).length,
    public: enriched.filter(w => w.is_publicly_exposed).length,
    'unused-iam': enriched.filter(w => w.is_unused_iam).length,
    ai: enriched.filter(w => w.is_ai_agent || w.is_mcp_server).length,
    credentials: enriched.filter(w => w.type === 'credential').length,
    resources: enriched.filter(w => w.type === 'external-resource').length,
    critical: enriched.filter(w => w._risk === 'Critical' || w._risk === 'High').length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 gap-3">
        <Loader className="w-5 h-5 text-accent animate-spin" />
        <span className="text-sm text-nhi-dim">Loading workloads...</span>
      </div>
    );
  }

  const COL_TEMPLATE = 'grid-cols-[2fr_1.2fr_0.8fr_0.8fr_0.8fr_0.7fr_0.5fr]';

  return (
    <div className="max-w-full">
      {/* Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6 stagger">
        <StatCard icon={Server} label="Total NHIs" value={counts.total} color="#7c6ff0" />
        <StatCard icon={ShieldCheck} label="Attested" value={counts.verified} color="#34d399" />
        <StatCard icon={AlertTriangle} label="At Risk" value={counts.critical} color="#ef4444" />
        <StatCard icon={Eye} label="Shadow" value={counts.shadow} color="#f97316" />
        <StatCard icon={Bot} label="AI / MCP" value={counts.ai} color="#a78bfa" />
      </div>

      {/* Actions */}
      <div className="nhi-card p-3 mb-4 flex items-center justify-between gap-4 animate-fadeIn">
        <div className="flex items-center gap-3 flex-1">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-nhi-faint" />
            <input type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search name, category, vendor, owner, runtime..."
              className="nhi-input pl-9 py-2" />
            {searchQuery && <button onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-white/[0.06] text-nhi-faint"><X className="w-3 h-3" /></button>}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-3.5 h-3.5 text-nhi-faint" />
            <FilterPill label="All" count={counts.total} active={filter === 'all'} onClick={() => setFilter('all')} />
            <FilterPill label="Attested" count={counts.verified} active={filter === 'verified'} onClick={() => setFilter('verified')} />
            <FilterPill label="Federated" count={counts.federated} active={filter === 'federated'} onClick={() => setFilter('federated')} />
            <FilterPill label="AI / MCP" count={counts.ai} active={filter === 'ai'} onClick={() => setFilter('ai')} />
            <FilterPill label="Credentials" count={counts.credentials} active={filter === 'credentials'} onClick={() => setFilter('credentials')} />
            <FilterPill label="Resources" count={counts.resources} active={filter === 'resources'} onClick={() => setFilter('resources')} />
            <FilterPill label="At Risk" count={counts.critical} active={filter === 'critical'} onClick={() => setFilter('critical')} />
            <div className="w-px h-4 bg-white/10" />
            <FilterPill label="Shadow" count={counts.shadow} active={filter === 'shadow'} onClick={() => setFilter('shadow')} />
            <FilterPill label="Zombie" count={counts.zombie} active={filter === 'zombie'} onClick={() => setFilter('zombie')} />
            <FilterPill label="Rogue" count={counts.rogue} active={filter === 'rogue'} onClick={() => setFilter('rogue')} />
            <FilterPill label="Orphan" count={counts.orphan} active={filter === 'orphan'} onClick={() => setFilter('orphan')} />
            <FilterPill label="Public" count={counts.public} active={filter === 'public'} onClick={() => setFilter('public')} />
            <FilterPill label="Unused IAM" count={counts['unused-iam']} active={filter === 'unused-iam'} onClick={() => setFilter('unused-iam')} />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchWorkloads} className="nhi-btn-ghost"><RefreshCw className="w-3.5 h-3.5" /><span>Refresh</span></button>
          <button onClick={async () => {
            toast.loading('Attesting all...', { id: 'attest-all' });
            try {
              const res = await fetch('/api/v1/workloads/attest-all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
              const data = await res.json();
              toast.success(`${data.attested || 0} attested`, { id: 'attest-all' });
              setTimeout(fetchWorkloads, 500);
            } catch { toast.error('Failed', { id: 'attest-all' }); }
          }} className="nhi-btn-ghost"><ShieldCheck className="w-3.5 h-3.5" /><span>Attest All</span></button>
          <button onClick={triggerDiscovery} disabled={scanning} className="nhi-btn-primary">
            {scanning ? <><Loader className="w-3.5 h-3.5 animate-spin" /><span>Scanning...</span></> : <><ScanSearch className="w-3.5 h-3.5" /><span>Scan</span></>}
          </button>
        </div>
      </div>

      {/* Shadow banner */}
      {counts.shadow > 0 && filter !== 'shadow' && (
        <div className="nhi-card mb-4 p-4 border-l-2 border-l-orange-400 animate-fadeIn">
          <div className="flex items-center gap-3">
            <span className="text-lg">👻</span>
            <div className="flex-1">
              <span className="text-sm font-semibold text-nhi-text">{counts.shadow} Shadow NHI{counts.shadow > 1 ? 's' : ''}</span>
              <span className="text-xs text-nhi-dim ml-2">— attested but ungoverned, highest risk category</span>
            </div>
            <button onClick={() => setFilter('shadow')} className="text-xs font-semibold text-orange-400 hover:text-orange-300 transition-colors">View all →</button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="nhi-card overflow-hidden animate-fadeIn" style={{ animationDelay: '0.1s' }}>
        <div className={`grid ${COL_TEMPLATE} gap-2 px-5 py-2.5 text-[10px] font-bold text-nhi-faint uppercase tracking-wider border-b border-white/[0.04]`}>
          <span>Identity</span>
          <span>Category</span>
          <span>Provider</span>
          <span>Risk / Score</span>
          <span>Trust</span>
          <span>Owner</span>
          <span>Status</span>
        </div>

        {filtered.length === 0 ? (
          <div className="text-center py-16">
            <Server className="w-10 h-10 text-nhi-ghost mx-auto mb-3" />
            <p className="text-sm text-nhi-dim">No workloads found</p>
          </div>
        ) : (
          filtered.map((w, i) => (
            <React.Fragment key={w.id || i}>
              <div
                onClick={() => setExpandedId(expandedId === w.id ? null : w.id)}
                className={`grid ${COL_TEMPLATE} gap-2 items-center px-5 h-[52px] border-b border-white/[0.02] hover:bg-accent/[0.03] transition-colors cursor-pointer group ${
                  expandedId === w.id ? 'bg-accent/[0.04]' : ''
                }`}
              >
                {/* Identity */}
                <div className="flex items-center gap-2 min-w-0">
                  <div className={`w-2 h-2 rounded-full shrink-0 ${
                    w._health === 'unhealthy' ? 'bg-red-400' :
                    w.is_rogue ? 'bg-red-400' :
                    w.is_dormant ? 'bg-gray-400' :
                    w.verified ? 'bg-emerald-400' :
                    w.is_shadow ? 'bg-orange-400' :
                    'bg-blue-400'
                  }`} title={w._health || (w.is_rogue ? 'rogue' : w.is_dormant ? 'zombie' : w.verified ? 'verified' : w.is_shadow ? 'shadow' : 'active')} />
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-semibold text-nhi-muted font-mono truncate group-hover:text-nhi-text transition-colors">{w.name}</span>
                      {(() => { const _ad = (() => { if (!w.attestation_data) return null; if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } } return w.attestation_data; })(); const _cls = classifyNHI(w, _ad); return _cls && _cls.classification !== 'TRUSTED' ? <span className="text-[9px] font-bold px-1 py-0 rounded" style={{ color: _cls.color, background: `${_cls.color}15` }}>{_cls.label}</span> : null; })()}
                      {w.is_dormant && <span className="text-[9px] font-bold text-gray-400 bg-gray-400/10 px-1 py-0 rounded">ZOMBIE</span>}
                      {w.is_orphan && <span className="text-[9px] font-bold text-purple-400 bg-purple-400/10 px-1 py-0 rounded">ORPHAN</span>}
                      {w.is_publicly_exposed && <span className="text-[9px] font-bold text-yellow-400 bg-yellow-400/10 px-1 py-0 rounded">PUBLIC</span>}
                      {w.is_unused_iam && <span className="text-[9px] font-bold text-purple-400 bg-purple-400/10 px-1 py-0 rounded">UNUSED</span>}
                      {w.type === 'credential' ? (
                        <span className="text-[9px] font-bold text-amber-400 bg-amber-400/10 px-1 py-0 rounded">🔑 CREDENTIAL</span>
                      ) : w.type === 'external-resource' ? (
                        <span className="text-[9px] font-bold text-cyan-400 bg-cyan-400/10 px-1 py-0 rounded">🔗 RESOURCE</span>
                      ) : w.discovered_by === 'federation-discovery' ? (
                        <span className="text-[9px] font-bold text-violet-400 bg-violet-400/10 px-1 py-0 rounded">FEDERATED</span>
                      ) : null}
                    </div>
                    <span className="text-[10px] text-nhi-faint truncate block">
                      {w.type === 'credential' || w.type === 'external-resource'
                        ? (() => { const m = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {}); return m.parent_identity ? `→ ${m.parent_identity}` : w.namespace; })()
                        : w.namespace}
                    </span>
                  </div>
                </div>

                {/* Category — ENRICHED */}
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="text-sm shrink-0">{w._categoryIcon}</span>
                  <div className="min-w-0">
                    <span className="text-[11px] text-nhi-muted font-medium block truncate">{w._category}</span>
                    {w._subcategory && w._subcategory !== w._category && (
                      <span className="text-[10px] text-nhi-faint block truncate">{w._subcategory}</span>
                    )}
                  </div>
                </div>

                {/* Provider + Env merged */}
                <div className="flex items-center gap-1.5">
                  <ProviderIcon provider={w.cloud_provider} />
                  <div className="min-w-0">
                    <span className="text-[10px] text-nhi-faint block">{w.region}</span>
                    <EnvBadge env={w.environment} />
                  </div>
                </div>

                {/* Risk */}
                {/* Risk — adjusted for attestation trust / resource verification */}
                {(() => {
                  if (w.type === 'external-resource') {
                    const rm = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
                    const vs = rm.verification_score;
                    const vStatus = rm.verification?.composite_status;
                    if (vs !== undefined && vs !== null) {
                      const vColor = vs >= 70 ? '#10b981' : vs >= 45 ? '#f59e0b' : '#ef4444';
                      const vLabel = vs >= 70 ? 'VERIFIED' : vs >= 45 ? 'PARTIAL' : 'UNVERIFIED';
                      return (
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ color: vColor, background: `${vColor}15`, border: `1px solid ${vColor}25` }}>{vLabel}</span>
                          <span className="text-[10px] font-medium" style={{ color: vColor }}>{vs}</span>
                        </div>
                      );
                    }
                    return <span className="text-[10px] text-nhi-ghost italic">Unverified</span>;
                  }
                  const ad = (() => { if (!w.attestation_data) return null; if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } } return w.attestation_data; })();
                  const effectiveTrust = ad?.trust_level || w.trust_level;
                  const adjustedRisk = effectiveTrust === 'cryptographic' ? 'LOW' : effectiveTrust === 'very-high' ? 'LOW' : effectiveTrust === 'high' ? 'MEDIUM' : w._risk;
                  const adjustedScore = ad ? (ad.correlated?.security_score || w.security_score) : w.security_score;
                  return <RiskBadge risk={adjustedRisk} score={adjustedScore} />;
                })()}

                {/* Trust — shows actual trust level badge + primary attestation method */}
                <div className="min-w-0">
                  {w.type === 'credential' || w.type === 'external-resource' ? (
                    <span className="text-[10px] text-nhi-ghost italic">N/A</span>
                  ) : (() => {
                    // Prefer attestation trust_level over DB value
                    const ad = (() => {
                      if (!w.attestation_data) return null;
                      if (typeof w.attestation_data === 'string') { try { return JSON.parse(w.attestation_data); } catch { return null; } }
                      return w.attestation_data;
                    })();
                    const effectiveTrust = ad?.trust_level || w.trust_level;
                    return effectiveTrust && effectiveTrust !== 'none' ? (
                    <div>
                      <TrustBadge level={effectiveTrust} />
                      {w.verification_method && (
                        <span className="text-[10px] text-nhi-dim block mt-0.5 truncate" title={w.verification_method}>
                          {w.verification_method.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()).replace('Aws ', 'AWS ').replace('Abac ', 'ABAC ').replace('Sts ', 'STS ')}
                        </span>
                      )}
                    </div>
                  ) : (
                    <TrustDots level={w._trust} />
                  );
                  })()}
                </div>

                {/* Owner — show parent identity for credentials/resources */}
                <div className="flex items-center gap-1 min-w-0">
                  {(() => {
                    if (w.type === 'credential' || w.type === 'external-resource') {
                      const m = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
                      return m.parent_identity ? (
                        <span className="text-[10px] text-violet-400 truncate" title={`Used by ${m.parent_identity}`}>↗ {m.parent_identity}</span>
                      ) : m.provider ? (
                        <span className="text-[10px] text-nhi-dim truncate">{m.provider}</span>
                      ) : (
                        <span className="text-[10px] text-nhi-ghost italic">Unlinked</span>
                      );
                    }
                    return w._owner ? (
                    <>
                      <User className="w-3 h-3 text-nhi-faint shrink-0" />
                      <span className="text-[10px] text-nhi-dim truncate" title={w._owner}>{w._owner.split('@')[0]}</span>
                    </>
                  ) : (
                    <span className="text-[10px] text-red-400/70 font-medium">No owner</span>
                  );
                  })()}
                </div>

                {/* Status — compact single-line */}
                <div className="flex items-center gap-1.5 min-w-0">
                  {(() => {
                    // Credential/resource specific status
                    if (w.type === 'credential') {
                      const m = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
                      const riskLevel = m.risk_level || 'medium';
                      const riskColors = { low: 'text-emerald-400', medium: 'text-amber-400', high: 'text-red-400', critical: 'text-red-500' };
                      return <span className={`text-[10px] font-bold ${riskColors[riskLevel] || riskColors.medium}`}>{(m.lifecycle_status || 'Active').replace(/^\w/, c => c.toUpperCase())}</span>;
                    }
                    if (w.type === 'external-resource') {
                      const rm = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
                      const vs = rm.verification?.composite_status;
                      if (vs === 'verified') return <span className="text-[10px] font-bold text-emerald-400">Verified</span>;
                      if (vs === 'partially-verified') return <span className="text-[10px] font-bold text-amber-400">Partial</span>;
                      if (vs === 'unverified') return <span className="text-[10px] font-bold text-red-400">Unverified</span>;
                      return <span className="text-[10px] font-medium text-nhi-ghost">Pending</span>;
                    }

                    const ad = (() => {
                      if (!w.attestation_data) return null;
                      if (typeof w.attestation_data === 'string') {
                        try { return JSON.parse(w.attestation_data); } catch { return null; }
                      }
                      return w.attestation_data;
                    })();

                    if (ad?.requires_manual_review) {
                      return (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-amber-400">
                          Manual Review
                        </span>
                      );
                    }
                    if (w.verified) {
                      return (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400">
                          Attested
                        </span>
                      );
                    }
                    if (w.is_shadow) return <span className="text-[10px] font-bold text-orange-400">Shadow</span>;
                    return <span className="text-[10px] font-medium text-nhi-dim">Discovered</span>;
                  })()}
                  <button onClick={(e) => { e.stopPropagation(); navigate(`/graph?focus=${encodeURIComponent(w.name)}`); }}
                    className="w-5 h-5 flex items-center justify-center rounded opacity-0 group-hover:opacity-100 hover:bg-white/[0.08] transition-all"
                    title="View in Graph">
                    <GitBranch className="w-3 h-3 text-nhi-ghost hover:text-cyan-400" />
                  </button>
                  {expandedId === w.id
                    ? <ChevronUp className="w-3 h-3 text-nhi-faint" />
                    : <ChevronDown className="w-3 h-3 text-nhi-ghost opacity-0 group-hover:opacity-100 transition-opacity" />}
                </div>
              </div>

              {/* Expanded detail */}
              {expandedId === w.id && <DetailPanel w={w} onRefresh={fetchWorkloads} navigate={navigate} />}
            </React.Fragment>
          ))
        )}

        {filtered.length > 0 && (
          <div className="px-5 py-3 border-t border-white/[0.04] flex items-center justify-between">
            <span className="text-[11px] text-nhi-faint">
              Showing {filtered.length} of {workloads.length} identit{workloads.length !== 1 ? 'ies' : 'y'}
              {filter !== 'all' && <span className="text-accent ml-1">· {filter}</span>}
            </span>
            <span className="text-[11px] text-nhi-faint font-mono">Click row for details · Auto-refresh: 30s</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default Workloads;