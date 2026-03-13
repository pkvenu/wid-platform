import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Shield, Plus, Trash2, Play, Check, X, AlertTriangle, Clock,
  ChevronDown, ChevronUp, ToggleLeft, ToggleRight, FileText,
  Copy, Zap, Eye, Edit2, Search, RefreshCw, Loader,
  BookOpen, Code, CheckCircle, XCircle, ArrowRight,
} from 'lucide-react';
import toast from 'react-hot-toast';

const API = (typeof __API_BASE__ !== 'undefined' && window.location.hostname !== 'localhost') ? (__API_BASE__ + '/api/v1') : '/api/v1';

// ── Color maps ──
const SEV = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-400' },
  high:     { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-400' },
  medium:   { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400' },
  low:      { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400' },
  info:     { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-400' },
};
const TICON = { enforcement: '🛡', compliance: '📋', lifecycle: '⏰', access: '🔑', ai_agent: '🤖', conditional_access: '🔐' };
const COMPLIANCE_COLORS = {
  SOC2:        { bg: 'bg-indigo-500/10', border: 'border-indigo-500/20', text: 'text-indigo-400', label: 'SOC2' },
  PCI_DSS:     { bg: 'bg-pink-500/10',   border: 'border-pink-500/20',  text: 'text-pink-400',   label: 'PCI' },
  NIST_800_53: { bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20',  text: 'text-cyan-400',   label: 'NIST' },
  ISO_27001:   { bg: 'bg-teal-500/10',   border: 'border-teal-500/20',  text: 'text-teal-400',   label: 'ISO' },
  EU_AI_ACT:   { bg: 'bg-violet-500/10', border: 'border-violet-500/20',text: 'text-violet-400', label: 'EU AI' },
};

// ── Field / operator schema ──
const FIELDS = [
  { key: 'trust_level',    label: 'Trust Level',    type: 'select', options: ['cryptographic','very-high','high','medium','low','none'] },
  { key: 'security_score', label: 'Security Score',  type: 'number' },
  { key: 'environment',    label: 'Environment',     type: 'select', options: ['production','staging','development','testing','unknown'] },
  { key: 'type',           label: 'Identity Type',   type: 'select', options: ['lambda','container','iam-role','iam-user','service-account','api-key','secret','secret-engine'] },
  { key: 'cloud_provider', label: 'Cloud Provider',  type: 'select', options: ['aws','gcp','azure','docker','kubernetes','vault','github'] },
  { key: 'verified',       label: 'Attested',        type: 'boolean' },
  { key: 'is_shadow',      label: 'Is Shadow',       type: 'boolean' },
  { key: 'owner',          label: 'Has Owner',       type: 'existence' },
  { key: 'team',           label: 'Has Team',        type: 'existence' },
  { key: 'spiffe_id',      label: 'Has SPIFFE ID',   type: 'existence' },
  { key: 'name',           label: 'Identity Name',   type: 'string' },
  { key: 'category',       label: 'Category',        type: 'string' },
  { key: 'last_seen',      label: 'Last Seen',       type: 'date' },
];
const OPS = {
  string:    [{ v:'equals',l:'equals' },{ v:'not_equals',l:'not equals' },{ v:'contains',l:'contains' },{ v:'starts_with',l:'starts with' },{ v:'matches',l:'regex' },{ v:'in',l:'in list' }],
  number:    [{ v:'gt',l:'>' },{ v:'gte',l:'>=' },{ v:'lt',l:'<' },{ v:'lte',l:'<=' },{ v:'equals',l:'=' },{ v:'between',l:'between' }],
  select:    [{ v:'equals',l:'is' },{ v:'not_equals',l:'is not' },{ v:'in',l:'one of' },{ v:'not_in',l:'not one of' }],
  boolean:   [{ v:'is_true',l:'is true' },{ v:'is_false',l:'is false' }],
  existence: [{ v:'exists',l:'exists' },{ v:'not_exists',l:'missing' }],
  date:      [{ v:'older_than_days',l:'older than (days)' },{ v:'newer_than_days',l:'newer than (days)' },{ v:'exists',l:'exists' },{ v:'not_exists',l:'missing' }],
};
const ACTIONS = [
  { key:'flag', label:'Flag violation' },{ key:'block_deploy', label:'Block deployment' },
  { key:'require_attest', label:'Require re-attestation' },{ key:'revoke_access', label:'Revoke access' },
  { key:'notify', label:'Notify owner/team' },{ key:'quarantine', label:'Quarantine' },
];

// ── Shared classes ──
const inp = "w-full px-2.5 py-1.5 rounded text-[12px] bg-black/30 border border-white/[0.08] text-nhi-muted placeholder-nhi-ghost outline-none focus:border-accent/40";
const sel = "px-2.5 py-1.5 rounded text-[12px] bg-black/30 border border-white/[0.08] text-nhi-muted outline-none focus:border-accent/40";
const btnP = "px-3 py-1.5 rounded text-[11px] font-bold bg-accent/15 border border-accent/25 text-accent hover:bg-accent/25 transition-colors flex items-center gap-1.5 disabled:opacity-40";
const btnD = "px-3 py-1.5 rounded text-[11px] font-bold bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors flex items-center gap-1.5";
const btnG = "px-3 py-1.5 rounded text-[11px] font-semibold text-nhi-muted hover:bg-white/[0.04] transition-colors flex items-center gap-1.5";

// ══════════════════════════════════════════════════════════════
// Condition Row
// ══════════════════════════════════════════════════════════════
const ConditionRow = ({ condition, index, onChange, onRemove, canRemove }) => {
  const fDef = FIELDS.find(f => f.key === condition.field) || FIELDS[0];
  const ops = OPS[fDef.type] || OPS.string;
  const needsVal = !['is_true','is_false','exists','not_exists'].includes(condition.operator);
  return (
    <div className="flex items-center gap-2 group">
      <span className="w-5 h-5 rounded-full bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-[10px] text-nhi-muted font-bold shrink-0">{index+1}</span>
      <select value={condition.field} onChange={e => {
        const f = FIELDS.find(fi => fi.key === e.target.value) || FIELDS[0];
        onChange({ field: e.target.value, operator: (OPS[f.type]||OPS.string)[0].v, value: '' });
      }} className={`${sel} w-36`}>
        {FIELDS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
      </select>
      <select value={condition.operator} onChange={e => onChange({ operator: e.target.value })} className={`${sel} w-32`}>
        {ops.map(o => <option key={o.v} value={o.v}>{o.l}</option>)}
      </select>
      {needsVal && (fDef.options
        ? <select value={condition.value} onChange={e => onChange({ value: e.target.value })} className={`${sel} flex-1`}>
            <option value="">Select...</option>
            {fDef.options.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        : <input type={fDef.type === 'number' ? 'number' : 'text'} value={condition.value||''} onChange={e => onChange({ value: e.target.value })}
            placeholder={fDef.type === 'date' ? 'days' : 'value...'} className={`${inp} flex-1`} />
      )}
      {!needsVal && <div className="flex-1" />}
      {canRemove && <button onClick={onRemove} className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-red-500/10 text-red-400/60 hover:text-red-400 transition-all"><Trash2 className="w-3.5 h-3.5" /></button>}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Policy Editor (Create + Edit)
// ══════════════════════════════════════════════════════════════
const PolicyEditor = ({ initial, onSave, onCancel }) => {
  const [p, setP] = useState(() => {
    if (initial) {
      const conds = typeof initial.conditions === 'string' ? JSON.parse(initial.conditions) : (initial.conditions || []);
      const acts = typeof initial.actions === 'string' ? JSON.parse(initial.actions) : (initial.actions || []);
      return { ...initial, conditions: conds.length ? conds : [{ field:'environment', operator:'equals', value:'' }], actions: acts.length ? acts : [{ type:'flag', message:'' }] };
    }
    return { name:'', description:'', policy_type:'enforcement', severity:'medium', conditions:[{ field:'environment', operator:'equals', value:'' }], actions:[{ type:'flag', message:'' }], enforcement_mode:'audit', scope_environment:'' };
  });
  const [testing, setTesting] = useState(false);
  const [testRes, setTestRes] = useState(null);
  const [showRego, setShowRego] = useState(false);
  const [rego, setRego] = useState('');
  const [saving, setSaving] = useState(false);

  const updCond = (i, u) => { const n = [...p.conditions]; n[i] = { ...n[i], ...u }; setP(s => ({ ...s, conditions: n })); };
  const addCond = () => setP(s => ({ ...s, conditions: [...s.conditions, { field:'environment', operator:'equals', value:'' }] }));
  const rmCond = (i) => setP(s => ({ ...s, conditions: s.conditions.filter((_,j) => j !== i) }));
  const updAct = (i, u) => { const n = [...p.actions]; n[i] = { ...n[i], ...u }; setP(s => ({ ...s, actions: n })); };
  const addAct = () => setP(s => ({ ...s, actions: [...s.actions, { type:'flag', message:'' }] }));
  const rmAct = (i) => setP(s => ({ ...s, actions: s.actions.filter((_,j) => j !== i) }));

  const runTest = async () => {
    setTesting(true); setTestRes(null);
    try {
      const r = await fetch(`${API}/policies/test`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ conditions: p.conditions, scope_environment: p.scope_environment || undefined, actions: p.actions, severity: p.severity }) });
      const d = await r.json(); setTestRes(d); setRego(d.rego_preview || '');
      toast.success(`${d.violations} violation${d.violations !== 1 ? 's' : ''} found`);
    } catch { toast.error('Test failed'); } finally { setTesting(false); }
  };

  const previewRego = async () => {
    try {
      const r = await fetch(`${API}/policies/rego-preview`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(p) });
      const d = await r.json(); setRego(d.rego || ''); setShowRego(true);
    } catch { toast.error('Rego generation failed'); }
  };

  const save = async () => {
    if (!p.name.trim()) { toast.error('Name required'); return; }
    if (!p.conditions.length) { toast.error('Add a condition'); return; }
    setSaving(true);
    try { await onSave(p); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="grid grid-cols-2 gap-3">
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Name</label>
          <input value={p.name} onChange={e => setP(s => ({...s, name:e.target.value}))} placeholder="e.g. Production Attestation Required" className={inp} /></div>
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Description</label>
          <input value={p.description} onChange={e => setP(s => ({...s, description:e.target.value}))} placeholder="What this policy enforces..." className={inp} /></div>
      </div>
      <div className="grid grid-cols-4 gap-3">
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Type</label>
          <select value={p.policy_type} onChange={e => setP(s => ({...s, policy_type:e.target.value}))} className={`${sel} w-full`}>
            <option value="enforcement">🛡 Enforcement</option><option value="compliance">📋 Compliance</option>
            <option value="lifecycle">⏰ Lifecycle</option><option value="access">🔑 Access</option></select></div>
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Severity</label>
          <select value={p.severity} onChange={e => setP(s => ({...s, severity:e.target.value}))} className={`${sel} w-full`}>
            {['critical','high','medium','low','info'].map(s => <option key={s} value={s}>{s}</option>)}</select></div>
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Mode</label>
          <select value={p.enforcement_mode} onChange={e => setP(s => ({...s, enforcement_mode:e.target.value}))} className={`${sel} w-full`}>
            <option value="audit">Audit</option><option value="enforce">Enforce</option><option value="disabled">Disabled</option></select></div>
        <div><label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold block mb-1">Scope</label>
          <select value={p.scope_environment||''} onChange={e => setP(s => ({...s, scope_environment: e.target.value||null}))} className={`${sel} w-full`}>
            <option value="">All envs</option>{['production','staging','development'].map(e => <option key={e} value={e}>{e}</option>)}</select></div>
      </div>

      {/* Conditions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold">Conditions <span className="text-nhi-faint">(all must match)</span></label>
          <button onClick={addCond} className={btnG}><Plus className="w-3 h-3" /> Add</button>
        </div>
        <div className="space-y-2 p-3 rounded-lg bg-white/[0.015] border border-white/[0.04]">
          {p.conditions.map((c,i) => (
            <React.Fragment key={i}>
              {i > 0 && <div className="text-[10px] text-accent font-bold pl-7">AND</div>}
              <ConditionRow condition={c} index={i} onChange={u => updCond(i,u)} onRemove={() => rmCond(i)} canRemove={p.conditions.length > 1} />
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold">Actions <span className="text-nhi-faint">(on violation)</span></label>
          <button onClick={addAct} className={btnG}><Plus className="w-3 h-3" /> Add</button>
        </div>
        <div className="space-y-2 p-3 rounded-lg bg-white/[0.015] border border-white/[0.04]">
          {p.actions.map((a,i) => (
            <div key={i} className="flex items-center gap-2 group">
              <select value={a.type} onChange={e => updAct(i, {type:e.target.value})} className={`${sel} w-44`}>
                {ACTIONS.map(o => <option key={o.key} value={o.key}>{o.label}</option>)}</select>
              <input value={a.message||''} onChange={e => updAct(i, {message:e.target.value})} placeholder="Message..." className={`${inp} flex-1`} />
              {p.actions.length > 1 && <button onClick={() => rmAct(i)} className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-red-500/10 text-red-400/60 hover:text-red-400 transition-all"><Trash2 className="w-3.5 h-3.5" /></button>}
            </div>
          ))}
        </div>
      </div>

      {/* Test Results */}
      {testRes && (
        <div className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-nhi-muted">Dry-Run Results</span>
            <span className={`text-[11px] font-bold ${testRes.violations > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {testRes.violations} of {testRes.evaluated} would violate
            </span>
          </div>
          {testRes.violations === 0 && <div className="flex items-center gap-1.5 text-[11px] text-emerald-400"><CheckCircle className="w-3.5 h-3.5" /> All workloads pass this policy</div>}
          {testRes.results?.slice(0, 10).map((r, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] py-0.5">
              <XCircle className="w-3 h-3 text-red-400 shrink-0" />
              <span className="text-nhi-muted font-mono text-[10px]">{r.workload_name}</span>
              <span className="text-nhi-muted truncate">{r.message}</span>
            </div>
          ))}
          {(testRes.results?.length || 0) > 10 && <div className="text-[10px] text-nhi-faint mt-1">+{testRes.results.length - 10} more</div>}
        </div>
      )}

      {/* Rego */}
      {showRego && rego && (
        <div className="p-3 rounded-lg bg-black/40 border border-white/[0.06]">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold">OPA Rego</span>
            <button onClick={() => { navigator.clipboard.writeText(rego); toast.success('Copied'); }} className={btnG}><Copy className="w-3 h-3" /> Copy</button>
          </div>
          <pre className="text-[11px] text-emerald-400/80 font-mono whitespace-pre-wrap leading-relaxed">{rego}</pre>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex items-center justify-between pt-2 border-t border-white/[0.04]">
        <div className="flex gap-2">
          <button onClick={runTest} disabled={testing || !p.conditions.length} className={btnP}>
            {testing ? <Loader className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            {testing ? 'Testing...' : 'Test Policy'}
          </button>
          <button onClick={previewRego} className={btnG}><Code className="w-3 h-3" /> Rego</button>
        </div>
        <div className="flex gap-2">
          <button onClick={onCancel} className={btnG}>Cancel</button>
          <button onClick={save} disabled={saving} className={btnP}>
            {saving ? <Loader className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
            {initial?.id ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Template Gallery
// ══════════════════════════════════════════════════════════════
const FILTER_TABS = [
  { key: 'all',        label: 'All',        icon: '📋' },
  { key: 'agent',      label: 'AI Agent',   icon: '🤖' },
  { key: 'mcp',        label: 'MCP Server', icon: '🔌' },
  { key: 'breach',     label: 'Breach-Based', icon: '🚨' },
  { key: 'access',     label: 'Access',     icon: '🔑' },
  { key: 'allow',      label: 'Allow',      icon: '✅' },
  { key: 'deny',       label: 'Deny',       icon: '🚫' },
  { key: 'compliance', label: 'Compliance', icon: '📋' },
  { key: 'credential', label: 'Credential', icon: '🗝️' },
];

const TAG_COLORS = {
  breach: { bg: '#ef444415', text: '#ef4444', border: '#ef444430' },
  agent: { bg: '#8b5cf615', text: '#8b5cf6', border: '#8b5cf630' },
  mcp: { bg: '#06b6d415', text: '#06b6d4', border: '#06b6d430' },
  allow: { bg: '#10b98115', text: '#10b981', border: '#10b98130' },
  deny: { bg: '#ef444415', text: '#ef4444', border: '#ef444430' },
  'prompt-injection': { bg: '#f9731615', text: '#f97316', border: '#f9731630' },
  'rce': { bg: '#ef444415', text: '#ef4444', border: '#ef444430' },
  'sql-injection': { bg: '#f5990b15', text: '#f59e0b', border: '#f59e0b30' },
  oauth: { bg: '#3b82f615', text: '#3b82f6', border: '#3b82f630' },
};

const TemplateGallery = ({ onUse, onClose }) => {
  const [templates, setTemplates] = useState([]);
  const [deploying, setDeploying] = useState(null);
  const [activeFilter, setActiveFilter] = useState('all');
  const [searchQ, setSearchQ] = useState('');
  useEffect(() => { fetch(`${API}/policies/templates`).then(r => r.json()).then(d => setTemplates(d.templates||[])).catch(() => {}); }, []);

  const deploy = async (tpl) => {
    setDeploying(tpl.id);
    try {
      const r = await fetch(`${API}/policies/from-template/${tpl.id}`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({}) });
      if (r.status === 409) { toast.error('Already exists'); return; }
      const d = await r.json();
      toast.success(`Created: ${d.name}`);
      onUse(d);
    } catch { toast.error('Failed'); } finally { setDeploying(null); }
  };

  // Filter templates
  const filtered = templates.filter(t => {
    const tags = t.tags || [];
    const matchFilter = activeFilter === 'all' || tags.includes(activeFilter) || t.policy_type === activeFilter;
    const matchSearch = !searchQ || t.name?.toLowerCase().includes(searchQ.toLowerCase()) || t.description?.toLowerCase().includes(searchQ.toLowerCase()) || tags.some(tg => tg.includes(searchQ.toLowerCase()));
    return matchFilter && matchSearch;
  });

  // Count per filter
  const counts = {};
  for (const f of FILTER_TABS) {
    counts[f.key] = f.key === 'all' ? templates.length : templates.filter(t => (t.tags || []).includes(f.key) || t.policy_type === f.key).length;
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-[14px] font-bold text-nhi-text">Policy Templates</h3>
          <p className="text-[11px] text-nhi-muted">
            {filtered.length} template{filtered.length !== 1 ? 's' : ''}
            {activeFilter !== 'all' && ` matching "${FILTER_TABS.find(f => f.key === activeFilter)?.label}"`}
            {searchQ && ` · search: "${searchQ}"`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 text-nhi-faint absolute left-2 top-1/2 -translate-y-1/2" />
            <input type="text" placeholder="Search templates..." value={searchQ} onChange={e => setSearchQ(e.target.value)}
              className="text-[10px] pl-6 pr-2 py-1.5 rounded-lg bg-surface-3 border border-[var(--border)] text-nhi-text placeholder-nhi-ghost w-44 focus:outline-none focus:border-accent/30" />
            {searchQ && <button onClick={() => setSearchQ('')} className="absolute right-1.5 top-1/2 -translate-y-1/2"><X className="w-2.5 h-2.5 text-nhi-faint" /></button>}
          </div>
          <button onClick={onClose} className={btnG}><X className="w-3 h-3" /> Close</button>
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex flex-wrap gap-1.5 mb-4">
        {FILTER_TABS.map(f => (
          <button key={f.key} onClick={() => setActiveFilter(f.key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-semibold border transition-all ${activeFilter === f.key ? 'border-accent/40 bg-accent/10 text-accent' : 'border-[var(--border)] bg-surface-3 text-nhi-faint hover:text-nhi-muted hover:border-accent/20'}`}>
            <span className="text-[11px]">{f.icon}</span>
            {f.label}
            {counts[f.key] > 0 && (
              <span className={`text-[8px] font-bold px-1.5 rounded-full ${activeFilter === f.key ? 'bg-accent/20 text-accent' : 'bg-surface-2 text-nhi-ghost'}`}>
                {counts[f.key]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Templates grid */}
      {filtered.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-[12px] text-nhi-faint">No templates match this filter</p>
          <button onClick={() => { setActiveFilter('all'); setSearchQ(''); }} className="text-[10px] text-accent mt-2 hover:underline">Clear filters</button>
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          {filtered.map(t => {
            const s = SEV[t.severity] || SEV.medium;
            const tags = t.tags || [];
            const isBreach = tags.includes('breach');
            const isAllow = t.effect === 'allow' || tags.includes('allow');
            const isDeny = t.effect === 'deny' || tags.includes('deny');
            return (
              <div key={t.id} className={`p-3 rounded-lg border transition-all hover:border-accent/20 ${isBreach ? 'bg-red-500/[0.03] border-red-500/10' : isAllow ? 'bg-emerald-500/[0.02] border-emerald-500/10' : isDeny ? 'bg-red-500/[0.02] border-red-500/10' : 'bg-white/[0.015] border-white/[0.04]'}`}>
                <div className="flex items-start justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[13px]">{TICON[t.policy_type]||'📋'}</span>
                    {isBreach && <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">🚨 Breach</span>}
                    {isAllow && !isBreach && <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Allow</span>}
                    {isDeny && !isBreach && <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">Deny</span>}
                  </div>
                  <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${s.bg} ${s.border} ${s.text} border`}>{t.severity}</span>
                </div>
                <div className="text-[12px] font-semibold text-nhi-muted mb-1">{t.name}</div>
                <div className="text-[10px] text-nhi-muted mb-2 line-clamp-2">{t.description}</div>
                {/* Tags */}
                <div className="flex flex-wrap gap-1 mb-2">
                  {tags.slice(0, 5).map(tg => {
                    const tc = TAG_COLORS[tg] || { bg: 'rgba(148,163,184,0.08)', text: '#94a3b8', border: 'rgba(148,163,184,0.15)' };
                    return (
                      <span key={tg} className="text-[8px] font-semibold px-1.5 py-0.5 rounded border cursor-pointer hover:opacity-80 transition-opacity"
                        style={{ background: tc.bg, color: tc.text, borderColor: tc.border }}
                        onClick={(e) => { e.stopPropagation(); setActiveFilter(tg); }}>
                        {tg}
                      </span>
                    );
                  })}
                  {tags.length > 5 && <span className="text-[8px] text-nhi-ghost">+{tags.length - 5}</span>}
                </div>
                <div className="text-[10px] text-nhi-faint mb-2">
                  {t.conditions?.length} condition{t.conditions?.length !== 1 ? 's' : ''} · {t.actions?.length} action{t.actions?.length !== 1 ? 's' : ''}
                </div>
                <div className="flex gap-1.5">
                  <button onClick={() => deploy(t)} disabled={deploying === t.id} className={`${btnP} flex-1 justify-center`}>
                    {deploying === t.id ? <Loader className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />} Deploy
                  </button>
                  <button onClick={() => onUse({ ...t, _customize: true })} className={`${btnG} flex-1 justify-center`}>
                    <Edit2 className="w-3 h-3" /> Customize
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Compliance Framework Badges
// ══════════════════════════════════════════════════════════════
const ComplianceBadges = ({ frameworks }) => {
  const parsed = typeof frameworks === 'string' ? (() => { try { return JSON.parse(frameworks); } catch { return []; } })() : (frameworks || []);
  if (!parsed.length) return null;
  const show = parsed.slice(0, 3);
  const overflow = parsed.length - 3;
  return (
    <div className="flex items-center gap-1">
      {show.map(cf => {
        const c = COMPLIANCE_COLORS[cf.framework];
        if (!c) return null;
        return (
          <span key={cf.framework}
            className={`text-[8px] font-bold uppercase px-1.5 py-0.5 rounded border ${c.bg} ${c.border} ${c.text}`}
            title={`${cf.framework}: ${(cf.controls || []).join(', ')}`}>
            {c.label}
          </span>
        );
      })}
      {overflow > 0 && <span className="text-[8px] text-nhi-faint">+{overflow}</span>}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Policy Row (List Item)
// ══════════════════════════════════════════════════════════════
const PolicyRow = ({ policy, onEdit, onDelete, onToggle, onEval }) => {
  const s = SEV[policy.severity] || SEV.medium;
  const [evaling, setEvaling] = useState(false);
  const [evalRes, setEvalRes] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const [modeChanging, setModeChanging] = useState(false);
  const [showConfirm, setShowConfirm] = useState(null); // 'enforce' | 'audit' | null

  const conds = typeof policy.conditions === 'string' ? JSON.parse(policy.conditions) : (policy.conditions || []);
  const acts = typeof policy.actions === 'string' ? JSON.parse(policy.actions) : (policy.actions || []);
  const isAudit = policy.enforcement_mode === 'audit';
  const isEnforce = policy.enforcement_mode === 'enforce';

  const runEval = async () => {
    setEvaling(true);
    try {
      const r = await fetch(`${API}/policies/${policy.id}/evaluate`, { method:'POST' });
      const d = await r.json(); setEvalRes(d); setExpanded(true);
      toast.success(`${d.violations} violation${d.violations !== 1 ? 's' : ''}`);
      if (onEval) onEval();
    } catch { toast.error('Eval failed'); } finally { setEvaling(false); }
  };

  const changeMode = async (newMode) => {
    setModeChanging(true);
    try {
      const r = await fetch(`${API}/policies/${policy.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforcement_mode: newMode }),
      });
      if (r.ok) {
        policy.enforcement_mode = newMode;
        toast.success(`Mode → ${newMode}`);
        if (onEval) onEval();
      }
    } catch { toast.error('Mode change failed'); }
    setModeChanging(false); setShowConfirm(null);
  };

  return (
    <div className={`border rounded-lg transition-all ${
      isEnforce ? 'border-emerald-500/15 bg-emerald-500/[0.02]'
      : isAudit ? 'border-amber-500/15 bg-amber-500/[0.02]'
      : 'border-white/[0.04] bg-white/[0.01]'
    }`}>
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        {/* Mode indicator dot */}
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
          isEnforce ? 'bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.4)]'
          : isAudit ? 'bg-amber-400 shadow-[0_0_6px_rgba(245,158,11,0.3)]'
          : 'bg-white/10'
        }`} />

        <span className="text-[14px]">{TICON[policy.policy_type]||'📋'}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-nhi-text truncate">{policy.name}</span>
            {!policy.enabled && <span className="text-[9px] font-bold text-nhi-faint bg-white/[0.04] px-1.5 py-0.5 rounded uppercase">disabled</span>}
          </div>
          {policy.description && <div className="text-[11px] text-nhi-muted truncate mt-0.5">{policy.description}</div>}
        </div>

        {/* Severity badge */}
        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${s.bg} ${s.border} ${s.text}`}>{policy.severity}</span>

        {/* Enforcement mode badge — clickable */}
        <button onClick={e => { e.stopPropagation(); setShowConfirm(isEnforce ? 'audit' : 'enforce'); }}
          disabled={modeChanging}
          className={`text-[10px] font-bold px-2.5 py-1 rounded-full flex items-center gap-1.5 transition-colors ${
            isEnforce ? 'bg-emerald-500/12 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20'
            : isAudit ? 'bg-amber-500/12 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20'
            : 'bg-white/[0.04] text-nhi-faint border border-white/[0.06]'
          }`} title={`Click to switch to ${isEnforce ? 'audit' : 'enforce'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${isEnforce ? 'bg-emerald-400' : isAudit ? 'bg-amber-400' : 'bg-white/20'}`} />
          {modeChanging ? '...' : isEnforce ? 'ENFORCING' : isAudit ? 'AUDIT' : policy.enforcement_mode}
        </button>

        {/* Workload scope badge */}
        {policy.client_workload_id && (
          <span className="text-[9px] font-semibold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-2 py-0.5 rounded-full"
            title={`Scoped to workload: ${policy.attack_path_id || policy.client_workload_id}`}>
            Scoped: {policy.name?.match(/\[(.+)\]/)?.[1] || 'workload'}
          </span>
        )}

        {/* Compliance framework badges */}
        <ComplianceBadges frameworks={policy.compliance_frameworks} />

        {/* Violation count */}
        {(policy.open_violations > 0 || (evalRes?.violations > 0)) && (
          <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">
            {policy.open_violations || evalRes?.violations || 0} violations
          </span>
        )}

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0" onClick={e => e.stopPropagation()}>
          <button onClick={runEval} disabled={evaling} className={`${btnG} px-2`} title="Evaluate now">
            {evaling ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          <button onClick={() => onEdit(policy)} className={`${btnG} px-2`} title="Edit"><Edit2 className="w-3.5 h-3.5" /></button>
          <button onClick={() => onToggle(policy)} className={`${btnG} px-2`} title={policy.enabled ? 'Disable' : 'Enable'}>
            {policy.enabled ? <ToggleRight className="w-3.5 h-3.5 text-emerald-400" /> : <ToggleLeft className="w-3.5 h-3.5" />}
          </button>
          <button onClick={() => { if (confirm(`Delete "${policy.name}"?`)) onDelete(policy.id); }} className={`${btnG} px-2`} title="Delete">
            <Trash2 className="w-3.5 h-3.5 text-red-400/60" />
          </button>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-nhi-faint" /> : <ChevronDown className="w-4 h-4 text-nhi-faint" />}
      </div>

      {/* Confirmation bar for mode change */}
      {showConfirm && (
        <div className={`mx-4 mb-2 px-3 py-2.5 rounded-lg flex items-center gap-3 ${
          showConfirm === 'enforce' ? 'bg-red-500/8 border border-red-500/15' : 'bg-amber-500/8 border border-amber-500/15'
        }`}>
          <AlertTriangle className="w-4 h-4 flex-shrink-0" style={{ color: showConfirm === 'enforce' ? '#ef4444' : '#f59e0b' }} />
          <div className="flex-1">
            <div className="text-[11px] font-semibold text-nhi-text">
              {showConfirm === 'enforce'
                ? 'Switch to Enforce Mode?'
                : 'Rollback to Audit Mode?'}
            </div>
            <div className="text-[10px] text-nhi-muted mt-0.5">
              {showConfirm === 'enforce'
                ? 'Violations will be actively blocked. Workloads that fail this policy will be denied access.'
                : 'Violations will be logged but not blocked. Traffic will be allowed through.'}
            </div>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <button onClick={() => setShowConfirm(null)}
              className="px-3 py-1.5 rounded text-[10px] font-semibold text-nhi-muted bg-white/[0.04] hover:bg-white/[0.08] transition-colors">
              Cancel
            </button>
            <button onClick={() => changeMode(showConfirm)} disabled={modeChanging}
              className={`px-3 py-1.5 rounded text-[10px] font-bold transition-colors ${
                showConfirm === 'enforce'
                  ? 'bg-red-500/15 text-red-400 hover:bg-red-500/25 border border-red-500/20'
                  : 'bg-amber-500/15 text-amber-400 hover:bg-amber-500/25 border border-amber-500/20'
              }`}>
              {modeChanging ? '...' : showConfirm === 'enforce' ? '⚡ Enforce Now' : '◐ Switch to Audit'}
            </button>
          </div>
        </div>
      )}

      {expanded && (
        <div className="px-4 pb-3 border-t border-white/[0.03] pt-3 space-y-3">
          {/* Mode explanation */}
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-[10px] ${
            isEnforce ? 'bg-emerald-500/6 text-emerald-400' : isAudit ? 'bg-amber-500/6 text-amber-400' : 'bg-white/[0.02] text-nhi-faint'
          }`}>
            {isEnforce
              ? <><CheckCircle className="w-3.5 h-3.5" /> <span>Live enforcement — violations are <strong>blocked</strong> at the edge gateway and ext-authz adapter.</span></>
              : isAudit
                ? <><Eye className="w-3.5 h-3.5" /> <span>Audit mode — violations are <strong>logged</strong> but traffic is allowed through. Safe for testing.</span></>
                : <span>Policy is disabled.</span>
            }
          </div>

          {/* Conditions */}
          <div>
            <div className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold mb-1">Conditions</div>
            {conds.map((c, i) => (
              <div key={i} className="flex items-center gap-1.5 text-[11px] py-0.5">
                {i > 0 && <span className="text-accent text-[10px] font-bold">AND</span>}
                <span className="text-nhi-muted font-semibold">{FIELDS.find(f => f.key === c.field)?.label || c.field}</span>
                <span className="text-nhi-muted">{c.operator.replace(/_/g, ' ')}</span>
                {c.value && <span className="text-accent font-mono">{c.value}</span>}
              </div>
            ))}
          </div>

          {/* Actions */}
          <div>
            <div className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold mb-1">Actions</div>
            {acts.map((a, i) => (
              <div key={i} className="flex items-center gap-1.5 text-[11px] py-0.5">
                <ArrowRight className="w-3 h-3 text-nhi-faint" />
                <span className="text-nhi-muted font-semibold">{ACTIONS.find(ac => ac.key === a.type)?.label || a.type}</span>
                {a.message && <span className="text-nhi-muted">— {a.message}</span>}
              </div>
            ))}
          </div>

          {/* Simulate button */}
          <button onClick={runEval} disabled={evaling}
            className="w-full py-2 rounded-lg text-[11px] font-bold transition-colors bg-blue-500/10 border border-blue-500/20 text-blue-400 hover:bg-blue-500/15 flex items-center justify-center gap-2">
            {evaling
              ? <><Loader className="w-3.5 h-3.5 animate-spin" /> Evaluating...</>
              : <><Play className="w-3.5 h-3.5" /> Evaluate Against All Workloads</>
            }
          </button>

          {/* Eval result */}
          {evalRes && (
            <div className={`p-3 rounded-lg border ${
              evalRes.violations > 0 ? 'bg-red-500/5 border-red-500/10' : 'bg-emerald-500/5 border-emerald-500/10'
            }`}>
              <div className="flex items-center justify-between mb-2">
                <div className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold">
                  Evaluation Results
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-[12px] font-bold font-mono ${evalRes.violations > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {evalRes.violations}/{evalRes.evaluated}
                  </span>
                  <span className="text-[10px] text-nhi-faint">would violate</span>
                </div>
              </div>

              {/* Visual bar */}
              <div className="w-full h-2 rounded-full bg-white/[0.04] mb-2 overflow-hidden">
                {evalRes.evaluated > 0 && (
                  <div className={`h-full rounded-full transition-all ${evalRes.violations > 0 ? 'bg-red-500' : 'bg-emerald-500'}`}
                    style={{ width: `${Math.max(2, (evalRes.violations / evalRes.evaluated) * 100)}%` }} />
                )}
              </div>

              {evalRes.violations === 0 && (
                <div className="flex items-center gap-2 text-[11px] text-emerald-400 py-1">
                  <CheckCircle className="w-4 h-4" />
                  <span>All {evalRes.evaluated} workloads are compliant.{isAudit && ' Safe to promote to enforce mode.'}</span>
                </div>
              )}

              {evalRes.violations > 0 && (
                <div className="space-y-0.5">
                  {evalRes.results?.slice(0, 8).map((r, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px] py-1 border-t border-white/[0.02]">
                      <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span className="text-nhi-text font-mono text-[10px] font-semibold">{r.workload_name}</span>
                      <span className="text-nhi-muted truncate flex-1">{r.message}</span>
                      {isEnforce && <span className="text-[8px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">BLOCKED</span>}
                      {isAudit && <span className="text-[8px] font-bold text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded">LOGGED</span>}
                    </div>
                  ))}
                  {(evalRes.results?.length || 0) > 8 && (
                    <div className="text-[10px] text-nhi-faint mt-1">+{evalRes.results.length - 8} more violations</div>
                  )}
                </div>
              )}

              {/* Action buttons based on current mode + results */}
              {isAudit && (
                <div className="flex gap-2 mt-3 pt-2 border-t border-white/[0.03]">
                  <button onClick={runEval} className="px-3 py-1.5 rounded text-[10px] font-semibold text-nhi-muted bg-white/[0.04] hover:bg-white/[0.06] transition-colors">
                    ↻ Re-evaluate
                  </button>
                  <button onClick={() => setShowConfirm('enforce')}
                    className={`flex-1 py-1.5 rounded text-[10px] font-bold transition-colors flex items-center justify-center gap-1.5 ${
                      evalRes.violations > 0
                        ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20 hover:bg-orange-500/15'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/15'
                    }`}>
                    {evalRes.violations > 0 ? '⚠ Promote to Enforce (will block)' : '✓ Promote to Enforce'}
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Meta */}
          <div className="flex flex-wrap gap-4 text-[10px] text-nhi-faint">
            {policy.last_evaluated && <span>Last eval: {new Date(policy.last_evaluated).toLocaleString()}</span>}
            <span>Evaluated {policy.evaluation_count || 0} times</span>
            {policy.template_id && <span>Template: <span className="font-mono text-nhi-muted">{policy.template_id}</span></span>}
            {policy.compliance_frameworks && (() => {
              const cfs = typeof policy.compliance_frameworks === 'string' ? (() => { try { return JSON.parse(policy.compliance_frameworks); } catch { return []; } })() : (policy.compliance_frameworks || []);
              return cfs.length > 0 ? <span>Frameworks: {cfs.map(cf => COMPLIANCE_COLORS[cf.framework]?.label || cf.framework).join(', ')}</span> : null;
            })()}
            <span>Created: {new Date(policy.created_at).toLocaleDateString()}</span>
          </div>
        </div>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════
// Main Policies Page
// ══════════════════════════════════════════════════════════════
const Policies = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState('list'); // list | create | edit | templates
  const [editTarget, setEditTarget] = useState(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all'); // all | enforcement | compliance | lifecycle

  // Auto-open create view when navigating from Graph page with ?create=true&workload=<name>
  useEffect(() => {
    if (searchParams.get('create') === 'true') {
      const workload = searchParams.get('workload') || '';
      setEditTarget(workload ? {
        name: `Custom policy for ${workload}`,
        description: `Custom enforcement rule scoped to ${workload}`,
        policy_type: 'enforcement',
        severity: 'medium',
        enforcement_mode: 'audit',
        conditions: [{ field: 'source_workload', operator: 'equals', value: workload }],
        actions: [{ type: 'deny', message: '' }],
      } : null);
      setView('create');
      setSearchParams({}, { replace: true }); // clear params after consuming
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API}/policies`);
      const d = await r.json();
      setPolicies(d.policies || []);
    } catch { toast.error('Failed to load policies'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (p) => {
    const r = await fetch(`${API}/policies`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(p) });
    if (!r.ok) { const e = await r.json(); toast.error(e.error || 'Failed'); return; }
    toast.success('Policy created');
    setView('list'); load();
  };

  const handleUpdate = async (p) => {
    const r = await fetch(`${API}/policies/${editTarget.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(p) });
    if (!r.ok) { const e = await r.json(); toast.error(e.error || 'Failed'); return; }
    toast.success('Policy updated');
    setView('list'); setEditTarget(null); load();
  };

  const handleDelete = async (id) => {
    await fetch(`${API}/policies/${id}`, { method:'DELETE' });
    toast.success('Deleted');
    load();
  };

  const handleToggle = async (p) => {
    await fetch(`${API}/policies/${p.id}/toggle`, { method:'PATCH' });
    toast.success(p.enabled ? 'Disabled' : 'Enabled');
    load();
  };

  const handleTemplateUse = (tpl) => {
    if (tpl._customize) {
      setEditTarget(null);
      setView('create');
      // Will populate editor with template data via a delayed state push
      setTimeout(() => {
        setEditTarget({ ...tpl, id: undefined, template_id: tpl.id, enforcement_mode: 'audit' });
        setView('create');
      }, 0);
    } else {
      setView('list'); load();
    }
  };

  const evalAll = async () => {
    try {
      const r = await fetch(`${API}/policies/evaluate-all`, { method:'POST' });
      const d = await r.json();
      toast.success(`${d.total_violations} total violations across ${d.total_policies} policies`);
      load();
    } catch { toast.error('Evaluation failed'); }
  };

  const filtered = policies.filter(p => {
    if (search && !p.name.toLowerCase().includes(search.toLowerCase())) return false;
    if (filter !== 'all' && p.policy_type !== filter) return false;
    return true;
  });

  const stats = {
    total: policies.length,
    enabled: policies.filter(p => p.enabled).length,
    violations: policies.reduce((sum, p) => sum + (parseInt(p.open_violations) || 0), 0),
    enforcing: policies.filter(p => p.enforcement_mode === 'enforce').length,
  };

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-[20px] font-bold text-nhi-text flex items-center gap-2">
            <Shield className="w-5 h-5 text-accent" /> Policies
          </h1>
          <p className="text-[12px] text-nhi-muted mt-0.5">Governance rules for non-human identities — enforce trust, compliance, and lifecycle standards.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={evalAll} className={btnG}><Zap className="w-3.5 h-3.5" /> Evaluate All</button>
          <button onClick={() => setView('templates')} className={btnG}><BookOpen className="w-3.5 h-3.5" /> Templates</button>
          <button onClick={() => { setEditTarget(null); setView('create'); }} className={btnP}><Plus className="w-3.5 h-3.5" /> New Policy</button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3 mb-5">
        {[
          { label: 'Total Policies', value: stats.total, color: 'text-accent' },
          { label: 'Enabled', value: stats.enabled, color: 'text-emerald-400' },
          { label: 'Open Violations', value: stats.violations, color: stats.violations > 0 ? 'text-red-400' : 'text-emerald-400' },
          { label: 'Enforcing', value: stats.enforcing, color: 'text-amber-400' },
        ].map((s, i) => (
          <div key={i} className="p-3 rounded-lg bg-white/[0.015] border border-white/[0.04]">
            <div className="text-[10px] text-nhi-faint uppercase tracking-widest font-bold">{s.label}</div>
            <div className={`text-[22px] font-bold ${s.color} mt-0.5`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Templates / Create / Edit views */}
      {view === 'templates' && (
        <div className="mb-5 p-4 rounded-lg bg-surface-2 border border-white/[0.04]">
          <TemplateGallery onUse={handleTemplateUse} onClose={() => setView('list')} />
        </div>
      )}
      {view === 'create' && (
        <div className="mb-5 p-4 rounded-lg bg-surface-2 border border-white/[0.04]">
          <h3 className="text-[14px] font-bold text-nhi-text mb-3 flex items-center gap-2"><Plus className="w-4 h-4 text-accent" /> Create Policy</h3>
          <PolicyEditor initial={editTarget} onSave={handleCreate} onCancel={() => setView('list')} />
        </div>
      )}
      {view === 'edit' && editTarget && (
        <div className="mb-5 p-4 rounded-lg bg-surface-2 border border-white/[0.04]">
          <h3 className="text-[14px] font-bold text-nhi-text mb-3 flex items-center gap-2"><Edit2 className="w-4 h-4 text-accent" /> Edit: {editTarget.name}</h3>
          <PolicyEditor initial={editTarget} onSave={handleUpdate} onCancel={() => { setView('list'); setEditTarget(null); }} />
        </div>
      )}

      {/* Filter bar */}
      {view === 'list' && (
        <>
          <div className="flex items-center gap-3 mb-3">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-nhi-faint" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search policies..." className={`${inp} pl-8`} />
            </div>
            {['all','enforcement','compliance','lifecycle','access'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`text-[10px] font-bold uppercase px-2.5 py-1 rounded transition-colors ${
                  filter === f ? 'bg-accent/15 text-accent border border-accent/25' : 'text-nhi-faint hover:text-nhi-muted'
                }`}>
                {f === 'all' ? 'All' : `${TICON[f]||''} ${f}`}
              </button>
            ))}
            <button onClick={load} className={btnG}><RefreshCw className="w-3 h-3" /> Refresh</button>
          </div>

          {/* Policy List */}
          {loading ? (
            <div className="flex items-center justify-center py-12 text-nhi-muted"><Loader className="w-5 h-5 animate-spin mr-2" /> Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12">
              <Shield className="w-10 h-10 text-nhi-faint mx-auto mb-3" />
              <div className="text-[14px] font-semibold text-nhi-muted mb-1">
                {policies.length === 0 ? 'No policies yet' : 'No matching policies'}
              </div>
              <div className="text-[12px] text-nhi-faint mb-3">
                {policies.length === 0 ? 'Create your first policy or deploy from a template.' : 'Try adjusting your filters.'}
              </div>
              {policies.length === 0 && (
                <div className="flex gap-2 justify-center">
                  <button onClick={() => setView('templates')} className={btnP}><BookOpen className="w-3.5 h-3.5" /> Browse Templates</button>
                  <button onClick={() => setView('create')} className={btnG}><Plus className="w-3.5 h-3.5" /> Custom Policy</button>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map(p => (
                <PolicyRow key={p.id} policy={p}
                  onEdit={(pol) => { setEditTarget(pol); setView('edit'); }}
                  onDelete={handleDelete} onToggle={handleToggle} onEval={load} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Policies;
