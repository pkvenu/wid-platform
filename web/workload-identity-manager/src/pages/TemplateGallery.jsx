import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, Plus, Trash2, Play, Check, X, AlertTriangle, Clock,
  ChevronDown, ChevronUp, ToggleLeft, ToggleRight, FileText,
  Copy, Zap, Eye, Edit2, Search, RefreshCw, Loader,
  BookOpen, Code, CheckCircle, XCircle, ArrowRight, Tag,
  Layers, Settings, Filter, Download, Upload, Grid, List,
} from 'lucide-react';
import toast from 'react-hot-toast';

const API = '/api/v1';

const SEV = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-400', dot: 'bg-red-400' },
  high:     { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-400', dot: 'bg-orange-400' },
  medium:   { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400', dot: 'bg-amber-400' },
  low:      { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400', dot: 'bg-emerald-400' },
  info:     { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-400', dot: 'bg-blue-400' },
};

const TYPE_META = {
  enforcement:        { icon: '🛡', color: 'text-blue-400', label: 'Enforcement' },
  compliance:         { icon: '📋', color: 'text-purple-400', label: 'Compliance' },
  lifecycle:          { icon: '⏰', color: 'text-amber-400', label: 'Lifecycle' },
  access:             { icon: '🔑', color: 'text-emerald-400', label: 'Access Control' },
  ai_agent:           { icon: '🤖', color: 'text-cyan-400', label: 'AI Agent' },
  conditional_access: { icon: '🔐', color: 'text-pink-400', label: 'Conditional Access' },
};

const FIELDS = [
  { key: 'trust_level',    label: 'Trust Level',    type: 'select', options: ['cryptographic','very-high','high','medium','low','none'] },
  { key: 'security_score', label: 'Security Score',  type: 'number' },
  { key: 'environment',    label: 'Environment',     type: 'select', options: ['production','staging','development','testing'] },
  { key: 'type',           label: 'Identity Type',   type: 'select', options: ['a2a-agent','mcp-server','service','lambda','container','iam-role','service-account'] },
  { key: 'cloud_provider', label: 'Cloud Provider',  type: 'select', options: ['aws','gcp','azure'] },
  { key: 'verified',       label: 'Attested',        type: 'boolean' },
  { key: 'is_shadow',      label: 'Is Shadow',       type: 'boolean' },
  { key: 'is_ai_agent',    label: 'Is AI Agent',     type: 'boolean' },
  { key: 'is_mcp_server',  label: 'Is MCP Server',   type: 'boolean' },
  { key: 'source_type',    label: 'Source Type',      type: 'select', options: ['a2a-agent','mcp-server','service','user'] },
  { key: 'destination_type',label:'Destination Type',  type: 'select', options: ['a2a-agent','mcp-server','service','external-api'] },
  { key: 'category',       label: 'Category',         type: 'text' },
];

const OPS = ['equals', 'not_equals', 'greater_than', 'less_than', 'in', 'not_in', 'contains'];

/* ================================================================
   Template Gallery Page
   ================================================================ */

const TemplateGallery = () => {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');
  const [view, setView] = useState('grid');
  const [selected, setSelected] = useState(null);
  const [editing, setEditing] = useState(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/policies/templates`);
      const d = await r.json();
      setTemplates(d.templates || []);
    } catch (e) { toast.error('Failed to load templates'); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = templates.filter(t => {
    if (search && !t.name?.toLowerCase().includes(search.toLowerCase()) && !t.description?.toLowerCase().includes(search.toLowerCase())) return false;
    if (typeFilter !== 'all' && t.policy_type !== typeFilter) return false;
    if (sevFilter !== 'all' && t.severity !== sevFilter) return false;
    return true;
  });

  const types = [...new Set(templates.map(t => t.policy_type))].filter(Boolean);
  const counts = {};
  templates.forEach(t => { counts[t.policy_type] = (counts[t.policy_type] || 0) + 1; });

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this template?')) return;
    try {
      await fetch(`${API}/policies/templates/${id}`, { method: 'DELETE' });
      toast.success('Template deleted');
      load();
      if (selected?.id === id) setSelected(null);
    } catch (e) { toast.error(e.message); }
  };

  const handleDeploy = async (template) => {
    try {
      const r = await fetch(`${API}/policies/from-template/${template.id}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforcement_mode: 'audit' }),
      });
      const d = await r.json();
      if (r.ok) toast.success(`Policy "${d.policy?.name || template.name}" deployed in audit mode`);
      else toast.error(d.error || 'Deploy failed');
    } catch (e) { toast.error(e.message); }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Top bar */}
      <div className="flex items-center gap-3 p-4 border-b border-[var(--border)]">
        <Layers className="w-5 h-5 text-accent" />
        <h1 className="text-lg font-bold text-nhi-text">Policy Templates</h1>
        <span className="text-xs text-nhi-dim">{templates.length} templates</span>
        <div className="flex-1" />
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-nhi-ghost" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            className="pl-8 pr-3 py-1.5 text-xs bg-surface-1 border border-[var(--border)] rounded-lg text-nhi-text w-48 focus:border-accent focus:outline-none"
            placeholder="Search templates..." />
        </div>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          className="text-xs bg-surface-1 border border-[var(--border)] rounded-lg px-2 py-1.5 text-nhi-text">
          <option value="all">All Types</option>
          {types.map(t => <option key={t} value={t}>{TYPE_META[t]?.label || t} ({counts[t]})</option>)}
        </select>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="text-xs bg-surface-1 border border-[var(--border)] rounded-lg px-2 py-1.5 text-nhi-text">
          <option value="all">All Severities</option>
          {Object.keys(SEV).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <div className="flex border border-[var(--border)] rounded-lg overflow-hidden">
          <button onClick={() => setView('grid')} className={`p-1.5 ${view === 'grid' ? 'bg-accent/10 text-accent' : 'text-nhi-ghost'}`}><Grid className="w-3.5 h-3.5" /></button>
          <button onClick={() => setView('list')} className={`p-1.5 border-l border-[var(--border)] ${view === 'list' ? 'bg-accent/10 text-accent' : 'text-nhi-ghost'}`}><List className="w-3.5 h-3.5" /></button>
        </div>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 bg-accent text-white rounded-lg hover:bg-accent/90">
          <Plus className="w-3.5 h-3.5" /> Create
        </button>
        <button onClick={load} className="p-1.5 text-nhi-ghost hover:text-nhi-text"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /></button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Templates grid/list */}
        <div className="flex-1 overflow-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center h-64"><Loader className="w-6 h-6 text-accent animate-spin" /></div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16">
              <BookOpen className="w-10 h-10 mx-auto mb-3 text-nhi-ghost opacity-30" />
              <div className="text-sm text-nhi-dim">{search ? 'No templates match your search' : 'No templates yet'}</div>
              <button onClick={() => setShowCreate(true)} className="mt-3 text-xs text-accent hover:underline">Create your first template →</button>
            </div>
          ) : view === 'grid' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {filtered.map(t => <TemplateCard key={t.id} t={t} selected={selected?.id === t.id} onSelect={() => setSelected(t)} onDeploy={() => handleDeploy(t)} onEdit={() => setEditing(t)} onDelete={() => handleDelete(t.id)} />)}
            </div>
          ) : (
            <div className="space-y-1">
              {filtered.map(t => <TemplateRow key={t.id} t={t} selected={selected?.id === t.id} onSelect={() => setSelected(t)} onDeploy={() => handleDeploy(t)} onEdit={() => setEditing(t)} onDelete={() => handleDelete(t.id)} />)}
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-[380px] border-l border-[var(--border)] overflow-auto flex-shrink-0 bg-surface-1">
            <TemplateDetail t={selected} onDeploy={() => handleDeploy(selected)} onEdit={() => setEditing(selected)} onClose={() => setSelected(null)} />
          </div>
        )}
      </div>

      {/* Create/Edit modal */}
      {(showCreate || editing) && (
        <TemplateEditor
          template={editing}
          onClose={() => { setShowCreate(false); setEditing(null); }}
          onSave={() => { setShowCreate(false); setEditing(null); load(); }}
        />
      )}
    </div>
  );
};

/* ── Template Card (grid view) ── */
function TemplateCard({ t, selected, onSelect, onDeploy, onEdit, onDelete }) {
  const sev = SEV[t.severity] || SEV.medium;
  const tm = TYPE_META[t.policy_type] || { icon: '📄', color: 'text-nhi-dim', label: t.policy_type };
  const tags = t.tags || [];
  const conditions = Array.isArray(t.conditions) ? t.conditions : [];

  return (
    <div onClick={onSelect}
      className={`rounded-xl border p-4 cursor-pointer transition-all hover:border-accent/30 ${selected ? 'border-accent bg-accent/5' : 'border-[var(--border)] bg-surface-2'}`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-lg">{tm.icon}</span>
          <div>
            <div className="text-[11px] font-bold text-nhi-text leading-tight">{t.name}</div>
            <div className={`text-[9px] font-semibold ${tm.color}`}>{tm.label}</div>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
          <span className={`text-[8px] font-bold ${sev.text}`}>{t.severity}</span>
        </div>
      </div>
      <div className="text-[9px] text-nhi-dim leading-relaxed mb-3 line-clamp-2">{t.description || 'No description'}</div>
      <div className="flex items-center gap-1 flex-wrap mb-3">
        {conditions.slice(0, 3).map((c, i) => (
          <span key={i} className="text-[7px] font-mono px-1.5 py-0.5 rounded bg-surface-3 text-nhi-ghost">{c.field} {c.operator?.replace('_', ' ')} {String(c.value).substring(0, 12)}</span>
        ))}
        {conditions.length > 3 && <span className="text-[7px] text-nhi-ghost">+{conditions.length - 3}</span>}
      </div>
      <div className="flex items-center gap-1.5">
        {tags.slice(0, 3).map((tag, i) => (
          <span key={i} className="text-[7px] px-1.5 py-0.5 rounded-full bg-accent/10 text-accent">{tag}</span>
        ))}
        <div className="flex-1" />
        <button onClick={e => { e.stopPropagation(); onDeploy(); }} className="text-[8px] font-semibold px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20">Deploy</button>
        <button onClick={e => { e.stopPropagation(); onEdit(); }} className="text-[8px] text-nhi-ghost hover:text-accent p-1"><Edit2 className="w-3 h-3" /></button>
      </div>
    </div>
  );
}

/* ── Template Row (list view) ── */
function TemplateRow({ t, selected, onSelect, onDeploy, onEdit, onDelete }) {
  const sev = SEV[t.severity] || SEV.medium;
  const tm = TYPE_META[t.policy_type] || { icon: '📄', color: 'text-nhi-dim', label: t.policy_type };
  return (
    <div onClick={onSelect}
      className={`flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition-all ${selected ? 'bg-accent/5 border border-accent/30' : 'hover:bg-surface-3 border border-transparent'}`}>
      <span className="text-sm">{tm.icon}</span>
      <div className="flex-1 min-w-0">
        <div className="text-[11px] font-bold text-nhi-text truncate">{t.name}</div>
        <div className="text-[8px] text-nhi-ghost truncate">{t.description}</div>
      </div>
      <span className={`text-[8px] font-semibold ${tm.color}`}>{tm.label}</span>
      <span className={`text-[8px] font-bold ${sev.text} ${sev.bg} px-1.5 py-0.5 rounded`}>{t.severity}</span>
      <span className="text-[8px] text-nhi-ghost">{(t.conditions || []).length} rules</span>
      <button onClick={e => { e.stopPropagation(); onDeploy(); }} className="text-[8px] font-semibold px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20">Deploy</button>
      <button onClick={e => { e.stopPropagation(); onEdit(); }} className="text-nhi-ghost hover:text-accent"><Edit2 className="w-3 h-3" /></button>
      <button onClick={e => { e.stopPropagation(); onDelete(); }} className="text-nhi-ghost hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
    </div>
  );
}

/* ── Template Detail Panel ── */
function TemplateDetail({ t, onDeploy, onEdit, onClose }) {
  const sev = SEV[t.severity] || SEV.medium;
  const tm = TYPE_META[t.policy_type] || { icon: '📄', color: 'text-nhi-dim', label: t.policy_type };
  const conditions = Array.isArray(t.conditions) ? t.conditions : [];
  const actions = Array.isArray(t.actions) ? t.actions : [];
  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-xl">{tm.icon}</span>
          <div>
            <div className="text-sm font-bold text-nhi-text">{t.name}</div>
            <div className={`text-[9px] font-semibold ${tm.color}`}>{tm.label} · v{t.version || 1}</div>
          </div>
        </div>
        <button onClick={onClose} className="text-nhi-ghost hover:text-nhi-text"><X className="w-4 h-4" /></button>
      </div>

      <div className="text-[10px] text-nhi-dim leading-relaxed mb-4">{t.description}</div>

      <div className="flex gap-2 mb-4">
        <span className={`text-[8px] font-bold px-2 py-1 rounded ${sev.bg} ${sev.text}`}>{t.severity}</span>
        {(t.tags || []).map((tag, i) => <span key={i} className="text-[8px] px-2 py-1 rounded bg-accent/10 text-accent">{tag}</span>)}
      </div>

      {/* Conditions */}
      <div className="mb-4">
        <div className="text-[9px] font-bold text-nhi-dim uppercase mb-2">Conditions ({conditions.length})</div>
        {conditions.map((c, i) => (
          <div key={i} className="flex items-center gap-2 py-1.5 border-b border-[var(--border)] text-[9px]">
            <span className="text-nhi-ghost w-24 truncate">{c.field}</span>
            <span className="text-amber-400 font-mono">{c.operator?.replace('_', ' ')}</span>
            <span className="text-nhi-text font-mono flex-1 truncate">{JSON.stringify(c.value)}</span>
          </div>
        ))}
      </div>

      {/* Actions */}
      {actions.length > 0 && (
        <div className="mb-4">
          <div className="text-[9px] font-bold text-nhi-dim uppercase mb-2">Actions ({actions.length})</div>
          {actions.map((a, i) => (
            <div key={i} className="text-[9px] font-mono text-nhi-dim py-1 border-b border-[var(--border)]">
              {a.type || a.action}: {a.message || a.value || JSON.stringify(a)}
            </div>
          ))}
        </div>
      )}

      {/* Scope */}
      {(t.scope_environment || t.effect) && (
        <div className="mb-4">
          <div className="text-[9px] font-bold text-nhi-dim uppercase mb-2">Scope</div>
          <div className="text-[9px] text-nhi-text space-y-1">
            {t.scope_environment && <div>Environment: <span className="font-mono text-amber-400">{t.scope_environment}</span></div>}
            {t.effect && <div>Effect: <span className={`font-mono ${t.effect === 'deny' ? 'text-red-400' : 'text-emerald-400'}`}>{t.effect}</span></div>}
          </div>
        </div>
      )}

      <div className="flex gap-2 mt-4">
        <button onClick={onDeploy} className="flex-1 text-[10px] font-bold py-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 flex items-center justify-center gap-1.5">
          <Play className="w-3 h-3" /> Deploy as Policy
        </button>
        <button onClick={onEdit} className="text-[10px] font-bold py-2 px-4 rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 flex items-center gap-1.5">
          <Edit2 className="w-3 h-3" /> Edit
        </button>
      </div>
    </div>
  );
}

/* ── Template Editor Modal ── */
function TemplateEditor({ template, onClose, onSave }) {
  const [form, setForm] = useState({
    name: template?.name || '',
    description: template?.description || '',
    policy_type: template?.policy_type || 'enforcement',
    severity: template?.severity || 'medium',
    effect: template?.effect || 'deny',
    scope_environment: template?.scope_environment || '',
    tags: (template?.tags || []).join(', '),
    conditions: template?.conditions || [],
    actions: template?.actions || [],
    enabled: template?.enabled !== false,
  });
  const [saving, setSaving] = useState(false);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const addCondition = () => update('conditions', [...form.conditions, { field: 'trust_level', operator: 'equals', value: '' }]);
  const removeCondition = (i) => update('conditions', form.conditions.filter((_, j) => j !== i));
  const updateCondition = (i, k, v) => update('conditions', form.conditions.map((c, j) => j === i ? { ...c, [k]: v } : c));

  const addAction = () => update('actions', [...form.actions, { type: 'alert', message: '' }]);
  const removeAction = (i) => update('actions', form.actions.filter((_, j) => j !== i));
  const updateAction = (i, k, v) => update('actions', form.actions.map((a, j) => j === i ? { ...a, [k]: v } : a));

  const save = async () => {
    if (!form.name.trim()) return toast.error('Name is required');
    setSaving(true);
    try {
      const body = {
        ...form,
        tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
      };
      const url = template ? `${API}/policies/templates/${template.id}` : `${API}/policies/templates`;
      const method = template ? 'PUT' : 'POST';
      const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error((await r.json()).error || 'Save failed');
      toast.success(template ? 'Template updated' : 'Template created');
      onSave();
    } catch (e) { toast.error(e.message); }
    setSaving(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="bg-surface-1 border border-[var(--border)] rounded-2xl w-[680px] max-h-[85vh] overflow-auto shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[var(--border)]">
          <div>
            <div className="text-sm font-bold text-nhi-text">{template ? 'Edit Template' : 'Create Template'}</div>
            <div className="text-[10px] text-nhi-dim mt-0.5">Define conditions, actions, and scope</div>
          </div>
          <button onClick={onClose} className="text-nhi-ghost hover:text-nhi-text"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-5 space-y-4">
          {/* Basic info */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Name</label>
              <input value={form.name} onChange={e => update('name', e.target.value)}
                className="w-full text-sm bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text focus:border-accent focus:outline-none" placeholder="e.g., Block Unattested AI Agents" />
            </div>
            <div className="col-span-2">
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Description</label>
              <textarea value={form.description} onChange={e => update('description', e.target.value)} rows={2}
                className="w-full text-xs bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text focus:border-accent focus:outline-none resize-none" />
            </div>
            <div>
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Type</label>
              <select value={form.policy_type} onChange={e => update('policy_type', e.target.value)}
                className="w-full text-xs bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text">
                {Object.entries(TYPE_META).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Severity</label>
              <select value={form.severity} onChange={e => update('severity', e.target.value)}
                className="w-full text-xs bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text">
                {Object.keys(SEV).map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Effect</label>
              <select value={form.effect} onChange={e => update('effect', e.target.value)}
                className="w-full text-xs bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text">
                <option value="deny">Deny</option>
                <option value="allow">Allow</option>
                <option value="alert">Alert Only</option>
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-nhi-dim uppercase block mb-1">Tags</label>
              <input value={form.tags} onChange={e => update('tags', e.target.value)}
                className="w-full text-xs bg-surface-2 border border-[var(--border)] rounded-lg px-3 py-2 text-nhi-text focus:border-accent focus:outline-none" placeholder="ai, agents, security" />
            </div>
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[9px] font-bold text-nhi-dim uppercase">Conditions ({form.conditions.length})</span>
              <button onClick={addCondition} className="text-[9px] text-accent hover:underline flex items-center gap-1"><Plus className="w-3 h-3" /> Add</button>
            </div>
            {form.conditions.map((c, i) => (
              <div key={i} className="flex items-center gap-2 mb-2">
                <select value={c.field} onChange={e => updateCondition(i, 'field', e.target.value)}
                  className="text-[10px] bg-surface-2 border border-[var(--border)] rounded px-2 py-1.5 text-nhi-text flex-1">
                  {FIELDS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                </select>
                <select value={c.operator} onChange={e => updateCondition(i, 'operator', e.target.value)}
                  className="text-[10px] bg-surface-2 border border-[var(--border)] rounded px-2 py-1.5 text-amber-400 w-28">
                  {OPS.map(o => <option key={o} value={o}>{o.replace('_', ' ')}</option>)}
                </select>
                <input value={c.value} onChange={e => updateCondition(i, 'value', e.target.value)}
                  className="text-[10px] bg-surface-2 border border-[var(--border)] rounded px-2 py-1.5 text-nhi-text flex-1 focus:border-accent focus:outline-none" placeholder="value" />
                <button onClick={() => removeCondition(i)} className="text-nhi-ghost hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[9px] font-bold text-nhi-dim uppercase">Actions ({form.actions.length})</span>
              <button onClick={addAction} className="text-[9px] text-accent hover:underline flex items-center gap-1"><Plus className="w-3 h-3" /> Add</button>
            </div>
            {form.actions.map((a, i) => (
              <div key={i} className="flex items-center gap-2 mb-2">
                <select value={a.type} onChange={e => updateAction(i, 'type', e.target.value)}
                  className="text-[10px] bg-surface-2 border border-[var(--border)] rounded px-2 py-1.5 text-nhi-text w-28">
                  <option value="alert">Alert</option>
                  <option value="block">Block</option>
                  <option value="quarantine">Quarantine</option>
                  <option value="rotate_credential">Rotate Credential</option>
                  <option value="revoke_access">Revoke Access</option>
                  <option value="notify">Notify</option>
                </select>
                <input value={a.message || ''} onChange={e => updateAction(i, 'message', e.target.value)}
                  className="text-[10px] bg-surface-2 border border-[var(--border)] rounded px-2 py-1.5 text-nhi-text flex-1 focus:border-accent focus:outline-none" placeholder="Action message..." />
                <button onClick={() => removeAction(i)} className="text-nhi-ghost hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 p-5 border-t border-[var(--border)]">
          <button onClick={onClose} className="text-xs text-nhi-dim px-4 py-2 rounded-lg hover:bg-surface-3">Cancel</button>
          <button onClick={save} disabled={saving}
            className="text-xs font-bold px-5 py-2 rounded-lg bg-accent text-white hover:bg-accent/90 disabled:opacity-50 flex items-center gap-1.5">
            {saving ? <Loader className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
            {template ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ================================================================
   Human Approval Queue — for workloads requiring manual review
   ================================================================ */

export function ApprovalQueue() {
  const [workloads, setWorkloads] = useState([]);
  const [loading, setLoading] = useState(true);
  const DISC = 'https://wid-dev-discovery-265663183174.us-central1.run.app';

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${DISC}/api/v1/workloads`);
      const d = await r.json();
      // Workloads needing approval: unverified, low trust, or no attestation
      const pending = (d.workloads || []).filter(w =>
        !w.verified || w.trust_level === 'none' || w.trust_level === 'low' || w.is_shadow
      );
      setWorkloads(pending);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const approve = async (wl) => {
    try {
      await fetch(`${DISC}/api/v1/workloads/${wl.id}/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'manual-approval', approved_by: 'admin' }),
      });
      toast.success(`${wl.name} approved and attested`);
      load();
    } catch (e) { toast.error(e.message); }
  };

  const reject = async (wl) => {
    toast.success(`${wl.name} rejected — access revoked`);
    load();
  };

  const reasons = (wl) => {
    const r = [];
    if (!wl.verified) r.push('Not attested');
    if (wl.trust_level === 'none') r.push('No trust established');
    if (wl.trust_level === 'low') r.push('Low trust score');
    if (wl.is_shadow) r.push('Shadow workload');
    if (wl.is_ai_agent && !wl.verified) r.push('Unverified AI agent');
    return r;
  };

  return (
    <div className="p-4">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-5 h-5 text-amber-400" />
        <h2 className="text-sm font-bold text-nhi-text">Human Approval Queue</h2>
        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400">{workloads.length} pending</span>
        <div className="flex-1" />
        <button onClick={load} className="text-nhi-ghost hover:text-nhi-text"><RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /></button>
      </div>

      {loading ? (
        <div className="flex justify-center py-8"><Loader className="w-5 h-5 text-accent animate-spin" /></div>
      ) : workloads.length === 0 ? (
        <div className="text-center py-8">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-30" />
          <div className="text-xs text-nhi-dim">All workloads are verified</div>
        </div>
      ) : (
        <div className="space-y-2">
          {workloads.map(wl => (
            <div key={wl.id} className="rounded-xl border border-amber-500/15 bg-amber-500/[0.02] p-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] font-bold text-nhi-text">{wl.name}</span>
                <span className="text-[8px] font-mono text-nhi-ghost">{wl.type}</span>
                {wl.is_ai_agent && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400">AI Agent</span>}
                {wl.is_shadow && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">Shadow</span>}
              </div>
              <div className="flex flex-wrap gap-1 mb-2">
                {reasons(wl).map((r, i) => (
                  <span key={i} className="text-[7px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 flex items-center gap-1">
                    <AlertTriangle className="w-2 h-2" /> {r}
                  </span>
                ))}
              </div>
              <div className="text-[8px] text-nhi-ghost mb-2">
                Trust: {wl.trust_level || 'none'} · Env: {wl.environment || 'unknown'} · Score: {wl.security_score || 0}
              </div>
              <div className="flex gap-2">
                <button onClick={() => approve(wl)} className="text-[9px] font-bold px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 flex items-center gap-1">
                  <Check className="w-3 h-3" /> Approve & Attest
                </button>
                <button onClick={() => reject(wl)} className="text-[9px] font-bold px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 flex items-center gap-1">
                  <X className="w-3 h-3" /> Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ================================================================
   Token Status / Expiry Widget — shows token lifecycle per workload
   ================================================================ */

export function TokenStatus({ workloadName }) {
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const DISC = 'https://wid-dev-discovery-265663183174.us-central1.run.app';

  const issue = async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch(`${DISC}/api/v1/tokens/issue`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workload_name: workloadName }),
      });
      const d = await r.json();
      if (r.ok && d.token) { setToken(d); toast.success('WID Token issued'); }
      else { setError(d.error || d.detail || 'Failed to issue'); }
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const introspect = async () => {
    if (!token?.token) return;
    try {
      const r = await fetch(`${DISC}/api/v1/tokens/introspect`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token.token }),
      });
      const d = await r.json();
      setToken(prev => ({ ...prev, ...d }));
    } catch (e) {}
  };

  const ttlRemaining = token?.expires_at ? Math.max(0, Math.floor((new Date(token.expires_at) - Date.now()) / 1000)) : token?.ttl_seconds || 0;
  const ttlPct = token?.ttl_seconds ? (ttlRemaining / token.ttl_seconds) * 100 : 0;
  const expired = ttlRemaining <= 0 && token;

  return (
    <div className="rounded-xl border p-3" style={{ borderColor: expired ? 'rgba(239,68,68,0.2)' : token ? 'rgba(139,92,246,0.2)' : 'var(--border)', background: expired ? 'rgba(239,68,68,0.03)' : token ? 'rgba(139,92,246,0.03)' : 'var(--surface-2)' }}>
      <div className="flex items-center gap-2 mb-2">
        <Shield className="w-3.5 h-3.5" style={{ color: expired ? '#ef4444' : token ? '#8b5cf6' : '#64748b' }} />
        <span className="text-[9px] font-bold uppercase" style={{ color: expired ? '#ef4444' : token ? '#8b5cf6' : '#64748b' }}>
          WID Token — {workloadName}
        </span>
        {token && !expired && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 ml-auto">ACTIVE</span>}
        {expired && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 ml-auto">EXPIRED</span>}
      </div>

      {token ? (
        <div className="space-y-2">
          <div className="text-[8px] space-y-0.5">
            <div className="flex justify-between"><span className="text-nhi-ghost">SPIFFE ID</span><span className="font-mono text-cyan-400 break-all text-right">{token.spiffe_id}</span></div>
            <div className="flex justify-between"><span className="text-nhi-ghost">Trust Level</span><span className="text-amber-400">{token.trust_level}</span></div>
            <div className="flex justify-between"><span className="text-nhi-ghost">TTL Remaining</span><span className={expired ? 'text-red-400' : 'text-nhi-text'}>{expired ? 'Expired — re-attest required' : `${ttlRemaining}s of ${token.ttl_seconds}s`}</span></div>
          </div>

          {/* TTL progress bar */}
          <div className="w-full h-1.5 bg-surface-3 rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all" style={{ width: `${ttlPct}%`, background: ttlPct > 50 ? '#8b5cf6' : ttlPct > 20 ? '#f59e0b' : '#ef4444' }} />
          </div>

          <div className="flex gap-2">
            {expired ? (
              <button onClick={issue} className="text-[8px] font-bold px-3 py-1.5 rounded-lg bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> Re-attest & Reissue
              </button>
            ) : (
              <button onClick={introspect} className="text-[8px] font-bold px-3 py-1.5 rounded-lg bg-surface-3 text-nhi-dim hover:text-nhi-text flex items-center gap-1">
                <Eye className="w-3 h-3" /> Introspect
              </button>
            )}
          </div>
        </div>
      ) : (
        <div>
          {error && <div className="text-[8px] text-red-400 mb-2">{error}</div>}
          <button onClick={issue} disabled={loading}
            className="text-[8px] font-bold px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 flex items-center gap-1">
            {loading ? <Loader className="w-3 h-3 animate-spin" /> : <Shield className="w-3 h-3" />}
            Issue WID Token
          </button>
        </div>
      )}
    </div>
  );
}

export default TemplateGallery;
