import React, { useState, useEffect, useCallback } from 'react';
import {
  Settings, Building2, Users, BarChart3, Mail, Shield, Globe,
  Edit2, Check, X, Loader, RefreshCw, UserPlus, Clock, Crown,
  Eye, Wrench, Copy, CheckCircle,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';

const API = '/api/v1';

const PLAN_BADGES = {
  trial:      { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400', label: 'Trial' },
  pro:        { bg: 'bg-blue-500/10',  border: 'border-blue-500/20',  text: 'text-blue-400',  label: 'Pro' },
  enterprise: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400', label: 'Enterprise' },
};

const ROLE_ICONS = { admin: Crown, operator: Wrench, viewer: Eye };
const ROLE_COLORS = {
  admin:    'text-amber-400 bg-amber-500/10',
  operator: 'text-blue-400 bg-blue-500/10',
  viewer:   'text-slate-400 bg-slate-500/10',
};

const REGIONS = [
  { value: 'us', label: 'United States' },
  { value: 'eu', label: 'European Union' },
  { value: 'ap', label: 'Asia Pacific' },
];

function ProgressBar({ value, max, color = '#7c6ff0' }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  const barColor = pct >= 90 ? '#ef4444' : pct >= 70 ? '#f59e0b' : color;
  return (
    <div className="w-full rounded-full overflow-hidden" style={{ background: 'var(--surface-3)', height: 6 }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, background: barColor }}
      />
    </div>
  );
}

function SectionCard({ title, icon: Icon, children, className = '' }) {
  return (
    <div
      className={`rounded-xl border p-6 ${className}`}
      style={{ background: 'var(--surface-2)', borderColor: 'var(--border)', boxShadow: 'var(--shadow-card)' }}
    >
      <div className="flex items-center gap-2.5 mb-5">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: 'var(--bg-accent-soft)' }}>
          <Icon className="w-4 h-4 text-accent" strokeWidth={1.5} />
        </div>
        <h3 className="text-sm font-bold text-nhi-text">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex items-center justify-between py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
      <span className="text-xs font-medium text-nhi-dim">{label}</span>
      <span className={`text-xs font-semibold text-nhi-text ${mono ? 'font-mono' : ''}`}>{value || '—'}</span>
    </div>
  );
}

export default function TenantSettings() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [tenant, setTenant] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [usersLoading, setUsersLoading] = useState(true);

  // Edit state
  const [editingName, setEditingName] = useState(false);
  const [nameValue, setNameValue] = useState('');
  const [saving, setSaving] = useState(false);

  // Invite state
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('viewer');
  const [inviting, setInviting] = useState(false);
  const [lastInviteToken, setLastInviteToken] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);

  const fetchTenant = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/tenant`, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setTenant(data.tenant);
      setNameValue(data.tenant?.name || '');
    } catch (e) {
      console.error('Failed to fetch tenant:', e);
      toast.error('Failed to load organization details');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchUsers = useCallback(async () => {
    try {
      setUsersLoading(true);
      const res = await fetch(`${API}/tenant/users`, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setUsers(data.users || []);
    } catch (e) {
      console.error('Failed to fetch users:', e);
    } finally {
      setUsersLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTenant();
    fetchUsers();
  }, [fetchTenant, fetchUsers]);

  const handleSaveName = async () => {
    if (!nameValue.trim() || nameValue === tenant?.name) {
      setEditingName(false);
      return;
    }
    try {
      setSaving(true);
      const res = await fetch(`${API}/tenant`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name: nameValue.trim() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setTenant(data.tenant);
      setEditingName(false);
      toast.success('Organization name updated');
    } catch (e) {
      toast.error(e.message || 'Failed to update name');
    } finally {
      setSaving(false);
    }
  };

  const handleInvite = async (e) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    try {
      setInviting(true);
      setLastInviteToken(null);
      const res = await fetch(`${API}/tenant/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: inviteEmail.trim(), role: inviteRole }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setLastInviteToken(data.invitation?.token);
      toast.success(`Invitation sent to ${inviteEmail}`);
      setInviteEmail('');
      setInviteRole('viewer');
      fetchUsers();
      fetchTenant();
    } catch (e) {
      toast.error(e.message || 'Failed to send invitation');
    } finally {
      setInviting(false);
    }
  };

  const copyToken = async (token) => {
    try {
      await navigator.clipboard.writeText(token);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } catch {
      toast.error('Failed to copy');
    }
  };

  const formatDate = (d) => {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  };

  const formatDateTime = (d) => {
    if (!d) return 'Never';
    return new Date(d).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="w-5 h-5 animate-spin text-accent" />
        <span className="ml-2 text-sm text-nhi-dim">Loading organization...</span>
      </div>
    );
  }

  const planCfg = PLAN_BADGES[tenant?.plan] || PLAN_BADGES.trial;

  const usageItems = [
    { label: 'Users',      value: tenant?.user_count || 0,      max: tenant?.max_users || 10,      icon: Users },
    { label: 'Workloads',  value: tenant?.workload_count || 0,  max: tenant?.max_workloads || 1000, icon: Shield },
    { label: 'Connectors', value: tenant?.connector_count || 0, max: tenant?.max_connectors || 20,  icon: Globe },
    { label: 'Policies',   value: tenant?.policy_count || 0,    max: tenant?.max_policies || 500,   icon: Settings },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-nhi-text">Organization Settings</h2>
          <p className="text-xs text-nhi-dim mt-0.5">Manage your organization, team members, and usage limits</p>
        </div>
        <button
          onClick={() => { fetchTenant(); fetchUsers(); }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-nhi-dim hover:text-nhi-text transition-colors"
          style={{ background: 'var(--bg-subtle)' }}
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* ── Section A: Organization Info ── */}
      <SectionCard title="Organization Info" icon={Building2}>
        <div className="space-y-0">
          {/* Name (editable for admin) */}
          <div className="flex items-center justify-between py-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
            <span className="text-xs font-medium text-nhi-dim">Name</span>
            {editingName ? (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={nameValue}
                  onChange={(e) => setNameValue(e.target.value)}
                  className="nhi-input px-2 py-1 text-xs w-48"
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSaveName();
                    if (e.key === 'Escape') { setEditingName(false); setNameValue(tenant?.name || ''); }
                  }}
                />
                <button
                  onClick={handleSaveName}
                  disabled={saving}
                  className="p-1 rounded-md text-emerald-400 hover:bg-emerald-500/10 transition-colors"
                >
                  {saving ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => { setEditingName(false); setNameValue(tenant?.name || ''); }}
                  className="p-1 rounded-md text-nhi-ghost hover:text-red-400 hover:bg-red-500/10 transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-nhi-text">{tenant?.name || '—'}</span>
                {isAdmin && (
                  <button
                    onClick={() => setEditingName(true)}
                    className="p-1 rounded-md text-nhi-ghost hover:text-accent hover:bg-accent/10 transition-colors"
                    title="Edit name"
                  >
                    <Edit2 className="w-3 h-3" />
                  </button>
                )}
              </div>
            )}
          </div>

          <InfoRow label="Slug" value={tenant?.slug} mono />
          <InfoRow label="Plan" value={
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${planCfg.bg} ${planCfg.border} ${planCfg.text} border`}>
              {planCfg.label}
            </span>
          } />
          <InfoRow label="Data Region" value={
            REGIONS.find(r => r.value === tenant?.data_region)?.label || tenant?.data_region || '—'
          } />
          <InfoRow label="Strict Data Residency" value={
            tenant?.data_residency_strict ? (
              <span className="text-emerald-400 font-semibold">Enabled</span>
            ) : (
              <span className="text-nhi-ghost">Disabled</span>
            )
          } />
          <InfoRow label="Created" value={formatDate(tenant?.created_at)} />
        </div>
      </SectionCard>

      {/* ── Section B: Usage & Limits ── */}
      <SectionCard title="Usage & Limits" icon={BarChart3}>
        <div className="grid grid-cols-2 gap-4">
          {usageItems.map((item) => {
            const Icon = item.icon;
            const pct = item.max > 0 ? Math.round((item.value / item.max) * 100) : 0;
            return (
              <div
                key={item.label}
                className="rounded-lg border p-4"
                style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-nhi-dim" strokeWidth={1.5} />
                    <span className="text-xs font-semibold text-nhi-text">{item.label}</span>
                  </div>
                  <span className="text-[10px] font-mono text-nhi-faint">{pct}%</span>
                </div>
                <div className="mb-2">
                  <ProgressBar value={item.value} max={item.max} />
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="text-lg font-bold text-nhi-text font-mono">{item.value.toLocaleString()}</span>
                  <span className="text-xs text-nhi-ghost">/ {item.max.toLocaleString()}</span>
                </div>
              </div>
            );
          })}
        </div>
      </SectionCard>

      {/* ── Section C: Team Members ── */}
      <SectionCard title="Team Members" icon={Users}>
        {/* Invite button */}
        {isAdmin && (
          <div className="mb-4">
            {!showInvite ? (
              <button
                onClick={() => setShowInvite(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold text-accent border border-accent/20 bg-accent/[0.06] hover:bg-accent/[0.12] transition-colors"
              >
                <UserPlus className="w-3.5 h-3.5" />
                Invite User
              </button>
            ) : (
              <form onSubmit={handleInvite} className="rounded-lg border p-4 space-y-3" style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}>
                <div className="flex items-center gap-2 mb-2">
                  <Mail className="w-4 h-4 text-accent" />
                  <span className="text-xs font-bold text-nhi-text">Invite a Team Member</span>
                </div>
                <div className="flex items-center gap-3">
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="colleague@company.com"
                    className="nhi-input flex-1 px-3 py-2 text-xs"
                    required
                    autoFocus
                  />
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    className="nhi-input px-3 py-2 text-xs w-32"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="operator">Operator</option>
                    <option value="admin">Admin</option>
                  </select>
                  <button
                    type="submit"
                    disabled={inviting}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold text-white bg-accent hover:bg-accent-dim transition-colors disabled:opacity-50"
                  >
                    {inviting ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <UserPlus className="w-3.5 h-3.5" />}
                    Send
                  </button>
                  <button
                    type="button"
                    onClick={() => { setShowInvite(false); setLastInviteToken(null); }}
                    className="p-2 rounded-lg text-nhi-ghost hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Show invitation token (dev mode) */}
                {lastInviteToken && (
                  <div className="rounded-lg border p-3 mt-2" style={{ background: 'var(--bg-accent-soft)', borderColor: 'var(--border)' }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-bold text-nhi-dim uppercase">Invite Token (dev mode)</span>
                      <button
                        onClick={() => copyToken(lastInviteToken)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-accent hover:bg-accent/10 transition-colors"
                      >
                        {copiedToken ? <CheckCircle className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        {copiedToken ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <code className="text-[10px] font-mono text-nhi-faint break-all">{lastInviteToken}</code>
                  </div>
                )}
              </form>
            )}
          </div>
        )}

        {/* Users table */}
        {usersLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader className="w-4 h-4 animate-spin text-accent" />
            <span className="ml-2 text-xs text-nhi-dim">Loading team...</span>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--border)' }}>
            <table className="w-full">
              <thead>
                <tr style={{ background: 'var(--surface-1)' }}>
                  <th className="text-left text-[10px] font-bold text-nhi-dim uppercase px-4 py-2.5 tracking-wider">User</th>
                  <th className="text-left text-[10px] font-bold text-nhi-dim uppercase px-4 py-2.5 tracking-wider">Role</th>
                  <th className="text-left text-[10px] font-bold text-nhi-dim uppercase px-4 py-2.5 tracking-wider">Last Login</th>
                  <th className="text-left text-[10px] font-bold text-nhi-dim uppercase px-4 py-2.5 tracking-wider">Joined</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => {
                  const RoleIcon = ROLE_ICONS[u.role] || Eye;
                  const roleColor = ROLE_COLORS[u.role] || ROLE_COLORS.viewer;
                  const initials = u.name
                    ? u.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
                    : u.email?.[0]?.toUpperCase() || '?';
                  const isCurrentUser = u.id === user?.id;
                  return (
                    <tr
                      key={u.id}
                      style={{ borderTop: i > 0 ? '1px solid var(--border)' : 'none' }}
                      className="hover:bg-surface-3/30 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-7 h-7 rounded-full bg-accent/[0.15] text-accent-light flex items-center justify-center shrink-0">
                            <span className="text-[10px] font-bold">{initials}</span>
                          </div>
                          <div>
                            <div className="text-xs font-semibold text-nhi-text flex items-center gap-1.5">
                              {u.name || 'Unnamed'}
                              {isCurrentUser && (
                                <span className="text-[9px] font-medium text-nhi-faint px-1.5 py-0.5 rounded-full" style={{ background: 'var(--bg-accent-soft)' }}>you</span>
                              )}
                            </div>
                            <div className="text-[10px] text-nhi-ghost font-mono">{u.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${roleColor}`}>
                          <RoleIcon className="w-3 h-3" />
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-xs text-nhi-dim">
                          <Clock className="w-3 h-3" />
                          {formatDateTime(u.last_login)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs text-nhi-dim">{formatDate(u.created_at)}</span>
                      </td>
                    </tr>
                  );
                })}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={4} className="text-center py-8 text-xs text-nhi-ghost">
                      No team members found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-3 text-[10px] text-nhi-ghost">
          {users.length} member{users.length !== 1 ? 's' : ''} of {tenant?.max_users || 10} allowed on {planCfg.label} plan
        </div>
      </SectionCard>
    </div>
  );
}
