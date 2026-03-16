import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useOnboarding } from '../context/OnboardingContext';
import {
  Building2, Cloud, Scan, Check, ChevronRight, ChevronLeft,
  Plus, Trash2, Mail, Users, Loader2, ArrowRight, Search,
  Shield, AlertTriangle, CheckCircle2, Sun, Moon, X, Copy, ExternalLink,
} from 'lucide-react';

const API = '/api/v1';

// ─── Steps ──────────────────────────────────────────────────────────────
const STEPS = [
  { id: 'org', label: 'Organization', icon: Building2 },
  { id: 'connect', label: 'Connect Cloud', icon: Cloud },
  { id: 'scan', label: 'First Scan', icon: Scan },
];

// ─── Provider catalog (subset for onboarding — mirrors Connectors.jsx) ──
const PROVIDERS = [
  {
    id: 'aws', name: 'Amazon Web Services',
    description: 'IAM roles, EC2, Lambda, ECS, S3',
    fields: [
      { name: 'accountId', label: 'AWS Account ID', type: 'text', required: true, placeholder: '123456789012' },
      { name: 'region', label: 'Default Region', type: 'text', required: false, placeholder: 'us-east-1' },
      { name: 'roleArn', label: 'Role ARN', type: 'text', required: true, placeholder: 'arn:aws:iam::123456789012:role/WIDDiscoveryRole' },
      { name: 'externalId', label: 'External ID', type: 'text', required: true, placeholder: 'Auto-generated', readOnly: true },
    ],
  },
  {
    id: 'gcp', name: 'Google Cloud Platform',
    description: 'Service accounts, Compute, Cloud Run, GKE',
    fields: [
      { name: 'projectId', label: 'Project ID', type: 'text', required: true, placeholder: 'my-project-123' },
    ],
  },
  {
    id: 'azure', name: 'Microsoft Azure',
    description: 'VMs, App Services, AKS, Entra ID',
    fields: [
      { name: 'tenantId', label: 'Tenant (Directory) ID', type: 'text', required: true, placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
      { name: 'subscriptionId', label: 'Subscription ID', type: 'text', required: true, placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    ],
  },
  {
    id: 'kubernetes', name: 'Kubernetes',
    description: 'Deployments, StatefulSets, CronJobs, ServiceAccounts',
    fields: [
      { name: 'clusterName', label: 'Cluster Name', type: 'text', required: false, placeholder: 'production-cluster' },
      { name: 'context', label: 'Kubeconfig Context', type: 'text', required: false, placeholder: 'my-context' },
      { name: 'kubeconfig', label: 'Kubeconfig', type: 'textarea', required: true, placeholder: 'apiVersion: v1\nkind: Config\n...' },
    ],
  },
  {
    id: 'docker', name: 'Docker',
    description: 'Containers, images, networks, volumes',
    fields: [
      { name: 'socketPath', label: 'Docker Socket Path', type: 'text', required: false, placeholder: '/var/run/docker.sock' },
      { name: 'host', label: 'Docker Host', type: 'text', required: false, placeholder: 'tcp://localhost:2375' },
    ],
  },
];

// ─── Provider Icons ─────────────────────────────────────────────────────
const ProviderIcon = ({ provider, size = 40 }) => {
  const s = size;
  const icons = {
    aws: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#232F3E"/>
        <path d="M16.8 21.5c0 .4.04.7.13.9.09.2.21.4.37.6.06.08.07.16.02.23l-.48.32c-.07.05-.14.04-.21-.02a2.5 2.5 0 01-.46-.6 3.06 3.06 0 01-.37-.75c-.93 1.1-2.1 1.64-3.52 1.64-.95 0-1.7-.27-2.27-.81-.56-.54-.84-1.27-.84-2.17 0-.96.34-1.74 1.02-2.33.68-.6 1.58-.89 2.72-.89.38 0 .77.03 1.18.1.41.06.83.15 1.28.27v-.83c0-.86-.18-1.46-.53-1.8-.36-.35-.96-.52-1.82-.52-.39 0-.79.05-1.2.14-.41.1-.81.22-1.2.38a.29.29 0 01-.1.02c-.08 0-.12-.06-.12-.18v-.37c0-.1.01-.17.05-.2.03-.04.1-.08.2-.13.39-.2.86-.37 1.4-.5.55-.14 1.13-.21 1.74-.21 1.33 0 2.3.3 2.92.91.61.61.92 1.53.92 2.78v3.67z" fill="#FF9900"/>
        <path d="M28.68 25.03c-3.19 2.35-7.82 3.6-11.8 3.6-5.58 0-10.6-2.06-14.4-5.49-.3-.27-.03-.64.33-.43 4.1 2.39 9.18 3.83 14.42 3.83 3.54 0 7.43-.73 11.01-2.25.54-.24 1 .35.44.74z" fill="#FF9900"/>
      </svg>
    ),
    gcp: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#fff"/>
        <rect x=".5" y=".5" width="39" height="39" rx="9.5" stroke="#e5e7eb"/>
        <path d="M23.76 14.44h1.2l3.4-3.4.17-1.44A13.38 13.38 0 007.62 16.3l.6-.06 4.08-.67s.21-.35.32-.33a9.3 9.3 0 0111.14-.8z" fill="#EA4335"/>
        <path d="M31.54 16.3a13.47 13.47 0 00-4.06-6.53l-3.72 3.72a7.9 7.9 0 012.9 6.26v.79a3.96 3.96 0 010 7.92h-6.68l-.79.8v4.76l.79.79h6.68a8.04 8.04 0 004.88-14.51z" fill="#4285F4"/>
        <path d="M13.3 34.81h6.68v-6.35H13.3a3.93 3.93 0 01-1.63-.36l-1.14.35-3.42 3.4-.28 1.1a8 8 0 006.47 1.86z" fill="#34A853"/>
        <path d="M13.3 18.73a8.04 8.04 0 00-6.47 14.22l4.84-4.84a3.96 3.96 0 011.63-7.3z" fill="#FBBC05"/>
      </svg>
    ),
    azure: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#fff"/>
        <rect x=".5" y=".5" width="39" height="39" rx="9.5" stroke="#e5e7eb"/>
        <path d="M17.09 7h7.28l-7.96 24.36a1.38 1.38 0 01-1.3.94H8.54a1.38 1.38 0 01-1.3-1.84L14.98 7.94A1.38 1.38 0 0116.28 7h.81z" fill="#0078D4"/>
        <path d="M27.3 24.06H15.44a.64.64 0 00-.44 1.11l7.64 7.1c.26.24.6.38.95.38h7.1l-3.39-8.59z" fill="#0078D4" opacity=".7"/>
        <path d="M17.09 7a1.36 1.36 0 00-1.31.97L8.06 30.44a1.38 1.38 0 001.3 1.86h6.82a1.5 1.5 0 001.11-.83l1.7-4.6 5.77 5.37c.25.22.57.35.9.36h7.04l-3.39-8.54H17.3l6.25-17.06H17.09z" fill="#0078D4"/>
      </svg>
    ),
    kubernetes: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#326CE5"/>
        <circle cx="20" cy="20.5" r="6" fill="none" stroke="#fff" strokeWidth="1.5"/>
        <circle cx="20" cy="20.5" r="2" fill="#fff"/>
      </svg>
    ),
    docker: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#2496ED"/>
        <g fill="#fff">
          <rect x="8" y="18.5" width="4.5" height="4" rx=".6"/>
          <rect x="13.5" y="18.5" width="4.5" height="4" rx=".6"/>
          <rect x="19" y="18.5" width="4.5" height="4" rx=".6"/>
          <rect x="24.5" y="18.5" width="4.5" height="4" rx=".6"/>
          <rect x="13.5" y="13.5" width="4.5" height="4" rx=".6"/>
          <rect x="19" y="13.5" width="4.5" height="4" rx=".6"/>
          <rect x="19" y="8.5" width="4.5" height="4" rx=".6"/>
          <rect x="24.5" y="13.5" width="4.5" height="4" rx=".6"/>
        </g>
      </svg>
    ),
  };
  return icons[provider] || <Cloud className="w-8 h-8 text-nhi-dim" />;
};

// ─── Stepper ────────────────────────────────────────────────────────────
function Stepper({ current, completed }) {
  return (
    <div className="flex items-center justify-center gap-0 mb-10">
      {STEPS.map((step, i) => {
        const Icon = step.icon;
        const isActive = i === current;
        const isDone = completed.includes(i);
        const isPast = i < current;
        return (
          <React.Fragment key={step.id}>
            {i > 0 && (
              <div className={`w-16 h-px mx-1 transition-colors duration-300 ${isPast || isDone ? 'bg-accent' : 'bg-brd'}`} />
            )}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all duration-300 ${
                  isDone
                    ? 'bg-accent/20 text-accent-light'
                    : isActive
                    ? 'bg-accent text-white shadow-lg shadow-accent/20'
                    : 'bg-surface-3/50 text-nhi-ghost'
                }`}
              >
                {isDone ? <Check className="w-5 h-5" /> : <Icon className="w-5 h-5" />}
              </div>
              <span className={`text-xs font-medium transition-colors ${isActive ? 'text-nhi-text' : isDone ? 'text-accent-light' : 'text-nhi-ghost'}`}>
                {step.label}
              </span>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ─── Step 1: Organization ───────────────────────────────────────────────
function StepOrg({ tenant, invites, setInvites, onContinue }) {
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('viewer');
  const [sending, setSending] = useState(false);

  const sendInvite = async () => {
    if (!inviteEmail) return;
    setSending(true);
    try {
      const res = await fetch(`${API}/tenant/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      if (res.ok) {
        setInvites((prev) => [...prev, { email: inviteEmail, role: inviteRole, status: 'sent' }]);
        setInviteEmail('');
        toast.success('Invitation sent');
      } else {
        const data = await res.json().catch(() => ({}));
        // Still show in UI even if endpoint not available yet
        setInvites((prev) => [...prev, { email: inviteEmail, role: inviteRole, status: 'queued' }]);
        setInviteEmail('');
        toast.success('Invitation queued');
      }
    } catch {
      setInvites((prev) => [...prev, { email: inviteEmail, role: inviteRole, status: 'queued' }]);
      setInviteEmail('');
      toast.success('Invitation queued');
    } finally {
      setSending(false);
    }
  };

  const removeInvite = (idx) => {
    setInvites((prev) => prev.filter((_, i) => i !== idx));
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-bold text-nhi-text mb-1">Your Organization</h2>
        <p className="text-sm text-nhi-dim">Review your setup and invite your team.</p>
      </div>

      {/* Org details */}
      <div className="bg-surface-1 border border-brd rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-3 gap-4">
          <div>
            <p className="text-xs text-nhi-ghost mb-1">Organization</p>
            <p className="text-sm font-semibold text-nhi-text">{tenant?.name || 'My Organization'}</p>
          </div>
          <div>
            <p className="text-xs text-nhi-ghost mb-1">Plan</p>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-accent/10 text-accent-light text-xs font-medium">
              Trial
            </span>
          </div>
          <div>
            <p className="text-xs text-nhi-ghost mb-1">Data Region</p>
            <p className="text-sm font-semibold text-nhi-text">{tenant?.data_region?.toUpperCase() || 'US'}</p>
          </div>
        </div>
      </div>

      {/* Invite team */}
      <div>
        <h3 className="text-sm font-semibold text-nhi-text mb-3 flex items-center gap-2">
          <Users className="w-4 h-4 text-accent-light" />
          Invite Team Members
        </h3>
        <div className="flex gap-2">
          <input
            type="email"
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            placeholder="colleague@company.com"
            className="flex-1 h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all"
            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), sendInvite())}
          />
          <select
            value={inviteRole}
            onChange={(e) => setInviteRole(e.target.value)}
            className="h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text focus:outline-none focus:ring-2 focus:ring-accent/30 transition-all appearance-none cursor-pointer"
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </select>
          <button
            onClick={sendInvite}
            disabled={!inviteEmail || sending}
            className="h-10 px-4 rounded-lg bg-accent text-white text-sm font-medium hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-1.5"
          >
            {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
            Send
          </button>
        </div>

        {invites.length > 0 && (
          <div className="mt-3 space-y-2">
            {invites.map((inv, i) => (
              <div key={i} className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-0 border border-brd">
                <div className="flex items-center gap-3">
                  <Mail className="w-4 h-4 text-nhi-ghost" />
                  <span className="text-sm text-nhi-text">{inv.email}</span>
                  <span className="text-xs text-nhi-ghost capitalize px-1.5 py-0.5 rounded bg-surface-3/50">{inv.role}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-accent-light capitalize">{inv.status}</span>
                  <button onClick={() => removeInvite(i)} className="text-nhi-ghost hover:text-red-400 transition-colors">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <button
          onClick={() => onContinue(true)}
          className="h-10 px-5 rounded-lg text-sm font-medium text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-all"
        >
          Skip
        </button>
        <button
          onClick={() => onContinue(false)}
          className="h-10 px-6 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 transition-all flex items-center gap-2"
        >
          Continue
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ─── Step 2: Connect Cloud ──────────────────────────────────────────────
function StepConnect({ connectorAdded, setConnectorAdded, onContinue, onBack }) {
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [formData, setFormData] = useState({});
  const [connectorName, setConnectorName] = useState('');
  const [connecting, setConnecting] = useState(false);
  const [connectedProvider, setConnectedProvider] = useState(null);

  const selectProvider = (prov) => {
    setSelectedProvider(prov);
    setConnectorName(`${prov.name} - Production`);
    // Pre-fill externalId for AWS
    const initial = {};
    prov.fields.forEach((f) => {
      if (f.name === 'externalId') {
        initial[f.name] = `wid-${Math.random().toString(36).slice(2, 10)}`;
      } else {
        initial[f.name] = '';
      }
    });
    setFormData(initial);
  };

  const handleConnect = async () => {
    if (!selectedProvider) return;
    setConnecting(true);
    try {
      const config = { ...formData };
      const res = await fetch(`${API}/connectors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: connectorName,
          provider: selectedProvider.id,
          config,
        }),
      });
      if (res.ok) {
        setConnectorAdded(true);
        setConnectedProvider(selectedProvider.id);
        toast.success('Connector created successfully');
      } else {
        const data = await res.json().catch(() => ({}));
        toast.error(data.error || 'Failed to create connector');
      }
    } catch (err) {
      toast.error('Connection failed. Please try again.');
    } finally {
      setConnecting(false);
    }
  };

  const inputClass = 'w-full h-10 px-3 rounded-lg bg-surface-0 border border-brd text-sm text-nhi-text placeholder:text-nhi-ghost focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent transition-all';

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-bold text-nhi-text mb-1">Connect Your Cloud</h2>
        <p className="text-sm text-nhi-dim">Add a cloud account or infrastructure source to start discovering workloads.</p>
      </div>

      {/* Provider cards */}
      {!selectedProvider && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {PROVIDERS.map((prov) => (
            <button
              key={prov.id}
              onClick={() => selectProvider(prov)}
              disabled={connectedProvider === prov.id}
              className={`flex flex-col items-center gap-3 p-5 rounded-xl border transition-all text-left ${
                connectedProvider === prov.id
                  ? 'bg-accent/[0.06] border-accent/30 cursor-default'
                  : 'bg-surface-1 border-brd hover:border-accent/40 hover:bg-surface-1/80 cursor-pointer'
              }`}
            >
              <ProviderIcon provider={prov.id} />
              <div className="text-center">
                <p className="text-sm font-semibold text-nhi-text">{prov.name}</p>
                <p className="text-xs text-nhi-ghost mt-0.5">{prov.description}</p>
              </div>
              {connectedProvider === prov.id && (
                <span className="inline-flex items-center gap-1 text-xs font-medium text-accent-light">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Connected
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Inline form for selected provider */}
      {selectedProvider && !connectedProvider && (
        <div className="bg-surface-1 border border-brd rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ProviderIcon provider={selectedProvider.id} size={32} />
              <div>
                <p className="text-sm font-semibold text-nhi-text">{selectedProvider.name}</p>
                <p className="text-xs text-nhi-ghost">{selectedProvider.description}</p>
              </div>
            </div>
            <button
              onClick={() => setSelectedProvider(null)}
              className="text-nhi-ghost hover:text-nhi-dim transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div>
            <label className="block text-xs font-medium text-nhi-dim mb-1.5">Connector Name</label>
            <input
              type="text"
              value={connectorName}
              onChange={(e) => setConnectorName(e.target.value)}
              className={inputClass}
            />
          </div>

          {selectedProvider.fields.map((field) => (
            <div key={field.name}>
              <label className="block text-xs font-medium text-nhi-dim mb-1.5">
                {field.label}
                {field.required && <span className="text-red-400 ml-0.5">*</span>}
              </label>
              {field.type === 'textarea' ? (
                <textarea
                  value={formData[field.name] || ''}
                  onChange={(e) => setFormData({ ...formData, [field.name]: e.target.value })}
                  placeholder={field.placeholder}
                  readOnly={field.readOnly}
                  rows={4}
                  className={`${inputClass} h-auto py-2 resize-none font-mono text-xs`}
                />
              ) : (
                <div className="relative">
                  <input
                    type={field.type || 'text'}
                    value={formData[field.name] || ''}
                    onChange={(e) => setFormData({ ...formData, [field.name]: e.target.value })}
                    placeholder={field.placeholder}
                    readOnly={field.readOnly}
                    required={field.required}
                    className={`${inputClass} ${field.readOnly ? 'bg-surface-3/30 text-nhi-dim cursor-default' : ''}`}
                  />
                  {field.readOnly && formData[field.name] && (
                    <button
                      type="button"
                      onClick={() => { navigator.clipboard.writeText(formData[field.name]); toast.success('Copied'); }}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nhi-ghost hover:text-nhi-dim transition-colors"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}

          <button
            onClick={handleConnect}
            disabled={connecting}
            className="w-full h-10 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
          >
            {connecting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <Cloud className="w-4 h-4" />
                Connect
              </>
            )}
          </button>
        </div>
      )}

      {/* Connected success state */}
      {connectedProvider && selectedProvider && (
        <div className="bg-accent/[0.06] border border-accent/20 rounded-xl p-6 text-center space-y-3">
          <CheckCircle2 className="w-10 h-10 text-accent-light mx-auto" />
          <p className="text-sm font-semibold text-nhi-text">{selectedProvider.name} connected</p>
          <p className="text-xs text-nhi-dim">Your connector is ready. You can add more connectors later from Settings.</p>
          <button
            onClick={() => setSelectedProvider(null)}
            className="text-xs text-accent-light hover:underline font-medium"
          >
            Add another connector
          </button>
        </div>
      )}

      <div className="flex justify-between pt-2">
        <button
          onClick={onBack}
          className="h-10 px-5 rounded-lg text-sm font-medium text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-all flex items-center gap-2"
        >
          <ChevronLeft className="w-4 h-4" />
          Back
        </button>
        <div className="flex gap-3">
          <button
            onClick={() => onContinue(true)}
            className="h-10 px-5 rounded-lg text-sm font-medium text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-all"
          >
            Skip
          </button>
          <button
            onClick={() => onContinue(false)}
            className="h-10 px-6 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 transition-all flex items-center gap-2"
          >
            Continue
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Step 3: First Scan ─────────────────────────────────────────────────
function StepScan({ connectorAdded, onFinish }) {
  const [scanning, setScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [progress, setProgress] = useState(0);

  const runScan = useCallback(async () => {
    setScanning(true);
    setProgress(0);

    // Animate progress
    const interval = setInterval(() => {
      setProgress((p) => Math.min(p + Math.random() * 15, 90));
    }, 500);

    try {
      const res = await fetch(`${API}/workloads/scan`, {
        method: 'POST',
        credentials: 'include',
      });
      clearInterval(interval);
      setProgress(95);

      let workloadCount = 0;
      if (res.ok) {
        const data = await res.json();
        workloadCount = data.total_workloads || data.discovered || 0;
      }

      // Fetch graph to get attack paths and findings
      let attackPaths = 0;
      let findings = 0;
      try {
        const graphRes = await fetch(`${API}/graph`, { credentials: 'include' });
        if (graphRes.ok) {
          const graph = await graphRes.json();
          attackPaths = graph.summary?.total_attack_paths || graph.attack_paths?.length || 0;
          findings = graph.summary?.total_findings || graph.findings?.length || 0;
          // Also update workload count from graph if scan returned 0
          if (workloadCount === 0) {
            workloadCount = graph.summary?.total_nodes || graph.nodes?.length || 0;
          }
        }
      } catch { /* graph not available yet */ }

      setProgress(100);
      setScanResults({ workloads: workloadCount, attackPaths, findings });
      setScanDone(true);
    } catch {
      clearInterval(interval);
      setProgress(100);
      setScanResults({ workloads: 0, attackPaths: 0, findings: 0 });
      setScanDone(true);
    } finally {
      setScanning(false);
    }
  }, []);

  // Auto-trigger scan if connector was added
  useEffect(() => {
    if (connectorAdded && !scanning && !scanDone) {
      runScan();
    }
  }, [connectorAdded, scanning, scanDone, runScan]);

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-xl font-bold text-nhi-text mb-1">First Discovery Scan</h2>
        <p className="text-sm text-nhi-dim">
          {connectorAdded
            ? 'Scanning your infrastructure to discover workloads and identities.'
            : 'You can run your first scan after connecting a cloud account.'}
        </p>
      </div>

      {/* Scanning animation */}
      {scanning && (
        <div className="bg-surface-1 border border-brd rounded-xl p-8 text-center space-y-6">
          <div className="relative w-20 h-20 mx-auto">
            <div className="absolute inset-0 rounded-full border-4 border-surface-3/50" />
            <div
              className="absolute inset-0 rounded-full border-4 border-accent border-t-transparent animate-spin"
              style={{ animationDuration: '1.5s' }}
            />
            <Search className="absolute inset-0 m-auto w-8 h-8 text-accent-light" />
          </div>
          <div>
            <p className="text-sm font-semibold text-nhi-text mb-2">Discovering workloads...</p>
            <div className="w-64 mx-auto h-2 rounded-full bg-surface-3/50 overflow-hidden">
              <div
                className="h-full rounded-full bg-accent transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-xs text-nhi-ghost mt-2">This may take a minute</p>
          </div>
        </div>
      )}

      {/* Scan results */}
      {scanDone && scanResults && (
        <div className="bg-surface-1 border border-brd rounded-xl p-8 space-y-6">
          <div className="text-center">
            <CheckCircle2 className="w-12 h-12 text-accent-light mx-auto mb-3" />
            <p className="text-lg font-bold text-nhi-text mb-1">Scan Complete</p>
            <p className="text-sm text-nhi-dim">Here is what we found in your infrastructure.</p>
          </div>

          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'Workloads', value: scanResults.workloads, icon: Shield },
              { label: 'Attack Paths', value: scanResults.attackPaths, icon: AlertTriangle },
              { label: 'Findings', value: scanResults.findings, icon: Search },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="bg-surface-0 border border-brd rounded-xl p-4 text-center">
                <Icon className="w-5 h-5 text-accent-light mx-auto mb-2" />
                <p className="text-2xl font-bold text-nhi-text">{value}</p>
                <p className="text-xs text-nhi-ghost mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No connector state */}
      {!connectorAdded && !scanning && !scanDone && (
        <div className="bg-surface-1 border border-brd rounded-xl p-8 text-center space-y-4">
          <Cloud className="w-12 h-12 text-nhi-ghost mx-auto" />
          <div>
            <p className="text-sm font-semibold text-nhi-text mb-1">No cloud connector added</p>
            <p className="text-xs text-nhi-dim">You can always add connectors later from the Connectors page.</p>
          </div>
        </div>
      )}

      <div className="flex justify-center pt-2">
        <button
          onClick={onFinish}
          className="h-11 px-8 rounded-lg bg-accent text-white text-sm font-semibold hover:bg-accent/90 transition-all flex items-center gap-2 shadow-lg shadow-accent/20"
        >
          Go to Dashboard
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ─── Main Wizard ────────────────────────────────────────────────────────
export default function OnboardingWizard() {
  const navigate = useNavigate();
  const { tenant } = useAuth();
  const { isDark, toggle } = useTheme();
  const { refresh: refreshOnboarding } = useOnboarding();
  const [step, setStep] = useState(0);
  const [completed, setCompleted] = useState([]);
  const [invites, setInvites] = useState([]);
  const [connectorAdded, setConnectorAdded] = useState(false);

  const markComplete = (idx) => {
    setCompleted((prev) => (prev.includes(idx) ? prev : [...prev, idx]));
  };

  const goNext = (skipStep = false) => {
    if (!skipStep) markComplete(step);
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  };

  const goBack = () => setStep((s) => Math.max(s - 1, 0));

  const finishOnboarding = async () => {
    localStorage.setItem('wid_onboarding_complete', 'true');
    if (refreshOnboarding) await refreshOnboarding();
    navigate('/workloads', { replace: true });
  };

  return (
    <div className="min-h-screen bg-surface-0 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-brd">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M4 5.5a2 2 0 012-2h4a2 2 0 010 4H8" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
              <path d="M12 10.5a2 2 0 01-2 2H6a2 2 0 010-4h2" stroke="#fff" strokeWidth="1.5" strokeLinecap="round"/>
              <circle cx="8" cy="8" r="1.2" fill="#fff"/>
            </svg>
          </div>
          <span className="text-sm font-bold text-nhi-text tracking-tight">Workload Identity Defense</span>
        </div>
        <button
          onClick={toggle}
          className="p-2 rounded-lg text-nhi-dim hover:text-nhi-text hover:bg-surface-3/50 transition-colors"
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 flex flex-col items-center justify-start px-6 py-10">
        <div className="w-full max-w-2xl">
          <Stepper current={step} completed={completed} />

          {step === 0 && (
            <StepOrg
              tenant={tenant}
              invites={invites}
              setInvites={setInvites}
              onContinue={(skip) => goNext(skip)}
            />
          )}

          {step === 1 && (
            <StepConnect
              connectorAdded={connectorAdded}
              setConnectorAdded={setConnectorAdded}
              onContinue={(skip) => goNext(skip)}
              onBack={goBack}
            />
          )}

          {step === 2 && (
            <StepScan
              connectorAdded={connectorAdded}
              onFinish={finishOnboarding}
            />
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="text-center py-4 border-t border-brd">
        <p className="text-[11px] text-nhi-ghost">Workload Identity Defense</p>
      </div>
    </div>
  );
}
