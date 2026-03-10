import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useOnboarding } from '../context/OnboardingContext';
import {
  Plug,
  Plus,
  RefreshCw,
  Trash2,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  ChevronRight,
  ChevronLeft,
  Shield,
  Eye,
  Zap,
  Cloud,
  Server,
  AlertTriangle,
  ExternalLink,
  Copy,
  X,
} from 'lucide-react';

const API = '/api/v1';

// ─── Fallback provider catalog (static, same as backend) ────────────────
// Fields with phase:'context' render first, then setup guide, then phase:'credential' fields
const FALLBACK_PROVIDERS = [
  {
    id: 'aws', name: 'Amazon Web Services', icon: 'aws',
    description: 'Discover IAM users, roles, EC2 instances, Lambda functions, ECS tasks, S3 buckets, and more.',
    credentialFields: [
      { name: 'accountId', label: 'AWS Account ID', type: 'text', required: true, placeholder: '123456789012', phase: 'context' },
      { name: 'region', label: 'Default Region', type: 'text', required: false, placeholder: 'us-east-1', phase: 'context' },
      { name: 'roleArn', label: 'Role ARN', type: 'text', required: true, placeholder: 'arn:aws:iam::123456789012:role/WIDDiscoveryRole' },
      { name: 'externalId', label: 'External ID', type: 'text', required: true, placeholder: 'Auto-generated — copy this into your role trust policy', readOnly: true },
    ],
    setupGuide: {
      title: 'Create a read-only IAM role for WID',
      usesAccountId: true,
      steps: [
        { label: 'Create the WID discovery role with a trust policy', command: 'aws iam create-role \\\n  --role-name WIDDiscoveryRole \\\n  --description "Read-only role for WID workload identity discovery" \\\n  --assume-role-policy-document \'{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "AWS": "arn:aws:iam::265663183174:root"\n      },\n      "Action": "sts:AssumeRole",\n      "Condition": {\n        "StringEquals": {\n          "sts:ExternalId": "{{externalId}}"\n        }\n      }\n    }\n  ]\n}\'' },
        { label: 'Attach SecurityAudit policy (read-only access to all AWS services)', command: 'aws iam attach-role-policy \\\n  --role-name WIDDiscoveryRole \\\n  --policy-arn arn:aws:iam::aws:policy/SecurityAudit' },
        { label: 'Attach ViewOnlyAccess policy (read-only for additional resources)', command: 'aws iam attach-role-policy \\\n  --role-name WIDDiscoveryRole \\\n  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess' },
      ],
      note: 'This creates a read-only IAM role in your AWS account that WID assumes to discover workloads. WID never stores long-lived AWS credentials — it uses short-lived STS session tokens via role assumption. The External ID prevents confused deputy attacks.',
    },
  },
  {
    id: 'gcp', name: 'Google Cloud Platform', icon: 'gcp',
    description: 'Discover service accounts, Compute Engine instances, Cloud Run services, GKE workloads, and IAM bindings.',
    credentialFields: [
      { name: 'projectId', label: 'Project ID', type: 'text', required: true, placeholder: 'my-project-123', phase: 'context' },
    ],
    setupGuide: {
      title: 'Grant WID read-only access to your project',
      usesProjectId: true,
      steps: [
        { label: 'Grant Viewer role to WID service account', command: 'gcloud projects add-iam-policy-binding {{projectId}} \\\n  --member="serviceAccount:wid-dev-run@wid-platform.iam.gserviceaccount.com" \\\n  --role="roles/viewer"' },
        { label: 'Grant Security Reviewer role (for IAM and security findings)', command: 'gcloud projects add-iam-policy-binding {{projectId}} \\\n  --member="serviceAccount:wid-dev-run@wid-platform.iam.gserviceaccount.com" \\\n  --role="roles/iam.securityReviewer"' },
      ],
      note: 'WID uses its own service account identity to access your project. No keys or credentials are stored — you simply grant read-only IAM roles to WID\'s service account. You can revoke access at any time by removing these role bindings.',
    },
  },
  {
    id: 'azure', name: 'Microsoft Azure', icon: 'azure',
    description: 'Discover VMs, App Services, AKS clusters, Entra ID applications, and service principals.',
    credentialFields: [
      { name: 'tenantId', label: 'Tenant (Directory) ID', type: 'text', required: true, placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', phase: 'context' },
      { name: 'subscriptionId', label: 'Subscription ID', type: 'text', required: true, placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', phase: 'context' },
    ],
    setupGuide: {
      title: 'Grant WID read-only access to your subscription',
      steps: [
        { label: 'Register WID as an enterprise application in your tenant', command: 'az ad sp create --id "WID_APP_CLIENT_ID"' },
        { label: 'Grant Reader role on your subscription', command: 'az role assignment create \\\n  --assignee "WID_APP_CLIENT_ID" \\\n  --role "Reader" \\\n  --scope "/subscriptions/{{subscriptionId}}"' },
        { label: 'Grant Security Reader role for security findings', command: 'az role assignment create \\\n  --assignee "WID_APP_CLIENT_ID" \\\n  --role "Security Reader" \\\n  --scope "/subscriptions/{{subscriptionId}}"' },
      ],
      note: 'WID uses a multi-tenant Azure AD application to access your subscription. No client secrets are stored in your environment — you simply consent to WID\'s app and assign read-only roles. You can revoke access by removing the role assignments or deleting the enterprise application.',
    },
  },
  {
    id: 'kubernetes', name: 'Kubernetes', icon: 'kubernetes',
    description: 'Discover deployments, statefulsets, daemonsets, cronjobs, and service accounts across clusters.',
    credentialFields: [
      { name: 'clusterName', label: 'Cluster Name', type: 'text', required: false, placeholder: 'production-cluster', phase: 'context' },
      { name: 'context', label: 'Kubeconfig Context (optional)', type: 'text', required: false, phase: 'context' },
      { name: 'kubeconfig', label: 'Kubeconfig', type: 'textarea', required: true, placeholder: 'apiVersion: v1\nkind: Config\n...' },
    ],
    setupGuide: {
      title: 'Export your kubeconfig',
      steps: [
        { label: 'Export the current kubeconfig (or a specific context)', command: 'kubectl config view --minify --flatten' },
      ],
      note: 'Copy the full YAML output and paste it below. This uses your current kubectl context.',
    },
  },
  {
    id: 'vault', name: 'HashiCorp Vault', icon: 'vault',
    description: 'Discover Vault secrets engines, auth methods, and token policies.',
    credentialFields: [
      { name: 'vaultAddr', label: 'Vault Address', type: 'text', required: true, placeholder: 'https://vault.example.com:8200', phase: 'context' },
      { name: 'vaultToken', label: 'Vault Token', type: 'password', required: true },
    ],
    setupGuide: {
      title: 'Create a read-only Vault token',
      steps: [
        { label: 'Create a read-only policy', command: 'vault policy write wid-readonly - <<EOF\npath "sys/mounts" { capabilities = ["read", "list"] }\npath "auth/*" { capabilities = ["read", "list"] }\npath "sys/auth" { capabilities = ["read", "list"] }\npath "sys/policies/*" { capabilities = ["read", "list"] }\nEOF' },
        { label: 'Create a token with the policy', command: 'vault token create -policy=wid-readonly -ttl=8760h' },
      ],
      note: 'Copy the token value from the output and paste it below.',
    },
  },
  {
    id: 'docker', name: 'Docker', icon: 'docker',
    description: 'Discover running containers, images, networks, and volumes on a Docker host.',
    credentialFields: [
      { name: 'socketPath', label: 'Docker Socket Path', type: 'text', required: false, placeholder: '/var/run/docker.sock', phase: 'context' },
      { name: 'host', label: 'Docker Host (optional)', type: 'text', required: false, placeholder: 'tcp://localhost:2375' },
    ],
    setupGuide: {
      title: 'Docker connection',
      steps: [
        { label: 'Verify Docker is running', command: 'docker info' },
      ],
      note: 'For local Docker, the default socket path (/var/run/docker.sock) usually works. For remote Docker hosts, enter the TCP address.',
    },
  },
];

// ─── Provider Logos — clean, crisp icons ─────────────────────────────────
const ProviderIcon = ({ provider, size = 32 }) => {
  const s = size;
  const icons = {
    aws: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#232F3E"/>
        <path d="M16.8 21.5c0 .4.04.7.13.9.09.2.21.4.37.6.06.08.07.16.02.23l-.48.32c-.07.05-.14.04-.21-.02a2.5 2.5 0 01-.46-.6 3.06 3.06 0 01-.37-.75c-.93 1.1-2.1 1.64-3.52 1.64-.95 0-1.7-.27-2.27-.81-.56-.54-.84-1.27-.84-2.17 0-.96.34-1.74 1.02-2.33.68-.6 1.58-.89 2.72-.89.38 0 .77.03 1.18.1.41.06.83.15 1.28.27v-.83c0-.86-.18-1.46-.53-1.8-.36-.35-.96-.52-1.82-.52-.39 0-.79.05-1.2.14-.41.1-.81.22-1.2.38a.29.29 0 01-.1.02c-.08 0-.12-.06-.12-.18v-.37c0-.1.01-.17.05-.2.03-.04.1-.08.2-.13.39-.2.86-.37 1.4-.5.55-.14 1.13-.21 1.74-.21 1.33 0 2.3.3 2.92.91.61.61.92 1.53.92 2.78v3.67zm-4.86.98c.37 0 .75-.07 1.15-.2.4-.13.75-.37 1.05-.7.18-.21.32-.44.4-.7.08-.26.12-.58.12-.95v-.46c-.33-.09-.68-.16-1.05-.21a7.1 7.1 0 00-1.06-.08c-.74 0-1.29.14-1.64.44-.35.3-.52.72-.52 1.26 0 .51.13.89.4 1.14.26.3.64.46 1.15.46zm9.6 1.3c-.1 0-.17-.02-.22-.07-.04-.04-.08-.14-.12-.28l-2.7-8.87c-.04-.15-.06-.25-.06-.3 0-.12.06-.18.18-.18h.82c.11 0 .18.02.22.07.04.04.08.14.12.28l1.93 7.6 1.79-7.6c.03-.15.07-.24.12-.28a.4.4 0 01.23-.07h.67c.11 0 .18.02.23.07.04.04.08.14.11.28l1.81 7.7 1.99-7.7c.04-.15.08-.24.12-.28.05-.05.12-.07.22-.07h.78c.12 0 .18.06.18.18 0 .04-.01.07-.02.12-.01.04-.03.1-.05.19l-2.77 8.87c-.04.15-.08.24-.12.28-.05.05-.13.07-.22.07h-.72c-.11 0-.18-.02-.23-.07s-.08-.14-.11-.29L23.66 15l-1.77 7.43c-.03.15-.07.24-.11.29-.05.05-.13.07-.23.07h-.72z" fill="#FF9900"/>
        <path d="M28.68 25.03c-3.19 2.35-7.82 3.6-11.8 3.6-5.58 0-10.6-2.06-14.4-5.49-.3-.27-.03-.64.33-.43 4.1 2.39 9.18 3.83 14.42 3.83 3.54 0 7.43-.73 11.01-2.25.54-.24 1 .35.44.74z" fill="#FF9900"/>
        <path d="M29.94 23.58c-.41-.52-2.68-.25-3.7-.12-.31.04-.36-.23-.08-.43 1.82-1.28 4.8-.91 5.14-.48.35.43-.09 3.44-1.79 4.88-.26.22-.51.1-.4-.19.38-.96 1.24-3.14.83-3.66z" fill="#FF9900"/>
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
        <path d="M25.03 7.94A1.37 1.37 0 0023.73 7H17.2a1.38 1.38 0 011.3.94l7.74 22.52a1.38 1.38 0 01-1.3 1.84h6.52a1.38 1.38 0 001.3-1.84L25.03 7.94z" fill="#0078D4" opacity=".5"/>
      </svg>
    ),
    kubernetes: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#326CE5"/>
        <g fill="#fff">
          <path d="M20 9.5a1.06 1.06 0 00-.42.09l-8.16 4.22a1.08 1.08 0 00-.58.76l-1.46 9.15c-.04.28.04.57.22.8l5.87 7.3c.2.26.5.4.82.4h9.42c.32 0 .62-.14.82-.4l5.87-7.3c.18-.23.26-.52.22-.8l-1.46-9.15a1.08 1.08 0 00-.58-.76l-8.16-4.22A1.06 1.06 0 0020 9.5z" fillOpacity=".3"/>
          <path d="M20 11.4c-.22 0-.4.18-.4.4v.56c-.02.42-.06.7-.17.82-.1.1-.36.2-.76.26a.35.35 0 00-.1.02l-.1.03a6.58 6.58 0 00-3.76 2.14l-.07.05c-.06.02-.1.02-.1.02-.37-.15-.63-.28-.78-.33-.16-.04-.38-.02-.58.18l-.38.4a.4.4 0 00.08.58l.42.34c.34.27.58.48.64.62.06.16.02.43-.1.82l-.02.1-.02.1a6.6 6.6 0 00-.34 3.39c.02.06.06.1.07.14 0 .06-.02.1-.02.1-.24.32-.43.57-.5.72-.08.17-.1.4.04.62l.24.46c.12.22.38.3.58.22l.5-.16c.38-.12.66-.18.8-.14.14.06.34.28.56.6l.06.08.07.08a6.58 6.58 0 003.14 2.18c.04.02.1.02.12.06.04.04.06.1.06.1.06.4.1.7.17.84.08.16.28.32.52.32h.52c.24 0 .44-.16.52-.32.07-.14.11-.44.17-.84 0 0 .02-.06.06-.1.02-.04.08-.04.12-.06a6.58 6.58 0 003.14-2.18l.07-.08.06-.08c.22-.32.42-.54.56-.6.14-.04.42.02.8.14l.5.16c.2.08.46 0 .58-.22l.24-.46c.14-.22.12-.45.04-.62-.07-.15-.26-.4-.5-.72 0 0-.02-.04-.02-.1.01-.04.05-.08.07-.14a6.6 6.6 0 00-.34-3.38l-.02-.1-.02-.11c-.12-.39-.16-.66-.1-.82.06-.14.3-.35.64-.62l.42-.34a.4.4 0 00.08-.58l-.38-.4c-.2-.2-.42-.22-.58-.18-.15.05-.41.18-.78.33 0 0-.04 0-.1-.02l-.08-.05a6.58 6.58 0 00-3.76-2.14l-.1-.03a.35.35 0 00-.1-.02c-.4-.06-.66-.16-.76-.26-.11-.12-.15-.4-.17-.82V11.8a.4.4 0 00-.4-.4z"/>
          <circle cx="20" cy="20.5" r="2" fill="#326CE5"/>
        </g>
      </svg>
    ),
    vault: (
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none">
        <rect width="40" height="40" rx="10" fill="#1A1A1A"/>
        <path d="M20 7l13 7.5v11L20 33 7 25.5v-11L20 7z" fill="none" stroke="#FFEC6E" strokeWidth="1.6"/>
        <path d="M20 12l7.5 4.33v8.67L20 29.33 12.5 25v-8.67L20 12z" fill="none" stroke="#FFEC6E" strokeWidth="1.2"/>
        <path d="M20 17l3.5 2v4L20 25l-3.5-2v-4l3.5-2z" fill="#FFEC6E"/>
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
        <path d="M33.5 20c-.5-1-1.6-1.6-3-1.8.3-1.3-.1-2.5-1-3.3l-.6-.5-.5.6c-.6.8-.9 1.9-.8 2.8.1.6.3 1.1.6 1.6-.9.5-2.3.7-3.5.7H5.4c-.3 1.8-.1 4.1 1 5.9 1 1.6 2.6 2.7 4.8 3.2.8.2 1.7.3 2.7.3 2.8 0 5.3-.8 7.3-2.5 1.8-1.5 2.9-3.5 3.6-5.7h.5c1.4 0 2.3-.5 3-1.3.5-.5.7-1.2.8-1.8l.1-.3-.7-.3z" fill="#fff" fillOpacity=".4"/>
      </svg>
    ),
  };
  return icons[provider] || <Cloud className="w-8 h-8 text-nhi-dim" />;
};

// ─── Status badge ────────────────────────────────────────────────────────
const StatusBadge = ({ status }) => {
  const styles = {
    active: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
    pending: 'bg-amber-500/15 text-amber-400 border-amber-500/20',
    validating: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
    error: 'bg-red-500/15 text-red-400 border-red-500/20',
    disabled: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/20',
  };
  const icons = {
    active: <CheckCircle2 className="w-3 h-3" />,
    pending: <Clock className="w-3 h-3" />,
    validating: <Loader2 className="w-3 h-3 animate-spin" />,
    error: <XCircle className="w-3 h-3" />,
    disabled: <XCircle className="w-3 h-3" />,
  };

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${styles[status] || styles.pending}`}>
      {icons[status]} {status}
    </span>
  );
};

// =============================================================================
// Onboarding Wizard Modal
// =============================================================================
const WizardModal = ({ providers, onClose, onCreated, initialProvider = null }) => {
  const initP = initialProvider ? providers?.find(p => p.id === initialProvider) : null;
  const [step, setStep] = useState(initP ? 1 : 0);
  const [selectedProvider, setSelectedProvider] = useState(initialProvider);
  const [formData, setFormData] = useState({
    name: initP ? `${initP.name} Account` : '',
    description: '',
    credentials: {},
    config: {},
  });
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [creating, setCreating] = useState(false);
  const [createdConnectorId, setCreatedConnectorId] = useState(null);

  const provider = providers?.find(p => p.id === selectedProvider);

  const resetWizard = () => {
    setStep(0);
    setSelectedProvider(null);
    setFormData({ name: '', description: '', credentials: {}, config: {} });
    setTestResult(null);
    setCreating(false);
    setTesting(false);
    setCreatedConnectorId(null);
  };

  const handleSelectProvider = (id) => {
    setSelectedProvider(id);
    const p = providers.find(pr => pr.id === id);
    // Auto-generate External ID for AWS (prevents confused deputy attacks)
    const seedCredentials = {};
    if (id === 'aws') {
      seedCredentials.externalId = `wid-${crypto.randomUUID().slice(0, 8)}`;
    }
    setFormData(prev => ({
      ...prev,
      name: `${p?.name || id} Account`,
      credentials: seedCredentials,
      config: {},
    }));
    setStep(1);
  };

  const handleCredentialChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      credentials: { ...prev.credentials, [field]: value },
    }));
    setTestResult(null);
  };

  const handleCreate = async () => {
    setCreating(true);
    try {
      const resp = await fetch(`${API}/connectors`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name,
          description: formData.description,
          provider: selectedProvider,
          config: formData.config,
          credentials: formData.credentials,
          mode: 'discovery',
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to create connector');

      setCreatedConnectorId(data.connector.id);

      // Auto-test credentials
      setTesting(true);
      const testResp = await fetch(`${API}/connectors/${data.connector.id}/test`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const testData = await testResp.json();
      setTestResult(testData);
      setTesting(false);

      if (testData.valid) {
        // Auto-trigger scan
        await fetch(`${API}/connectors/${data.connector.id}/scan`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        toast.success(`Connector created and scan started for ${formData.name}`);
        setStep(2);
      } else {
        toast.error(`Credentials invalid: ${testData.error}`);
      }

      setCreating(false);
      onCreated?.();
    } catch (err) {
      setCreating(false);
      setTesting(false);
      toast.error(err.message);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div
        className="w-full max-w-2xl mx-4 nhi-card rounded-2xl shadow-2xl flex flex-col animate-fadeInUp"
        style={{ animationDuration: '0.25s', maxHeight: 'calc(100vh - 48px)' }}
      >
        {/* Header — fixed */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-brd shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-accent/15 flex items-center justify-center">
              <Plug className="w-5 h-5 text-accent" />
            </div>
            <div>
              <h2 className="text-[15px] font-bold text-nhi-text">Connect Cloud Account</h2>
              <p className="text-[11px] text-nhi-faint">Step {step + 1} of 3</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-surface-3 text-nhi-faint hover:text-nhi-text transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Step indicator — fixed */}
        <div className="flex gap-1 px-6 py-3 bg-surface-1 border-b border-brd/50 shrink-0">
          {['Choose Provider', 'Configure', 'Verify & Scan'].map((label, i) => (
            <div key={i} className="flex items-center gap-2 flex-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border transition-colors ${
                i < step ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400' :
                i === step ? 'bg-accent/20 border-accent/30 text-accent' :
                'bg-surface-3 border-brd text-nhi-faint'
              }`}>
                {i < step ? <CheckCircle2 className="w-3.5 h-3.5" /> : i + 1}
              </div>
              <span className={`text-[11px] font-medium ${i === step ? 'text-nhi-text' : 'text-nhi-faint'}`}>
                {label}
              </span>
              {i < 2 && <ChevronRight className="w-3 h-3 text-nhi-ghost ml-auto" />}
            </div>
          ))}
        </div>

        {/* Content — scrollable */}
        <div className="px-6 py-5 overflow-y-auto flex-1 min-h-0">
          {/* Step 0: Choose Provider */}
          {step === 0 && (
            <div>
              <p className="text-[12px] text-nhi-dim mb-4">
                Select one or more cloud providers to connect. You can add additional providers after the first one is set up.
              </p>
              <div className="grid grid-cols-3 gap-3">
                {(providers || []).map(p => (
                  <button
                    key={p.id}
                    onClick={() => handleSelectProvider(p.id)}
                    className="group nhi-card p-4 rounded-xl text-left hover:border-accent/40 hover:shadow-[0_0_16px_rgba(124,111,240,0.1)] transition-all duration-200 cursor-pointer"
                  >
                    <div className="mb-3">
                      <ProviderIcon provider={p.id} size={36} />
                    </div>
                    <div className="text-[13px] font-semibold text-nhi-text mb-1">{p.name}</div>
                    <div className="text-[10px] text-nhi-faint leading-relaxed line-clamp-2">{p.description}</div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Step 1: Configure */}
          {step === 1 && provider && (() => {
            const contextFields = (provider.credentialFields || []).filter(f => f.phase === 'context');
            const credFields = (provider.credentialFields || []).filter(f => f.phase !== 'context');
            const guide = provider.setupGuide;
            // Replace {{fieldName}} placeholders in commands with actual values
            const fillCmd = (cmd) => cmd.replace(/\{\{(\w+)\}\}/g, (_, key) =>
              formData.credentials[key] || `<${key}>`
            );
            // Show guide only when all context fields with content have been entered
            const hasContextInput = contextFields.some(f => formData.credentials[f.name]?.trim());

            return (
              <div className="space-y-4">
                <div className="flex items-center gap-3 mb-4">
                  <ProviderIcon provider={selectedProvider} size={28} />
                  <span className="text-[13px] font-semibold text-nhi-text">{provider.name}</span>
                </div>

                {/* Connector name */}
                <div>
                  <label className="block text-[11px] font-semibold text-nhi-dim mb-1.5">Connector Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    className="nhi-input w-full"
                    placeholder="e.g., Production AWS"
                  />
                </div>

                {/* Context fields (Project ID, Region, Tenant ID, etc.) */}
                {contextFields.map(field => (
                  <div key={field.name}>
                    <label className="block text-[11px] font-semibold text-nhi-dim mb-1.5">
                      {field.label} {field.required && <span className="text-red-400">*</span>}
                    </label>
                    <input
                      type={field.type || 'text'}
                      value={formData.credentials[field.name] || ''}
                      onChange={e => handleCredentialChange(field.name, e.target.value)}
                      className="nhi-input w-full"
                      placeholder={field.placeholder}
                    />
                  </div>
                ))}

                {/* Setup guide — CLI instructions with values pre-filled */}
                {guide && (contextFields.length === 0 || hasContextInput) && (
                  <div className="p-4 rounded-xl bg-surface-1 border border-brd space-y-3">
                    <div className="flex items-center gap-2">
                      <Zap className="w-4 h-4 text-accent shrink-0" />
                      <span className="text-[12px] font-bold text-nhi-text">{guide.title}</span>
                    </div>
                    <div className="space-y-2.5">
                      {guide.steps.map((s, i) => (
                        <div key={i}>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="w-5 h-5 rounded-full bg-accent/15 text-accent text-[10px] font-bold flex items-center justify-center shrink-0">{i + 1}</span>
                            <span className="text-[11px] font-medium text-nhi-dim">{s.label}</span>
                          </div>
                          <div className="ml-7 relative group/cmd">
                            <pre className="text-[10px] font-mono text-nhi-muted bg-surface-0 rounded-lg px-3 py-2 overflow-x-auto border border-brd/50 whitespace-pre-wrap">{fillCmd(s.command)}</pre>
                            <button
                              type="button"
                              onClick={() => { navigator.clipboard.writeText(fillCmd(s.command)); toast.success('Copied to clipboard'); }}
                              className="absolute top-1.5 right-1.5 p-1 rounded bg-surface-3/80 text-nhi-ghost hover:text-nhi-text opacity-0 group-hover/cmd:opacity-100 transition-opacity"
                              title="Copy"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                    {guide.note && (
                      <p className="text-[10px] text-nhi-faint ml-7 mt-1 italic">{guide.note}</p>
                    )}
                  </div>
                )}

                {/* Credential fields (JSON key, Role ARN, Client Secret, etc.) */}
                {credFields.map(field => (
                  <div key={field.name}>
                    <label className="block text-[11px] font-semibold text-nhi-dim mb-1.5">
                      {field.label} {field.required && <span className="text-red-400">*</span>}
                    </label>
                    {field.type === 'textarea' ? (
                      <textarea
                        value={formData.credentials[field.name] || ''}
                        onChange={e => handleCredentialChange(field.name, e.target.value)}
                        className="nhi-input w-full h-24 font-mono text-[11px] resize-none"
                        placeholder={field.placeholder}
                        readOnly={field.readOnly}
                      />
                    ) : (
                      <input
                        type={field.type || 'text'}
                        value={formData.credentials[field.name] || ''}
                        onChange={e => !field.readOnly && handleCredentialChange(field.name, e.target.value)}
                        className={`nhi-input w-full ${field.readOnly ? 'bg-surface-1 text-nhi-muted cursor-default select-all' : ''}`}
                        placeholder={field.placeholder}
                        readOnly={field.readOnly}
                      />
                    )}
                  </div>
                ))}

                {/* Test result inline */}
                {testResult && !testResult.valid && (
                  <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-[11px] font-semibold text-red-400">Credential validation failed</div>
                      <div className="text-[10px] text-red-300/80 mt-0.5">{testResult.error}</div>
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* Step 2: Verify & Scan */}
          {step === 2 && (
            <div className="space-y-4">
              <div className="flex items-center justify-center py-6">
                <div className="text-center">
                  <div className="w-16 h-16 rounded-full bg-emerald-500/15 flex items-center justify-center mx-auto mb-4">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                  </div>
                  <h3 className="text-[15px] font-bold text-nhi-text mb-2">
                    {provider?.name} Connected
                  </h3>
                  <p className="text-[12px] text-nhi-dim mb-6">
                    Your {provider?.name} account is connected and scanning has started.
                    <br />Workloads will appear in the Identity Graph shortly.
                  </p>

                  {/* Actions */}
                  <div className="flex flex-col items-center gap-3">
                    <button
                      onClick={resetWizard}
                      className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-accent text-white text-[12px] font-semibold hover:bg-accent/90 transition-colors"
                    >
                      <Plus className="w-4 h-4" /> Connect Another Provider
                    </button>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={onClose}
                        className="px-4 py-2 rounded-lg bg-surface-3 text-nhi-text text-[12px] font-semibold hover:bg-surface-4 transition-colors"
                      >
                        Done
                      </button>
                      <button
                        onClick={() => { onClose(); window.location.href = '/graph'; }}
                        className="px-4 py-2 rounded-lg border border-accent/30 text-accent text-[12px] font-semibold hover:bg-accent/10 transition-colors flex items-center gap-1.5"
                      >
                        View Identity Graph <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer — fixed at bottom */}
        {step === 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t border-brd bg-surface-1 shrink-0">
            <button
              onClick={() => { setStep(0); setSelectedProvider(null); setTestResult(null); }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-[12px] font-medium text-nhi-dim hover:text-nhi-text hover:bg-surface-3 transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" /> Back
            </button>
            <button
              onClick={handleCreate}
              disabled={creating || testing}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-accent text-white text-[12px] font-semibold hover:bg-accent/90 transition-colors disabled:opacity-50"
            >
              {(creating || testing) && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {testing ? 'Validating...' : creating ? 'Creating...' : 'Connect & Scan'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// =============================================================================
// Main Connectors Page
// =============================================================================
export default function Connectors() {
  const [connectors, setConnectors] = useState([]);
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showWizard, setShowWizard] = useState(false);
  const [wizardProvider, setWizardProvider] = useState(null); // pre-select provider
  const [scanning, setScanning] = useState({});
  const [deleteDialog, setDeleteDialog] = useState(null); // { id, name, workloadCount, deleting }
  const navigate = useNavigate();
  const { refresh: refreshOnboarding } = useOnboarding();

  const fetchConnectors = useCallback(async () => {
    try {
      const resp = await fetch(`${API}/connectors`, { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json();
        setConnectors(data.connectors || []);
      }
    } catch (err) {
      console.error('Failed to fetch connectors:', err);
    }
  }, []);

  const fetchProviders = useCallback(async () => {
    // Always use FALLBACK_PROVIDERS as the base — they have setupGuide + field ordering.
    // Merge any extra API-only providers that aren't in the fallback.
    const base = [...FALLBACK_PROVIDERS];
    try {
      const resp = await fetch(`${API}/connectors/providers`, { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json();
        const apiProviders = data.providers || [];
        const baseIds = new Set(base.map(p => p.id));
        for (const ap of apiProviders) {
          if (!baseIds.has(ap.id)) base.push(ap);
        }
      }
    } catch (err) {
      console.error('Failed to fetch providers:', err);
    }
    setProviders(base);
  }, []);

  useEffect(() => {
    Promise.all([fetchConnectors(), fetchProviders()]).finally(() => setLoading(false));
  }, [fetchConnectors, fetchProviders]);

  // Poll for scan status updates
  useEffect(() => {
    if (Object.keys(scanning).length === 0) return;
    const interval = setInterval(fetchConnectors, 3000);
    return () => clearInterval(interval);
  }, [scanning, fetchConnectors]);

  const handleScan = async (id) => {
    setScanning(prev => ({ ...prev, [id]: true }));
    try {
      await fetch(`${API}/connectors/${id}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      toast.success('Scan triggered');
      setTimeout(fetchConnectors, 2000);
    } catch (err) {
      toast.error('Failed to trigger scan');
    }
    setTimeout(() => setScanning(prev => { const n = { ...prev }; delete n[id]; return n; }), 5000);
  };

  const handleDelete = async (id, name) => {
    // Fetch workload count before showing dialog
    let workloadCount = 0;
    try {
      const resp = await fetch(`${API}/connectors/${id}`, { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json();
        workloadCount = data.connector?.workload_count || 0;
      }
    } catch { /* ignore — will show 0 */ }
    setDeleteDialog({ id, name, workloadCount, deleting: false });
  };

  const confirmDelete = async (purge) => {
    if (!deleteDialog) return;
    setDeleteDialog(d => ({ ...d, deleting: true }));
    try {
      const url = purge
        ? `${API}/connectors/${deleteDialog.id}?purge=true`
        : `${API}/connectors/${deleteDialog.id}`;
      await fetch(url, { method: 'DELETE' });
      toast.success(purge
        ? `Connector and ${deleteDialog.workloadCount} workloads removed`
        : 'Connector removed — workloads kept as archived');
      fetchConnectors();
      refreshOnboarding();
    } catch (err) {
      toast.error('Failed to delete connector');
    }
    setDeleteDialog(null);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 animate-spin text-accent" />
      </div>
    );
  }

  const hasConnectors = connectors.length > 0;

  return (
    <div className="p-6 max-w-[1200px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 animate-fadeInUp">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent/15 flex items-center justify-center">
            <Plug className="w-5 h-5 text-accent" />
          </div>
          <div>
            <h1 className="text-[18px] font-bold text-nhi-text">Cloud Connectors</h1>
            <p className="text-[12px] text-nhi-faint">Connect your cloud accounts for workload discovery</p>
          </div>
        </div>
        <button
          onClick={() => { setWizardProvider(null); setShowWizard(true); }}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-accent text-white text-[12px] font-semibold hover:bg-accent/90 transition-all duration-200 shadow-lg shadow-accent/20"
        >
          <Plus className="w-4 h-4" /> Add Connector
        </button>
      </div>

      {/* Empty State */}
      {!hasConnectors && (
        <div className="nhi-card p-12 rounded-2xl text-center animate-fadeInUp" style={{ animationDelay: '0.1s' }}>
          <div className="w-20 h-20 rounded-2xl bg-accent/10 flex items-center justify-center mx-auto mb-6">
            <Cloud className="w-10 h-10 text-accent" />
          </div>
          <h2 className="text-[16px] font-bold text-nhi-text mb-2">Connect Your First Cloud Account</h2>
          <p className="text-[13px] text-nhi-dim max-w-md mx-auto mb-6">
            Connect your AWS, GCP, or Azure account to discover workloads, map identities,
            and find security risks. No agents or installations required.
          </p>
          <div className="flex items-center justify-center gap-3 mb-8">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-brd">
              <Eye className="w-3.5 h-3.5 text-accent" />
              <span className="text-[11px] font-medium text-nhi-dim">Read-only access</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-brd">
              <Clock className="w-3.5 h-3.5 text-accent" />
              <span className="text-[11px] font-medium text-nhi-dim">Results in minutes</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-2 border border-brd">
              <Shield className="w-3.5 h-3.5 text-accent" />
              <span className="text-[11px] font-medium text-nhi-dim">Credentials encrypted</span>
            </div>
          </div>

          {/* Provider cards — click goes straight to configure */}
          <div className="grid grid-cols-5 gap-3 max-w-2xl mx-auto">
            {providers.map(p => (
              <button
                key={p.id}
                onClick={() => { setWizardProvider(p.id); setShowWizard(true); }}
                className="group nhi-card p-4 rounded-xl text-center hover:border-accent/40 hover:shadow-[0_0_16px_rgba(124,111,240,0.1)] transition-all duration-200 cursor-pointer"
              >
                <div className="flex justify-center mb-2">
                  <ProviderIcon provider={p.id} size={32} />
                </div>
                <div className="text-[11px] font-semibold text-nhi-text">{p.name}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Connected Connectors List */}
      {hasConnectors && (
        <div className="space-y-3 animate-fadeInUp" style={{ animationDelay: '0.1s' }}>
          {/* Stats bar */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            {[
              { label: 'Total', value: connectors.length, color: 'text-accent' },
              { label: 'Active', value: connectors.filter(c => c.status === 'active').length, color: 'text-emerald-400' },
              { label: 'Workloads', value: connectors.reduce((sum, c) => sum + (c.workload_count || 0), 0), color: 'text-blue-400' },
              { label: 'Errors', value: connectors.filter(c => c.status === 'error').length, color: 'text-red-400' },
            ].map((stat, i) => (
              <div key={i} className="nhi-card px-4 py-3 rounded-xl">
                <div className="text-[10px] font-semibold text-nhi-faint uppercase tracking-wider">{stat.label}</div>
                <div className={`text-[20px] font-bold font-mono ${stat.color}`}>{stat.value}</div>
              </div>
            ))}
          </div>

          {/* Connector cards */}
          {connectors.map((c, i) => (
            <div
              key={c.id}
              className="nhi-card p-4 rounded-xl hover:border-accent/20 transition-all duration-200 animate-fadeInUp"
              style={{ animationDelay: `${0.15 + i * 0.05}s` }}
            >
              <div className="flex items-center gap-4">
                {/* Provider icon */}
                <ProviderIcon provider={c.provider} size={40} />

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[14px] font-bold text-nhi-text truncate">{c.name}</span>
                    <StatusBadge status={c.status} />
                    {c.mode === 'enforcement' && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-accent/15 text-accent border border-accent/20">
                        <Shield className="w-3 h-3" /> Enforcement
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-[11px] text-nhi-faint">
                    <span className="capitalize">{c.provider}</span>
                    {c.config?.region && <span>{c.config.region}</span>}
                    <span>{c.workload_count || 0} workloads</span>
                    {c.last_scan_at && (
                      <span>Scanned {new Date(c.last_scan_at).toLocaleDateString()}</span>
                    )}
                    {c.last_scan_duration_ms && (
                      <span>{(c.last_scan_duration_ms / 1000).toFixed(1)}s</span>
                    )}
                  </div>
                  {c.error_message && (
                    <div className="flex items-center gap-1.5 mt-1.5 text-[10px] text-red-400">
                      <AlertTriangle className="w-3 h-3 shrink-0" />
                      <span className="truncate">{c.error_message}</span>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    onClick={() => handleScan(c.id)}
                    disabled={scanning[c.id] || c.last_scan_status === 'running'}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-3 text-[11px] font-medium text-nhi-dim hover:text-nhi-text hover:bg-surface-4 transition-colors disabled:opacity-50"
                    title="Trigger scan"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${(scanning[c.id] || c.last_scan_status === 'running') ? 'animate-spin' : ''}`} />
                    Scan
                  </button>
                  <button
                    onClick={() => handleDelete(c.id, c.name)}
                    className="p-1.5 rounded-lg text-nhi-ghost hover:text-red-400 hover:bg-red-500/10 transition-colors"
                    title="Delete connector"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {deleteDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => !deleteDialog.deleting && setDeleteDialog(null)} />
          <div className="relative w-full max-w-md mx-4 rounded-2xl border border-white/[0.06] p-6"
               style={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16162a 100%)' }}>
            <button onClick={() => setDeleteDialog(null)} disabled={deleteDialog.deleting}
              className="absolute top-4 right-4 p-1 rounded-lg text-nhi-ghost hover:text-nhi-text hover:bg-white/5 transition-colors disabled:opacity-50">
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-[15px] font-bold text-nhi-text">Delete Connector</h3>
                <p className="text-[11px] text-nhi-faint">"{deleteDialog.name}"</p>
              </div>
            </div>

            {deleteDialog.workloadCount > 0 ? (
              <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4 mb-5">
                <p className="text-[12px] text-nhi-dim mb-2">
                  This connector discovered <span className="text-nhi-text font-semibold">{deleteDialog.workloadCount} workload{deleteDialog.workloadCount !== 1 ? 's' : ''}</span> in the identity graph.
                </p>
                <p className="text-[11px] text-nhi-faint">
                  Choose whether to remove them from the graph or keep them as archived entries.
                </p>
              </div>
            ) : (
              <p className="text-[12px] text-nhi-dim mb-5">
                No workloads are linked to this connector. The connector record and credentials will be removed.
              </p>
            )}

            <div className="flex flex-col gap-2">
              {deleteDialog.workloadCount > 0 && (
                <>
                  <button
                    onClick={() => confirmDelete(true)}
                    disabled={deleteDialog.deleting}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-red-500/20 border border-red-500/30 text-red-400 text-[12px] font-semibold hover:bg-red-500/30 transition-all disabled:opacity-50"
                  >
                    {deleteDialog.deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                    Remove Everything
                  </button>
                  <button
                    onClick={() => confirmDelete(false)}
                    disabled={deleteDialog.deleting}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-white/[0.04] border border-white/[0.06] text-nhi-dim text-[12px] font-semibold hover:bg-white/[0.08] hover:text-nhi-text transition-all disabled:opacity-50"
                  >
                    {deleteDialog.deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                    Keep Workloads
                  </button>
                </>
              )}
              {deleteDialog.workloadCount === 0 && (
                <button
                  onClick={() => confirmDelete(false)}
                  disabled={deleteDialog.deleting}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-red-500/20 border border-red-500/30 text-red-400 text-[12px] font-semibold hover:bg-red-500/30 transition-all disabled:opacity-50"
                >
                  {deleteDialog.deleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                  Delete Connector
                </button>
              )}
              <button
                onClick={() => setDeleteDialog(null)}
                disabled={deleteDialog.deleting}
                className="w-full px-4 py-2 text-[11px] text-nhi-ghost hover:text-nhi-dim transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Wizard Modal */}
      {showWizard && (
        <WizardModal
          providers={providers}
          initialProvider={wizardProvider}
          onClose={() => { setShowWizard(false); setWizardProvider(null); }}
          onCreated={() => { fetchConnectors(); refreshOnboarding(); }}
        />
      )}
    </div>
  );
}
