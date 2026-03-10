// =============================================================================
// SPIFFE ID Generation
// Produces type-routed SPIFFE IDs following the SPIFFE spec:
//   spiffe://<trust-domain>/<workload-type>/<namespace>/<name>
//
// Requires SPIRE_TRUST_DOMAIN env var. Fails loudly in production if not set.
// =============================================================================

const TRUST_DOMAIN = process.env.SPIRE_TRUST_DOMAIN;
const IS_PROD = process.env.NODE_ENV === 'production';

if (!TRUST_DOMAIN) {
  if (IS_PROD) {
    throw new Error('SPIRE_TRUST_DOMAIN env var is required in production. Set it to your SPIRE trust domain (e.g. company.com).');
  } else {
    console.warn('[spiffe] SPIRE_TRUST_DOMAIN not set — using "dev.local" for development');
  }
}

const EFFECTIVE_DOMAIN = TRUST_DOMAIN || 'dev.local';

// Map workload types to SPIFFE path segments
const TYPE_PATH = {
  'cloud-run':          'gcp/cloud-run',
  'cloud-run-service':  'gcp/cloud-run',
  'cloud-function':     'gcp/function',
  'gce-instance':       'gcp/vm',
  'gke-cluster':        'gcp/gke',
  'lambda':             'aws/lambda',
  'ec2':                'aws/ec2',
  'ecs-task':           'aws/ecs',
  'azure-vm':           'azure/vm',
  'azure-function':     'azure/function',
  'azure-app-service':  'azure/app',
  'a2a-agent':          'agent/a2a',
  'mcp-server':         'agent/mcp',
  'container':          'k8s/pod',
  'pod':                'k8s/pod',
  'service-account':    'identity/sa',
};

/**
 * Generate a SPIFFE ID for a workload.
 *
 * @param {string} namespace - Namespace (k8s namespace, GCP project, AWS account, etc.)
 * @param {string} name - Workload name
 * @param {string} [type] - Workload type (cloud-run, lambda, a2a-agent, etc.)
 * @returns {string} SPIFFE URI, e.g. spiffe://company.com/gcp/cloud-run/prod/payment-processor
 */
function generateSpiffeId(namespace, name, type) {
  const cleanName = name.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase().replace(/-+/g, '-').replace(/^-|-$/g, '');
  const cleanNs = namespace.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase().replace(/-+/g, '-').replace(/^-|-$/g, '');
  const typePath = TYPE_PATH[type] || 'workload';

  return `spiffe://${EFFECTIVE_DOMAIN}/${typePath}/${cleanNs}/${cleanName}`;
}

/**
 * Parse a SPIFFE ID into components.
 * @param {string} spiffeId
 * @returns {{ domain: string, type: string, namespace: string, name: string } | null}
 */
function parseSpiffeId(spiffeId) {
  const match = spiffeId?.match(/^spiffe:\/\/([^/]+)\/(.+)\/([^/]+)\/([^/]+)$/);
  if (!match) return null;
  return { domain: match[1], type: match[2], namespace: match[3], name: match[4] };
}

module.exports = {
  generateSpiffeId,
  parseSpiffeId,
  EFFECTIVE_DOMAIN,
};
