/**
 * NHI Enrichment Engine
 * Extracts meaningful context from raw API workload data by mining:
 *   - labels (docker compose service names, vendor, owner, etc.)
 *   - metadata (image names, runtime, IAM roles, ports)
 *   - spiffe_id path segments
 *   - naming conventions
 */

/* ────────────────────────────────────────────
   Category inference
   ──────────────────────────────────────────── */

const KNOWN_SERVICES = {
  postgres:   { category: 'Database',        subcategory: 'PostgreSQL',   icon: '🐘' },
  redis:      { category: 'Database',        subcategory: 'Redis',        icon: '🔴' },
  mongo:      { category: 'Database',        subcategory: 'MongoDB',      icon: '🍃' },
  mysql:      { category: 'Database',        subcategory: 'MySQL',        icon: '🐬' },
  vault:      { category: 'Secrets Manager', subcategory: 'HashiCorp Vault', icon: '🔐' },
  opa:        { category: 'Policy Engine',   subcategory: 'OPA',          icon: '🛡️' },
  nginx:      { category: 'Gateway',         subcategory: 'Nginx',        icon: '🌐' },
  envoy:      { category: 'Gateway',         subcategory: 'Envoy Proxy',  icon: '🌐' },
  traefik:    { category: 'Gateway',         subcategory: 'Traefik',      icon: '🌐' },
  rabbitmq:   { category: 'Message Queue',   subcategory: 'RabbitMQ',     icon: '🐇' },
  kafka:      { category: 'Message Queue',   subcategory: 'Kafka',        icon: '📨' },
  grafana:    { category: 'Observability',   subcategory: 'Grafana',      icon: '📊' },
  prometheus: { category: 'Observability',   subcategory: 'Prometheus',   icon: '📈' },
};

function inferCategory(w) {
  // If API already classified it meaningfully, keep it
  if (w.category && w.category !== 'unknown') {
    return { category: w.category, subcategory: w.subcategory || null };
  }

  // Mine the compose service name from labels
  const composeSvc = w.labels?.['com.docker.compose.service'] || '';
  // Mine the image name from metadata
  const image = (w.metadata?.image || '').toLowerCase();
  // Combine all searchable text
  const haystack = `${w.name} ${composeSvc} ${image} ${w.spiffe_id || ''}`.toLowerCase();

  // Check known services
  for (const [key, info] of Object.entries(KNOWN_SERVICES)) {
    if (haystack.includes(key)) {
      return { category: info.category, subcategory: info.subcategory, _icon: info.icon };
    }
  }

  // Infer from naming patterns
  if (haystack.includes('token') || haystack.includes('auth')) return { category: 'Auth Service', subcategory: 'Token' };
  if (haystack.includes('credential') || haystack.includes('broker')) return { category: 'Auth Service', subcategory: 'Credential Broker' };
  if (haystack.includes('audit')) return { category: 'Audit', subcategory: 'Audit Service' };
  if (haystack.includes('discovery')) return { category: 'Platform', subcategory: 'Discovery Service' };
  if (haystack.includes('policy') || haystack.includes('sync')) return { category: 'Platform', subcategory: 'Policy Sync' };
  if (haystack.includes('payment') || haystack.includes('billing')) return { category: 'Microservice', subcategory: 'Payments' };
  if (haystack.includes('deploy') || haystack.includes('ci') || haystack.includes('cd')) return { category: 'CI/CD', subcategory: 'Deployment' };

  return { category: w.category || 'Unknown', subcategory: null };
}

/* ────────────────────────────────────────────
   Vendor / product extraction from labels
   ──────────────────────────────────────────── */

function extractVendor(w) {
  const labels = w.labels || {};
  // Docker labels often have vendor info
  if (labels.vendor) return labels.vendor;
  if (labels['org.opencontainers.image.vendor']) return labels['org.opencontainers.image.vendor'];
  // Check image name for known vendors
  const image = (w.metadata?.image || '').toLowerCase();
  if (image.includes('hashicorp')) return 'HashiCorp';
  if (image.includes('openpolicyagent')) return 'Open Policy Agent';
  if (image.includes('postgres')) return 'PostgreSQL';
  if (image.includes('redis')) return 'Redis';
  if (image.includes('nginx')) return 'Nginx';
  // AI providers from labels
  if (labels['ai-provider']) return labels['ai-provider'].charAt(0).toUpperCase() + labels['ai-provider'].slice(1);
  return null;
}

/* ────────────────────────────────────────────
   Owner extraction (check multiple sources)
   ──────────────────────────────────────────── */

function extractOwner(w) {
  if (w.owner) return w.owner;
  if (w.labels?.owner) return w.labels.owner;
  if (w.labels?.maintainer) {
    // Clean "Name <email>" format
    const match = w.labels.maintainer.match(/<(.+?)>/);
    return match ? match[1] : w.labels.maintainer;
  }
  if (w.team) return `${w.team} (team)`;
  return null;
}

/* ────────────────────────────────────────────
   Runtime / image enrichment
   ──────────────────────────────────────────── */

function extractRuntime(w) {
  // Lambda: use metadata.runtime directly
  if (w.metadata?.runtime) return w.metadata.runtime;
  // Docker: extract from image tag
  const image = w.metadata?.image || '';
  if (image) {
    // Shorten "workload-identity-platform-xxx" to just the service name
    const short = image.replace('workload-identity-platform-', '').split(':')[0];
    return short;
  }
  return null;
}

function extractImageVersion(w) {
  const image = w.metadata?.image || '';
  if (image.includes(':')) return image.split(':').pop();
  return null;
}

/* ────────────────────────────────────────────
   Port / network info
   ──────────────────────────────────────────── */

function extractPorts(w) {
  const ports = w.metadata?.ports;
  if (!ports || !Array.isArray(ports)) return null;
  // Dedupe public ports
  const unique = [...new Set(ports.filter(p => p.PublicPort).map(p => p.PublicPort))];
  return unique.length > 0 ? unique : null;
}

/* ────────────────────────────────────────────
   Container health for Docker workloads
   ──────────────────────────────────────────── */

function extractHealth(w) {
  const status = w.metadata?.status || '';
  if (status.includes('healthy') && !status.includes('unhealthy')) return 'healthy';
  if (status.includes('unhealthy')) return 'unhealthy';
  if (w.metadata?.state === 'running') return 'running';
  return w.metadata?.state || null;
}

/* ────────────────────────────────────────────
   Risk derivation — correlates score AND trust level
   A VERY-HIGH trust workload can never be "Critical" risk.
   ──────────────────────────────────────────── */

// Trust level sets a risk ceiling (can't be worse than this)
const TRUST_RISK_CEILING = {
  'cryptographic': 'Low',
  'very-high': 'Low',
  'high': 'Medium',
  'medium': 'Medium',
  'low': 'High',
  'none': 'Critical'
};

// Trust level sets a score floor (client-side, until backend correlation deploys)
const TRUST_SCORE_FLOOR = {
  'cryptographic': 90,
  'very-high': 80,
  'high': 70,
  'medium': 55,
  'low': 40,
  'none': 0
};

const RISK_ORDER = ['Low', 'Medium', 'High', 'Critical'];

function deriveRisk(score, trustLevel) {
  // Risk from score
  let scoreRisk;
  if (score == null) scoreRisk = 'Medium';
  else if (score >= 90) scoreRisk = 'Low';
  else if (score >= 70) scoreRisk = 'Medium';
  else if (score >= 40) scoreRisk = 'High';
  else scoreRisk = 'Critical';

  // Cap risk based on trust level (trust overrides score when trust is verified)
  const ceiling = TRUST_RISK_CEILING[trustLevel] || 'Critical';
  const ceilingIdx = RISK_ORDER.indexOf(ceiling);
  const scoreIdx = RISK_ORDER.indexOf(scoreRisk);

  // Return the lower risk (better) of the two
  return RISK_ORDER[Math.min(ceilingIdx, scoreIdx)];
}

// Client-side score correction: if backend hasn't correlated yet, apply trust floor
function deriveScore(rawScore, trustLevel) {
  const floor = TRUST_SCORE_FLOOR[trustLevel] || 0;
  return Math.max(rawScore || 0, floor);
}

function deriveTrust(trust_level, score) {
  const map = { cryptographic: 5, 'very-high': 5, high: 4, medium: 3, low: 2, none: 1 };
  if (trust_level && map[trust_level]) return map[trust_level];
  if (score != null) return Math.min(5, Math.max(1, Math.round(score / 20)));
  return 1;
}

/* ────────────────────────────────────────────
   Age calculation (how old is this workload)
   ──────────────────────────────────────────── */

function calculateAge(w) {
  const modified = w.metadata?.last_modified;
  if (modified) return modified;
  return w.created_at || null;
}

/* ────────────────────────────────────────────
   Main enrichment function
   ──────────────────────────────────────────── */

export function enrichWorkload(w) {
  const cat = inferCategory(w);
  const correctedScore = deriveScore(w.security_score, w.trust_level);
  
  return {
    ...w,
    // Client-side corrected score (until backend correlation is deployed)
    security_score: correctedScore,
    // Classification fields passed through from server-side classifyWorkload()
    // (no client-side overrides — classification is authoritative from backend)
    // Enriched fields (prefixed with _ to distinguish from raw API)
    _category: cat.category,
    _subcategory: cat.subcategory || w.subcategory,
    _categoryIcon: cat._icon || getCategoryIcon(cat.category, w),
    _risk: deriveRisk(correctedScore, w.trust_level),
    _trust: deriveTrust(w.trust_level, correctedScore),
    _vendor: extractVendor(w),
    _owner: extractOwner(w),
    _runtime: extractRuntime(w),
    _imageVersion: extractImageVersion(w),
    _ports: extractPorts(w),
    _health: extractHealth(w),
    _age: calculateAge(w),
    _labels: extractImportantLabels(w),
  };
}

function getCategoryIcon(category, w) {
  if (w.is_ai_agent) return '🧠';
  if (w.is_mcp_server) return '🔌';
  const map = {
    'Database': '🗄️', 'Secrets Manager': '🔐', 'Policy Engine': '🛡️',
    'Gateway': '🌐', 'Message Queue': '📨', 'Observability': '📊',
    'Auth Service': '🔑', 'Audit': '📋', 'Platform': '⚙️',
    'Microservice': '📦', 'CI/CD': '🚀', 'ai-agent': '🧠',
    'mcp-server': '🔌', 'agent': '🤖',
    // New NHI types from credential scanners
    'iam-role': '🎭', 'lambda-execution-role': '🎭', 'ec2-instance-role': '🎭',
    'ecs-task-role': '🎭', 'admin-role': '⚠️', 'service-linked-role': '🔗',
    'service-account': '🤖', 'iam-user': '👤',
    'secrets-manager': '🔐', 'secret': '🔒',
    'service-token': '🎟️', 'certificate': '📜', 'auth-service': '🔑',
    'ci-cd': '🚀',
  };
  return map[category] || '📦';
}

function extractImportantLabels(w) {
  const labels = w.labels || {};
  const important = {};
  
  // Pick out the most relevant labels
  const interestingKeys = [
    'environment', 'team', 'owner', 'category', 'pci-compliant',
    'ai-provider', 'model', 'mcp-type', 'STAGE', 'version',
  ];
  
  for (const key of interestingKeys) {
    if (labels[key]) important[key] = labels[key];
  }
  
  return Object.keys(important).length > 0 ? important : null;
}

/* ────────────────────────────────────────────
   Time utilities
   ──────────────────────────────────────────── */

export function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const then = new Date(dateStr).getTime();
  if (isNaN(then)) return '—';
  const diff = Date.now() - then;
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

export function formatAge(dateStr) {
  if (!dateStr) return null;
  const then = new Date(dateStr).getTime();
  if (isNaN(then)) return null;
  const diff = Date.now() - then;
  const days = Math.floor(diff / 86400000);
  if (days < 1) return 'Today';
  if (days < 30) return `${days}d old`;
  if (days < 365) return `${Math.floor(days / 30)}mo old`;
  return `${Math.floor(days / 365)}y old`;
}