// =============================================================================
// Protocol Scanner — MCP Server & A2A Agent Detection
// =============================================================================
// Runs inside the Discovery Service alongside the relationship scanner.
// After workload discovery finds services, this scanner:
//   1. Fingerprints each workload for MCP/A2A protocol signals
//   2. Probes reachable endpoints (Agent Card, JSON-RPC initialize)
//   3. Maps environment variables to external API credentials
//   4. Returns nodes + relationships + findings for the identity graph
//
// Integration (in relationship-scanner.js discover() after Phase 3):
//   const ProtocolScanner = require('./protocol-scanner');
//   const proto = new ProtocolScanner();
//   const results = await proto.scan(workloads);
//   results.nodes.forEach(n => this.addNode(n));
//   results.relationships.forEach(r => this.addRel(r));
// =============================================================================

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// ── External API credential patterns ─────────────────────────────────────────

const EXTERNAL_APIS = {
  salesforce: {
    keys: ['SALESFORCE_TOKEN', 'SALESFORCE_API_KEY', 'SF_ACCESS_TOKEN', 'SF_CLIENT_ID',
           'SF_CLIENT_SECRET', 'SALESFORCE_INSTANCE_URL', 'SF_REFRESH_TOKEN'],
    label: 'Salesforce', category: 'crm',
  },
  stripe: {
    keys: ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY', 'STRIPE_PUBLISHABLE_KEY',
           'STRIPE_WEBHOOK_SECRET', 'STRIPE_CONNECT_SECRET'],
    label: 'Stripe', category: 'financial',
  },
  slack: {
    keys: ['SLACK_TOKEN', 'SLACK_BOT_TOKEN', 'SLACK_API_TOKEN', 'SLACK_WEBHOOK_URL',
           'SLACK_SIGNING_SECRET', 'SLACK_APP_TOKEN'],
    label: 'Slack', category: 'communication',
  },
  github: {
    keys: ['GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT', 'GITHUB_APP_PRIVATE_KEY',
           'GITHUB_APP_ID', 'GH_APP_KEY'],
    label: 'GitHub', category: 'devops',
  },
  openai: {
    keys: ['OPENAI_API_KEY', 'OPENAI_ORG_ID'],
    label: 'OpenAI', category: 'ai-provider',
  },
  anthropic: {
    keys: ['ANTHROPIC_API_KEY'],
    label: 'Anthropic', category: 'ai-provider',
  },
  bigquery: {
    keys: ['BIGQUERY_CREDENTIALS', 'GOOGLE_APPLICATION_CREDENTIALS'],
    label: 'BigQuery', category: 'data',
  },
  snowflake: {
    keys: ['SNOWFLAKE_ACCOUNT', 'SNOWFLAKE_PASSWORD', 'SNOWFLAKE_PRIVATE_KEY'],
    label: 'Snowflake', category: 'data',
  },
  twilio: {
    keys: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN'],
    label: 'Twilio', category: 'communication',
  },
  sendgrid: {
    keys: ['SENDGRID_API_KEY'],
    label: 'SendGrid', category: 'communication',
  },
  datadog: {
    keys: ['DD_API_KEY', 'DATADOG_API_KEY', 'DD_APP_KEY'],
    label: 'Datadog', category: 'observability',
  },
  pagerduty: {
    keys: ['PAGERDUTY_TOKEN', 'PAGERDUTY_API_KEY'],
    label: 'PagerDuty', category: 'observability',
  },
  jira: {
    keys: ['JIRA_TOKEN', 'JIRA_API_TOKEN', 'JIRA_PAT', 'ATLASSIAN_API_KEY'],
    label: 'Jira', category: 'devops',
  },
  servicenow: {
    keys: ['SERVICENOW_API_KEY', 'SN_API_KEY', 'SNOW_TOKEN'],
    label: 'ServiceNow', category: 'itsm',
  },
  workday: {
    keys: ['WORKDAY_TOKEN', 'WORKDAY_API_KEY', 'WD_CLIENT_SECRET'],
    label: 'Workday', category: 'hr',
  },
  epic: {
    keys: ['EPIC_FHIR_TOKEN', 'EPIC_CLIENT_SECRET', 'EPIC_API_KEY'],
    label: 'Epic FHIR', category: 'healthcare',
  },
  snyk: {
    keys: ['SNYK_TOKEN', 'SNYK_API_TOKEN'],
    label: 'Snyk', category: 'security',
  },
  zendesk: {
    keys: ['ZENDESK_API_TOKEN', 'ZENDESK_TOKEN', 'ZD_API_KEY'],
    label: 'Zendesk', category: 'support',
  },
  sonarqube: {
    keys: ['SONAR_TOKEN', 'SONARQUBE_TOKEN', 'SONAR_API_KEY'],
    label: 'SonarQube', category: 'security',
  },
};

// ── Static detection patterns ────────────────────────────────────────────────

const MCP_SIGNALS = {
  images: [/mcp-server/i, /modelcontextprotocol/i, /@modelcontextprotocol\//, /mcp-.*-server/i],
  env: ['MCP_SERVER_URL', 'MCP_SERVER_PORT', 'MCP_TRANSPORT', 'MCP_AUTH_TOKEN'],
  labels: ['mcp.server', 'mcp.transport', 'mcp.protocol', 'ai.mcp.server'],
  cmd: [/mcp[-_]server|modelcontextprotocol/i],
};

const A2A_SIGNALS = {
  images: [/a2a-agent/i, /agent2agent/i, /a2a-server/i],
  env: ['A2A_AGENT_URL', 'A2A_AGENT_CARD', 'A2A_PORT', 'A2A_AUTH_TYPE'],
  labels: ['a2a.agent', 'a2a.protocol', 'a2a.skills', 'ai.a2a.agent'],
};

// ── Tool Poisoning Detection Patterns ────────────────────────────────────────
// 7.2% of MCP servers have exploitable flaws, 5.5% have tool poisoning.
// These patterns detect hidden instructions in tool descriptions that attempt
// prompt injection, credential exfiltration, or unauthorized actions.

const TOOL_POISONING_PATTERNS = [
  // Prompt injection — override system/user instructions
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, type: 'prompt-injection', severity: 'critical' },
  { pattern: /ignore\s+(all\s+)?prior\s+(instructions|context)/i, type: 'prompt-injection', severity: 'critical' },
  { pattern: /disregard\s+(all\s+)?previous/i, type: 'prompt-injection', severity: 'critical' },
  { pattern: /you\s+are\s+now\s+/i, type: 'prompt-injection', severity: 'critical' },
  { pattern: /new\s+instructions?\s*:/i, type: 'prompt-injection', severity: 'critical' },
  { pattern: /system\s*:\s*/i, type: 'prompt-injection', severity: 'high' },
  { pattern: /\[INST\]/i, type: 'prompt-injection', severity: 'high' },
  { pattern: /<\|im_start\|>/i, type: 'prompt-injection', severity: 'high' },

  // Hidden instructions — invisible unicode or base64 encoded content
  { pattern: /[\u200B\u200C\u200D\uFEFF\u00AD]{3,}/u, type: 'hidden-text', severity: 'critical' },
  { pattern: /base64[:\s]+[A-Za-z0-9+/=]{20,}/i, type: 'encoded-payload', severity: 'high' },
  { pattern: /eval\s*\(/i, type: 'code-execution', severity: 'critical' },
  { pattern: /exec\s*\(\s*['"`]/i, type: 'code-execution', severity: 'critical' },

  // Credential exfiltration — instructions to send data to external URLs
  { pattern: /send\s+(the\s+)?(data|results?|output|credentials?|tokens?|keys?)\s+to\s+/i, type: 'exfiltration', severity: 'critical' },
  { pattern: /forward\s+(all\s+)?(data|results?|output)\s+to\s+/i, type: 'exfiltration', severity: 'critical' },
  { pattern: /https?:\/\/[^\s]+\.(xyz|tk|ml|ga|cf|pw|top|click|buzz)\b/i, type: 'suspicious-url', severity: 'high' },
  { pattern: /webhook\.site|requestbin|pipedream\.net|hookbin/i, type: 'suspicious-url', severity: 'critical' },
  { pattern: /ngrok\.io|localtunnel|serveo\.net/i, type: 'suspicious-url', severity: 'high' },

  // Privilege escalation — attempts to invoke other tools or gain access
  { pattern: /also\s+(call|invoke|run|execute)\s+/i, type: 'tool-hijack', severity: 'high' },
  { pattern: /before\s+returning.*call\s+/i, type: 'tool-hijack', severity: 'high' },
  { pattern: /silently\s+(call|invoke|run|execute|send)/i, type: 'tool-hijack', severity: 'critical' },
  { pattern: /do\s+not\s+(tell|inform|notify|show)\s+(the\s+)?user/i, type: 'stealth', severity: 'critical' },
  { pattern: /without\s+(the\s+)?user('s)?\s+(knowledge|knowing|consent)/i, type: 'stealth', severity: 'critical' },
];

// Known-good MCP server registry — curated list of verified packages
// In production this would be a remote registry service; for now, a local allowlist
const MCP_KNOWN_GOOD_REGISTRY = {
  // Official Anthropic MCP servers
  '@modelcontextprotocol/server-filesystem': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-github': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-postgres': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-slack': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-memory': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-puppeteer': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-brave-search': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-google-maps': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-fetch': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-sequentialthinking': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  '@modelcontextprotocol/server-everything': { verified: true, publisher: 'Anthropic', min_version: '0.5.0' },
  // Popular community servers with verified publishers
  'mcp-server-sqlite': { verified: true, publisher: 'community', min_version: '0.3.0' },
};

// ═══════════════════════════════════════════════════════════════════════════════
// AI Agent Enrichment — LLM providers, models, embeddings, vector stores
//
// Detects which AI/ML services an agent uses by scanning env vars, labels,
// and container metadata. Builds a structured ai_enrichment profile.
// ═══════════════════════════════════════════════════════════════════════════════

const AI_PROVIDERS = {
  openai: {
    keys: ['OPENAI_API_KEY', 'OPENAI_ORG_ID', 'OPENAI_PROJECT_ID', 'OPENAI_API_BASE'],
    label: 'OpenAI', category: 'llm-provider',
    models: ['OPENAI_MODEL', 'GPT_MODEL', 'OPENAI_MODEL_NAME', 'OPENAI_DEPLOYMENT'],
    modelPatterns: [/gpt-4o?(-mini|-turbo)?/i, /o[1-3](-mini|-preview)?/i, /chatgpt/i, /dall-e/i, /whisper/i, /tts/i],
    defaultModel: 'gpt-4o',
    scopes: { chat: 'Chat completions', embeddings: 'Text embeddings', images: 'Image generation', audio: 'Speech/transcription', files: 'File management', 'fine-tuning': 'Model fine-tuning', assistants: 'Assistants API' },
  },
  anthropic: {
    keys: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_PROJECT_ID'],
    label: 'Anthropic', category: 'llm-provider',
    models: ['ANTHROPIC_MODEL', 'CLAUDE_MODEL', 'ANTHROPIC_MODEL_NAME'],
    modelPatterns: [/claude-[34](\.\d)?(-sonnet|-opus|-haiku)/i, /claude-instant/i],
    defaultModel: 'claude-sonnet-4-5-20250514',
    scopes: { messages: 'Message completions', tools: 'Tool use', vision: 'Image analysis', batches: 'Batch processing' },
  },
  google_ai: {
    keys: ['GOOGLE_AI_API_KEY', 'GEMINI_API_KEY', 'VERTEX_AI_PROJECT', 'GOOGLE_GENAI_API_KEY'],
    label: 'Google AI / Gemini', category: 'llm-provider',
    models: ['GEMINI_MODEL', 'GOOGLE_AI_MODEL', 'VERTEX_MODEL'],
    modelPatterns: [/gemini-(pro|ultra|flash|nano|1\.5|2\.0)/i, /palm/i],
    defaultModel: 'gemini-2.0-flash',
    scopes: { generate: 'Content generation', embed: 'Embeddings', vision: 'Multimodal', code: 'Code generation' },
  },
  azure_openai: {
    keys: ['AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT', 'AZURE_OPENAI_DEPLOYMENT'],
    label: 'Azure OpenAI', category: 'llm-provider',
    models: ['AZURE_OPENAI_DEPLOYMENT', 'AZURE_OPENAI_MODEL'],
    modelPatterns: [/gpt-4/i, /gpt-35-turbo/i],
    defaultModel: 'gpt-4',
    scopes: { completions: 'Chat completions', embeddings: 'Embeddings', images: 'DALL-E' },
  },
  cohere: {
    keys: ['COHERE_API_KEY', 'CO_API_KEY'],
    label: 'Cohere', category: 'llm-provider',
    models: ['COHERE_MODEL'], modelPatterns: [/command(-r|-light|-nightly)?/i, /embed-/i],
    defaultModel: 'command-r-plus', scopes: { generate: 'Text generation', embed: 'Embeddings', rerank: 'Reranking' },
  },
  mistral: {
    keys: ['MISTRAL_API_KEY'],
    label: 'Mistral AI', category: 'llm-provider',
    models: ['MISTRAL_MODEL'], modelPatterns: [/mistral-(large|medium|small|tiny|7b)/i, /mixtral/i, /codestral/i],
    defaultModel: 'mistral-large', scopes: { chat: 'Chat', embed: 'Embeddings', code: 'Code generation' },
  },
  huggingface: {
    keys: ['HUGGINGFACE_TOKEN', 'HF_TOKEN', 'HUGGINGFACE_API_KEY', 'HF_API_KEY'],
    label: 'Hugging Face', category: 'ml-platform',
    models: ['HF_MODEL', 'HUGGINGFACE_MODEL'], modelPatterns: [/meta-llama/i, /bert/i, /t5/i, /stable-diffusion/i],
    scopes: { inference: 'Inference API', spaces: 'Spaces', models: 'Model Hub' },
  },
  replicate: {
    keys: ['REPLICATE_API_TOKEN', 'REPLICATE_API_KEY'],
    label: 'Replicate', category: 'ml-platform',
    models: ['REPLICATE_MODEL'], modelPatterns: [/replicate\//i],
    scopes: { predictions: 'Run models', models: 'Model management' },
  },
  aws_bedrock: {
    keys: ['AWS_BEDROCK_REGION', 'BEDROCK_MODEL_ID', 'AWS_BEDROCK_ENDPOINT'],
    label: 'AWS Bedrock', category: 'llm-provider',
    models: ['BEDROCK_MODEL_ID', 'AWS_BEDROCK_MODEL'], modelPatterns: [/anthropic\.claude/i, /amazon\.titan/i, /ai21\.jamba/i, /meta\.llama/i],
    scopes: { invoke: 'Model invocation', agents: 'Bedrock Agents', knowledge: 'Knowledge Bases' },
  },
  groq: {
    keys: ['GROQ_API_KEY', 'GROQ_ORG_ID'],
    label: 'Groq', category: 'llm-provider',
    models: ['GROQ_MODEL'], modelPatterns: [/llama-3/i, /mixtral/i, /gemma/i],
    defaultModel: 'llama-3-70b',
    scopes: { chat: 'Chat completions' },
  },
  together: {
    keys: ['TOGETHER_API_KEY', 'TOGETHERAI_API_KEY'],
    label: 'Together AI', category: 'llm-provider',
    models: ['TOGETHER_MODEL'], modelPatterns: [/together\//i],
    scopes: { inference: 'Inference', fine_tuning: 'Fine-tuning' },
  },
  fireworks: {
    keys: ['FIREWORKS_API_KEY', 'FIREWORKS_ACCOUNT_ID'],
    label: 'Fireworks AI', category: 'llm-provider',
    models: ['FIREWORKS_MODEL'], modelPatterns: [/fireworks/i],
    scopes: { inference: 'Inference' },
  },
  deepseek: {
    keys: ['DEEPSEEK_API_KEY'],
    label: 'DeepSeek', category: 'llm-provider',
    models: ['DEEPSEEK_MODEL'], modelPatterns: [/deepseek-(chat|coder|r1|v[23])/i],
    defaultModel: 'deepseek-chat',
    scopes: { chat: 'Chat completions', code: 'Code generation' },
  },
};

const EMBEDDING_STORES = {
  pinecone: {
    keys: ['PINECONE_API_KEY', 'PINECONE_ENVIRONMENT', 'PINECONE_INDEX', 'PINECONE_PROJECT_ID'],
    label: 'Pinecone', category: 'vector-store',
  },
  weaviate: {
    keys: ['WEAVIATE_URL', 'WEAVIATE_API_KEY', 'WEAVIATE_CLUSTER_URL'],
    label: 'Weaviate', category: 'vector-store',
  },
  chromadb: {
    keys: ['CHROMA_HOST', 'CHROMA_API_KEY', 'CHROMADB_URL', 'CHROMA_SERVER_URL'],
    label: 'ChromaDB', category: 'vector-store',
  },
  qdrant: {
    keys: ['QDRANT_URL', 'QDRANT_API_KEY', 'QDRANT_HOST'],
    label: 'Qdrant', category: 'vector-store',
  },
  milvus: {
    keys: ['MILVUS_HOST', 'MILVUS_URI', 'MILVUS_TOKEN'],
    label: 'Milvus', category: 'vector-store',
  },
  pgvector: {
    keys: ['PGVECTOR_CONNECTION', 'VECTOR_DB_URL'],
    label: 'pgvector', category: 'vector-store',
  },
  supabase_vector: {
    keys: ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'],
    label: 'Supabase Vector', category: 'vector-store',
  },
};

const FINE_TUNING_SIGNALS = {
  env: ['FINE_TUNED_MODEL', 'FT_MODEL_ID', 'CUSTOM_MODEL_ID', 'FINE_TUNE_SUFFIX',
        'TRAINING_DATA_PATH', 'LORA_ADAPTER', 'PEFT_MODEL_ID', 'RLHF_REWARD_MODEL'],
  patterns: [/ft[:-]gpt/i, /ft[:-]claude/i, /fine[-_]tuned/i, /custom[-_]model/i, /lora/i, /qlora/i, /peft/i],
};

const FRAMEWORK_SIGNALS = {
  langchain: { keys: ['LANGCHAIN_API_KEY', 'LANGCHAIN_TRACING_V2', 'LANGCHAIN_PROJECT', 'LANGSMITH_API_KEY'], label: 'LangChain / LangSmith' },
  llamaindex: { keys: ['LLAMA_CLOUD_API_KEY', 'LLAMAINDEX_CACHE_DIR'], label: 'LlamaIndex' },
  crewai: { keys: ['CREWAI_API_KEY'], label: 'CrewAI' },
  autogen: { keys: ['AUTOGEN_CONFIG'], label: 'AutoGen' },
  semantic_kernel: { keys: ['SEMANTIC_KERNEL_ENDPOINT'], label: 'Semantic Kernel' },
};

const LLM_GATEWAY_SIGNALS = {
  litellm: {
    keys: ['LITELLM_PROXY_BASE_URL', 'LITELLM_MASTER_KEY', 'LITELLM_API_KEY', 'LITELLM_API_BASE'],
    label: 'LiteLLM', category: 'llm-gateway',
    images: [/litellm/i],
  },
  portkey: {
    keys: ['PORTKEY_API_KEY', 'PORTKEY_GATEWAY_URL', 'PORTKEY_BASE_URL'],
    label: 'Portkey', category: 'llm-gateway',
    images: [/portkey/i],
  },
  helicone: {
    keys: ['HELICONE_API_KEY', 'HELICONE_BASE_URL'],
    label: 'Helicone', category: 'llm-gateway',
    images: [/helicone/i],
  },
  langfuse: {
    keys: ['LANGFUSE_SECRET_KEY', 'LANGFUSE_PUBLIC_KEY', 'LANGFUSE_HOST', 'LANGFUSE_BASEURL'],
    label: 'Langfuse', category: 'llm-observability',
  },
  arize_phoenix: {
    keys: ['PHOENIX_COLLECTOR_ENDPOINT', 'ARIZE_API_KEY', 'ARIZE_SPACE_KEY'],
    label: 'Arize / Phoenix', category: 'llm-observability',
  },
  braintrust: {
    keys: ['BRAINTRUST_API_KEY', 'BRAINTRUST_PROJECT'],
    label: 'Braintrust', category: 'llm-observability',
  },
  promptlayer: {
    keys: ['PROMPTLAYER_API_KEY'],
    label: 'PromptLayer', category: 'llm-observability',
  },
};

const AI_EGRESS_ENDPOINTS = [
  { pattern: /api\.openai\.com/i, provider: 'openai', label: 'OpenAI API' },
  { pattern: /api\.anthropic\.com/i, provider: 'anthropic', label: 'Anthropic API' },
  { pattern: /generativelanguage\.googleapis\.com/i, provider: 'google', label: 'Google Generative AI' },
  { pattern: /bedrock-runtime\..+\.amazonaws\.com/i, provider: 'bedrock', label: 'AWS Bedrock' },
  { pattern: /\.openai\.azure\.com/i, provider: 'azure_openai', label: 'Azure OpenAI' },
  { pattern: /api\.cohere\.ai/i, provider: 'cohere', label: 'Cohere API' },
  { pattern: /api\.mistral\.ai/i, provider: 'mistral', label: 'Mistral API' },
  { pattern: /api\.groq\.com/i, provider: 'groq', label: 'Groq API' },
  { pattern: /api\.together\.xyz/i, provider: 'together', label: 'Together AI API' },
  { pattern: /api\.fireworks\.ai/i, provider: 'fireworks', label: 'Fireworks API' },
  { pattern: /api\.deepseek\.com/i, provider: 'deepseek', label: 'DeepSeek API' },
];


class ProtocolScanner {
  constructor(config = {}) {
    this.timeout = config.probeTimeout || 3000;
    // P0.3: Active probing is opt-in only to prevent SSRF
    this.activeProbeEnabled = config.activeProbe ?? (process.env.PROTOCOL_ACTIVE_PROBE === 'true');
    this.probeAllowlist = (process.env.PROTOCOL_PROBE_ALLOWLIST || '').split(',').filter(Boolean);
    // DB-driven provider registry (falls back to hardcoded defaults if not initialized)
    const { ProviderRegistry } = require('./provider-registry');
    this.registry = config.providerRegistry || ProviderRegistry.getInstance();
    this.nodes = [];
    this.relationships = [];
    this.findings = [];
    this._nids = new Set();
    this._rkeys = new Set();
  }

  _add(n) { if (!this._nids.has(n.id)) { this._nids.add(n.id); this.nodes.push(n); } }
  _rel(r) {
    const k = `${r.source}|${r.target}|${r.type}`;
    if (!this._rkeys.has(k)) { this._rkeys.add(k); this.relationships.push({ ...r, id: k }); }
  }

  log(msg, lvl = 'info') {
    const p = { info: '  ℹ️', success: '  ✓', error: '  ✗', warn: '  ⚠️' }[lvl] || '  ';
    console.log(`${p} [protocol] ${msg}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Main entry — called from RelationshipScanner.discover()
  // ═══════════════════════════════════════════════════════════════════════════

  async scan(workloads) {
    this.nodes = []; this.relationships = []; this.findings = [];
    this._nids = new Set(); this._rkeys = new Set();

    this.log(`Scanning ${workloads.length} workloads for MCP/A2A protocols`);

    for (const w of workloads) {
      const wNodeId = `w:${w.id || w.name}`;

      // 1 — Static signal scoring
      const mcpScore = this._scoreMCP(w);
      const a2aScore = this._scoreA2A(w);

      // 2 — External API credential detection (static env vars)
      const extAPIs = this._detectAPIs(w);

      // 2b — Health endpoint credential self-reporting (P0.3: gated by active probe flag)
      const url = this._getUrl(w);
      if (url && this.activeProbeEnabled) {
        const urlHost = new URL(url).hostname;
        const allowed = this.probeAllowlist.length === 0 || this.probeAllowlist.some(h => urlHost.endsWith(h));
        if (allowed) {
          const healthCreds = await this._probeHealthCredentials(url);
          const existingIds = new Set(extAPIs.map(a => a.id));
          for (const hc of healthCreds) {
            if (!existingIds.has(hc.id)) {
              extAPIs.push(hc);
              existingIds.add(hc.id);
            }
          }
        }
      } else if (!url) {
        // no-op: no URL to probe
      }

      // 3 — Active probing (P0.3: opt-in only, with allowlist)
      this.log(`Workload: ${w.name} | type: ${w.type} | url: ${url || 'NONE'} | probe: ${this.activeProbeEnabled ? 'ON' : 'OFF'}`);
      let a2aCard = null;
      let mcpCaps = null;

      if (url && this.activeProbeEnabled) {
        // Allowlist check: if allowlist is configured, only probe matching hosts
        const urlHost = new URL(url).hostname;
        const allowed = this.probeAllowlist.length === 0 || this.probeAllowlist.some(h => urlHost.endsWith(h));
        if (allowed) {
          a2aCard = await this._probeA2A(url);
          mcpCaps = await this._probeMCP(url);
        } else {
          this.log(`Skipping probe for ${urlHost} — not in PROTOCOL_PROBE_ALLOWLIST`, 'warn');
        }
      }

      // 4 — Add detected protocols to graph
      if (a2aCard || a2aScore.total >= 2) this._addA2A(w, wNodeId, a2aCard, a2aScore);
      if (mcpCaps || mcpScore.total >= 2) this._addMCP(w, wNodeId, mcpCaps, mcpScore);

      // 5 — External API credential nodes
      for (const api of extAPIs) this._addExtAPI(wNodeId, api, w);
    }

    // 6 — Cross-cutting relationships
    this._linkAgents();

    // 7 — Toxic combo detection
    this._detectToxicCombos();

    // 8 — AI Agent enrichment (LLM providers, models, embeddings, vector stores)
    const aiEnrichments = {};
    for (const w of workloads) {
      const enrichment = this.enrichAIAgent(w);
      if (enrichment.llm_providers.length > 0 || enrichment.embeddings_and_vectors.length > 0 || enrichment.frameworks.length > 0) {
        aiEnrichments[w.id || w.name] = enrichment;
        this.log(`AI enrichment for ${w.name}: ${enrichment.llm_providers.length} providers, ${enrichment.models.length} models, ${enrichment.embeddings_and_vectors.length} vector stores`, 'success');
      }
    }

    this.log(`Done: ${this.nodes.length} nodes, ${this.relationships.length} edges, ${this.findings.length} findings, ${Object.keys(aiEnrichments).length} AI profiles`, 'success');

    return {
      nodes: this.nodes,
      relationships: this.relationships,
      findings: this.findings,
      aiEnrichments,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Signal Scoring
  // ═══════════════════════════════════════════════════════════════════════════

  _scoreMCP(w) {
    const signals = [];
    let total = 0;
    const img = w.metadata?.image || '';
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    const lbl = w.labels || w.metadata?.labels || {};
    const cmd = w.metadata?.command || '';

    if (MCP_SIGNALS.images.some(p => p.test(img))) { total += 3; signals.push(`image:${img}`); }
    for (const k of MCP_SIGNALS.env) if (env[k] !== undefined) { total += 2; signals.push(`env:${k}`); }
    for (const k of MCP_SIGNALS.labels) if (lbl[k] !== undefined) { total += 2; signals.push(`label:${k}`); }
    if (MCP_SIGNALS.cmd.some(p => p.test(cmd))) { total += 2; signals.push('cmd'); }

    return { total, signals };
  }

  _scoreA2A(w) {
    const signals = [];
    let total = 0;
    const img = w.metadata?.image || '';
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    const lbl = w.labels || w.metadata?.labels || {};

    if (A2A_SIGNALS.images.some(p => p.test(img))) { total += 3; signals.push(`image:${img}`); }
    for (const k of A2A_SIGNALS.env) if (env[k] !== undefined) { total += 2; signals.push(`env:${k}`); }
    for (const k of A2A_SIGNALS.labels) if (lbl[k] !== undefined) { total += 2; signals.push(`label:${k}`); }

    return { total, signals };
  }

  _detectAPIs(w) {
    const found = [];
    const foundIds = new Set();
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    const envKeys = Object.keys(env);
    const externalAPIs = this.registry.getExternalAPIs();

    // Pass 1: env-var based detection (original logic)
    for (const [id, pat] of externalAPIs) {
      const matched = pat.keys.filter(k => envKeys.includes(k));
      if (!matched.length) continue;

      // Classify using highest-risk matched key (never downgrade)
      const CRED_RANK = { 'oauth-client': 0, 'api-key': 1, 'token': 2, 'secret-key': 3, 'long-lived-key': 4 };
      let credType = 'api-key', scope = 'unknown', risk = 'medium';
      let hasStaticKey = false;
      for (const k of matched) {
        if (/SECRET|PRIVATE/i.test(k)) {
          if ((CRED_RANK['secret-key'] || 0) > (CRED_RANK[credType] || 0)) credType = 'secret-key';
          risk = 'high'; scope = 'write'; hasStaticKey = true;
        } else if (/TOKEN/i.test(k)) {
          if ((CRED_RANK['token'] || 0) > (CRED_RANK[credType] || 0)) credType = 'token';
          if (scope === 'unknown') scope = 'read';
          hasStaticKey = true;
        } else if (/CLIENT_ID/i.test(k)) {
          // oauth-client only applies if nothing higher has matched
          if (credType === 'api-key') { credType = 'oauth-client'; risk = 'low'; }
        }
        const val = (env[k] || '').toString();
        if (/^(sk-|xoxb-|ghp_|ghs_)/.test(val)) { credType = 'long-lived-key'; risk = 'critical'; hasStaticKey = true; }
      }

      found.push({
        id, label: pat.label, category: pat.category,
        credType, scope, risk, matchedKeys: matched,
        isStatic: hasStaticKey || credType !== 'oauth-client',
      });
      foundIds.add(id);
    }

    // Pass 2: metadata.credentials array (from cloud scanners — GCP, AWS, Azure)
    // Cloud Run redacts env values as [secret], but scanners populate structured credentials.
    // This is critical for GCP Cloud Run where env values are always redacted — the
    // structured credentials array is the only reliable source of credential data.
    const metaCreds = w.metadata?.credentials || [];
    let metaCredsFound = 0;
    for (const cred of metaCreds) {
      const credName = (cred.name || cred.key || '').toUpperCase();
      const credProvider = (cred.provider || cred.api || '').toLowerCase();

      // Match to external APIs by provider name or credential key patterns
      let matchedApiId = null;
      for (const [id, pat] of externalAPIs) {
        if (foundIds.has(id)) continue; // already found via env
        // Direct provider match (e.g., provider='openai' matches EXTERNAL_APIS.openai)
        if (credProvider === id || credProvider === pat.label.toLowerCase()) {
          matchedApiId = id;
          break;
        }
        // Key-name match: credential name contains (or is contained by) a known API key pattern
        if (pat.keys.some(k => credName.includes(k) || k.includes(credName))) {
          matchedApiId = id;
          break;
        }
        // Partial match: credential name contains the API id (e.g., "STRIPE_WEBHOOK_SECRET" contains "stripe")
        if (credName.includes(id.toUpperCase())) {
          matchedApiId = id;
          break;
        }
      }

      // Determine if static: check explicit is_static, then fall back to type/storage_method.
      // GCP scanner sets type='secret_manager_ref' for Secret Manager-backed secrets
      // and type='env_variable' for plain env vars. AWS/Azure use similar conventions.
      const isManagedSecret = cred.type === 'secret_manager_ref'
        || cred.storage_method === 'secret-manager'
        || cred.storage_method === 'secrets-manager'
        || cred.storage_method === 'key-vault'
        || !!cred.secret_manager_ref;
      const isStatic = cred.is_static !== undefined
        ? cred.is_static
        : !isManagedSecret;

      // Even unmatched credentials (no EXTERNAL_APIS hit) should produce findings
      // if they are static — these are unknown-but-risky credentials
      if (!matchedApiId) {
        // Only generate findings for static credentials with recognizable key names
        if (isStatic && credName && /KEY|SECRET|TOKEN|PASSWORD|CRED|API_KEY/i.test(credName)) {
          const inferredCategory = /STRIPE|PAYMENT|PAY/i.test(credName) ? 'financial'
            : /SLACK|TEAMS|EMAIL|SEND/i.test(credName) ? 'communication'
            : /GITHUB|GIT|CI|CD|DEPLOY/i.test(credName) ? 'devops'
            : /OPENAI|ANTHROPIC|GEMINI|BEDROCK|AI|LLM|MODEL/i.test(credName) ? 'ai-provider'
            : /DB|SQL|MONGO|REDIS|POSTGRES/i.test(credName) ? 'data'
            : 'unknown';
          let risk = 'medium';
          if (/SECRET|PRIVATE/i.test(credName)) risk = 'high';
          if (/financial|crm/.test(inferredCategory)) risk = 'critical';
          if (risk === 'medium') risk = 'high'; // static creds are at least high risk

          // Use a synthetic id based on credential name to avoid collisions
          const syntheticId = `unknown:${credName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
          if (!foundIds.has(syntheticId)) {
            found.push({
              id: syntheticId,
              label: credName,
              category: inferredCategory,
              credType: cred.type || 'api-key',
              scope: cred.scope || 'unknown',
              risk,
              matchedKeys: [credName],
              isStatic: true,
              source: 'metadata-credentials',
            });
            foundIds.add(syntheticId);
            metaCredsFound++;
          }
        }
        continue;
      }

      const pat = externalAPIs.get(matchedApiId);

      let credType = cred.type || 'api-key';
      // Normalize GCP scanner types that aren't useful as credType labels
      if (credType === 'secret_manager_ref' || credType === 'env_variable') credType = 'api-key';
      let scope = cred.scope || 'unknown';
      let risk = 'medium';
      if (/secret|private/i.test(credName)) { credType = 'secret-key'; risk = 'high'; scope = 'write'; }
      else if (/token/i.test(credName)) { credType = 'token'; scope = 'read'; }
      if (isStatic && /financial|crm/.test(pat.category)) risk = 'critical';
      if (isStatic && risk === 'medium') risk = 'high';

      found.push({
        id: matchedApiId, label: pat.label, category: pat.category,
        credType, scope, risk,
        matchedKeys: [credName || `${matchedApiId.toUpperCase()}_CREDENTIAL`],
        isStatic,
        source: 'metadata-credentials',
      });
      foundIds.add(matchedApiId);
      metaCredsFound++;
    }

    if (metaCredsFound > 0 || found.length > 0) {
      this.log(`${w.name}: ${found.length - metaCredsFound} creds via env, ${metaCredsFound} via metadata.credentials`, 'info');
    }

    return found;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Active Probing
  // ═══════════════════════════════════════════════════════════════════════════

  _getUrl(w) {
    if (w.metadata?.url) return w.metadata.url;
    if (w.metadata?.uri) return w.metadata.uri;
    if (w.metadata?.service_url) return w.metadata.service_url;
    // Check env vars for self-reported URL (MCP_SERVER_URL, APP_URL)
    const env = w.metadata?.env || {};
    if (env.MCP_SERVER_URL) return env.MCP_SERVER_URL;
    if (env.APP_URL) return env.APP_URL;
    // Construct from container name + port
    const name = w.name || w.metadata?.container_name;
    const port = env.PORT || env.APP_PORT;
    if (name && port) return `http://${name}:${port}`;
    const ip = w.metadata?.public_ip || w.metadata?.cluster_ip || w.metadata?.host;
    const ports = w.metadata?.ports || [];
    const portFromPorts = ports[0]?.containerPort || ports[0]?.port || ports[0];
    if (ip && portFromPorts) return `http://${ip}:${portFromPorts}`;
    return null;
  }

  async _probeA2A(baseUrl) {
    const url = `${baseUrl.replace(/\/$/, '')}/.well-known/agent.json`;
    this.log(`Probing A2A: ${url}`);
    try {
      const data = await this._get(url);
      this.log(`A2A response (${url}): ${data.substring(0, 100)}`);
      const card = JSON.parse(data);
      if (card.name && (card.skills || card.capabilities || card.supportedInterfaces)) {
        this.log(`A2A Agent Card: ${card.name} at ${url}`, 'success');

        // ── JWS Signature Verification ──
        if (card.signature) {
          try {
            const { verifyAgentCard } = require('../../../../shared/agent-card-signer');
            // Fetch JWKS from token-service (cached via _jwksCache)
            const publicKeyPem = await this._getSigningPublicKey();
            if (publicKeyPem) {
              const jwsParts = card.signature.split('.');
              if (jwsParts.length === 3) {
                // Parse header for kid
                const headerJson = Buffer.from(jwsParts[0], 'base64url').toString('utf8');
                const header = JSON.parse(headerJson);
                const result = verifyAgentCard(card.signature, publicKeyPem);
                card._signatureVerified = {
                  valid: result.valid,
                  error: result.error || null,
                  kid: header.kid || null,
                };
                this.log(`A2A signature verification: ${result.valid ? 'VALID' : 'INVALID'} (kid=${header.kid})`, result.valid ? 'success' : 'warn');
              } else {
                card._signatureVerified = { valid: false, error: 'Invalid JWS format', kid: null };
              }
            } else {
              card._signatureVerified = { valid: false, error: 'Could not fetch public key', kid: null };
              this.log('A2A signature: could not fetch public key for verification');
            }
          } catch (e) {
            card._signatureVerified = { valid: false, error: e.message, kid: null };
            this.log(`A2A signature verification error: ${e.message}`);
          }
        }

        return card;
      }
      this.log(`A2A card invalid: missing name/skills`);
    } catch (e) {
      this.log(`A2A probe failed (${url}): ${e.message}`);
    }
    return null;
  }

  /**
   * Get the platform's public key PEM for Agent Card signature verification.
   * Fetches JWKS from token-service and caches for 1 hour.
   * @private
   */
  async _getSigningPublicKey() {
    // Check cache
    if (this._jwksCache && this._jwksCacheExpiry > Date.now()) {
      return this._jwksCache;
    }

    const tokenServiceUrl = process.env.TOKEN_SERVICE_URL || 'http://token-service:3000';
    try {
      const data = await this._get(`${tokenServiceUrl}/.well-known/jwks.json`, 3000);
      const jwks = JSON.parse(data);
      if (jwks.keys && jwks.keys.length > 0) {
        const key = jwks.keys[0]; // Use first key
        // Convert JWK to PEM using Node.js crypto
        const keyObject = crypto.createPublicKey({ key, format: 'jwk' });
        const pem = keyObject.export({ type: 'spki', format: 'pem' });
        // Cache for 1 hour
        this._jwksCache = pem;
        this._jwksCacheExpiry = Date.now() + 3600000;
        return pem;
      }
    } catch (e) {
      this.log(`Failed to fetch JWKS for signature verification: ${e.message}`);
    }
    return null;
  }

  async _probeMCP(baseUrl) {
    const url = baseUrl.replace(/\/$/, '');
    this.log(`Probing MCP: ${url}`);
    try {
      const body = JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: {
          protocolVersion: '2024-11-05', capabilities: {},
          clientInfo: { name: 'wid-scanner', version: '1.0.0' },
        },
      });
      const data = await this._post(url, body);
      this.log(`MCP response (${url}): ${data.substring(0, 100)}`);
      const resp = JSON.parse(data);
      if (resp.result?.protocolVersion || resp.result?.capabilities) {
        const result = resp.result;
        this.log(`MCP Server: ${result.serverInfo?.name || 'unknown'} at ${url}`, 'success');

        // ── Tool/resource/prompt introspection ──
        const caps = result.capabilities || {};

        if (caps.tools) {
          try {
            const toolsData = await this._mcpRPC(url, 'tools/list', {});
            if (toolsData?.tools) {
              result._introspected_tools = toolsData.tools.map(t => ({
                name: t.name,
                description: t.description || '',
                input_schema_summary: t.inputSchema
                  ? Object.keys(t.inputSchema.properties || {}).join(', ')
                  : '',
                risk_level: this._scoreToolRisk(t.name, t.description),
              }));
              this.log(`  Tools: ${result._introspected_tools.length} enumerated`, 'success');
            }
          } catch (e) {
            this.log(`  tools/list failed: ${e.message}`);
          }
        }

        if (caps.resources) {
          try {
            const resData = await this._mcpRPC(url, 'resources/list', {});
            if (resData?.resources) {
              result._introspected_resources = resData.resources.map(r => ({
                uri: r.uri,
                name: r.name || '',
                description: r.description || '',
                mime_type: r.mimeType || '',
              }));
              this.log(`  Resources: ${result._introspected_resources.length} enumerated`, 'success');
            }
          } catch (e) {
            this.log(`  resources/list failed: ${e.message}`);
          }
        }

        if (caps.prompts) {
          try {
            const promptData = await this._mcpRPC(url, 'prompts/list', {});
            if (promptData?.prompts) {
              result._introspected_prompts = promptData.prompts.map(p => ({
                name: p.name,
                description: p.description || '',
              }));
              this.log(`  Prompts: ${result._introspected_prompts.length} enumerated`, 'success');
            }
          } catch (e) {
            this.log(`  prompts/list failed: ${e.message}`);
          }
        }

        return result;
      }
    } catch (e) {
      this.log(`MCP probe failed (${url}): ${e.message}`);
    }
    try {
      const data = await this._get(`${url}/sse`, 1500);
      if (data?.includes('event:')) {
        this.log(`MCP SSE endpoint at ${url}/sse`, 'success');
        return { transport: 'sse', endpoint: `${url}/sse` };
      }
    } catch (e) {
      this.log(`MCP SSE probe failed (${url}/sse): ${e.message}`);
    }
    return null;
  }

  // JSON-RPC helper for MCP method calls
  async _mcpRPC(url, method, params) {
    const body = JSON.stringify({
      jsonrpc: '2.0', id: Date.now(), method, params: params || {},
    });
    const data = await this._post(url, body);
    const resp = JSON.parse(data);
    if (resp.error) throw new Error(resp.error.message || 'RPC error');
    return resp.result;
  }

  // Per-tool risk assessment based on name and description patterns
  _scoreToolRisk(name, description) {
    const text = `${name} ${description || ''}`.toLowerCase();
    const HIGH_RISK = [/exec/i, /shell/i, /command/i, /\bdelete\b/i, /\bremove\b/i, /write.*file/i, /\bsql\b/i, /\badmin\b/i, /\bdrop\b/i, /\bkill\b/i, /\beval\b/i];
    const MEDIUM_RISK = [/read.*file/i, /\blist\b/i, /\bsearch\b/i, /\bapi\b/i, /\bhttp\b/i, /\bfetch\b/i, /\bquery\b/i, /\bupdate\b/i, /\bcreate\b/i];
    if (HIGH_RISK.some(r => r.test(text))) return 'high';
    if (MEDIUM_RISK.some(r => r.test(text))) return 'medium';
    return 'low';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Tool Poisoning Detection — Hidden instructions in MCP tool descriptions
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Scan all introspected tools for poisoning indicators.
   * Returns array of poisoning findings with tool name, pattern type, and severity.
   */
  _detectToolPoisoning(tools) {
    if (!tools || tools.length === 0) return [];
    const findings = [];

    for (const tool of tools) {
      const text = `${tool.name || ''} ${tool.description || ''}`;
      if (!text.trim()) continue;

      // Check input schema descriptions too — poisoning can hide in parameter descriptions
      let schemaText = '';
      if (tool.inputSchema?.properties) {
        for (const prop of Object.values(tool.inputSchema.properties)) {
          schemaText += ` ${prop.description || ''}`;
        }
      }
      const fullText = `${text} ${schemaText}`;

      for (const { pattern, type, severity } of TOOL_POISONING_PATTERNS) {
        const match = fullText.match(pattern);
        if (match) {
          findings.push({
            tool_name: tool.name,
            poisoning_type: type,
            severity,
            matched_text: match[0].slice(0, 80),
            location: schemaText && match.index >= text.length ? 'input_schema' : 'description',
          });
          // One finding per type per tool is enough
          break;
        }
      }

      // Check for suspiciously long descriptions (>500 chars) — may hide instructions
      if ((tool.description || '').length > 500) {
        findings.push({
          tool_name: tool.name,
          poisoning_type: 'oversized-description',
          severity: 'medium',
          matched_text: `Description length: ${tool.description.length} chars`,
          location: 'description',
        });
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MCP Server Integrity Verification — Package hash + version check
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Verify MCP server integrity against known-good registry.
   * Returns { status: 'verified'|'unverified'|'outdated', details }
   */
  _verifyMCPIntegrity(serverInfo, caps) {
    const serverName = serverInfo?.name || '';
    const serverVersion = serverInfo?.version || '';
    const protocolVersion = caps?.protocolVersion || '';

    // Compute a fingerprint from the server's capabilities for change detection
    const capFingerprint = crypto.createHash('sha256')
      .update(JSON.stringify({
        name: serverName,
        version: serverVersion,
        protocol: protocolVersion,
        tools: (caps?._introspected_tools || []).map(t => t.name).sort(),
        resources: (caps?._introspected_resources || []).map(r => r.uri || r.name).sort(),
        prompts: (caps?._introspected_prompts || []).map(p => p.name).sort(),
      }))
      .digest('hex')
      .slice(0, 16);

    // Enhanced: hash tool descriptions to detect post-deployment poisoning
    // that only changes descriptions (not tool names)
    const toolDescriptionsHash = crypto.createHash('sha256')
      .update(JSON.stringify(
        (caps?._introspected_tools || [])
          .map(t => ({ name: t.name, description: t.description || '' }))
          .sort((a, b) => a.name.localeCompare(b.name))
      ))
      .digest('hex')
      .slice(0, 16);

    // Check against known-good registry
    const registryEntry = MCP_KNOWN_GOOD_REGISTRY[serverName];
    if (!registryEntry) {
      return {
        status: 'unverified',
        fingerprint: capFingerprint,
        toolDescriptionsHash,
        reason: `Server "${serverName}" not found in known-good registry`,
        registry_size: Object.keys(MCP_KNOWN_GOOD_REGISTRY).length,
      };
    }

    // Version check
    if (registryEntry.min_version && serverVersion) {
      const current = serverVersion.split('.').map(Number);
      const minimum = registryEntry.min_version.split('.').map(Number);
      const isOutdated = current[0] < minimum[0]
        || (current[0] === minimum[0] && current[1] < minimum[1])
        || (current[0] === minimum[0] && current[1] === minimum[1] && (current[2] || 0) < (minimum[2] || 0));

      if (isOutdated) {
        return {
          status: 'outdated',
          fingerprint: capFingerprint,
          toolDescriptionsHash,
          current_version: serverVersion,
          minimum_version: registryEntry.min_version,
          publisher: registryEntry.publisher,
          reason: `Version ${serverVersion} is below minimum ${registryEntry.min_version}`,
        };
      }
    }

    return {
      status: 'verified',
      fingerprint: capFingerprint,
      toolDescriptionsHash,
      publisher: registryEntry.publisher,
      version: serverVersion,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MCP Server Rescan — Periodic fingerprint drift detection
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Rescan all active MCP servers, compute fingerprints, detect drift.
   * @param {object} dbClient - Postgres client
   * @returns {{ scanned: number, drifted: number, findings: object[] }}
   */
  async rescanMCPServers(dbClient) {
    const results = { scanned: 0, drifted: 0, findings: [] };

    let mcpServers;
    try {
      const res = await dbClient.query(
        "SELECT id, name, metadata FROM workloads WHERE is_mcp_server = true AND status = 'active'"
      );
      mcpServers = res.rows;
    } catch (e) {
      this.log(`MCP rescan: DB query failed: ${e.message}`);
      return results;
    }

    if (!mcpServers || mcpServers.length === 0) {
      this.log('MCP rescan: no active MCP servers found');
      return results;
    }

    for (const w of mcpServers) {
      try {
        const baseUrl = this._getUrl(w);
        if (!baseUrl) continue;

        // Re-probe the server
        const caps = await this._probeMCP(baseUrl);
        if (!caps) continue;

        // Compute new fingerprint + descriptions hash
        const integrity = this._verifyMCPIntegrity(caps.serverInfo || caps.result?.serverInfo, caps);
        const newFingerprint = integrity.fingerprint;
        const newDescHash = integrity.toolDescriptionsHash;
        const toolNames = (caps._introspected_tools || []).map(t => t.name);

        // Get previous fingerprint
        let prevFingerprint = null;
        let prevDescHash = null;
        let prevToolNames = [];
        try {
          const fpRes = await dbClient.query(
            'SELECT fingerprint, tool_descriptions_hash, tool_names FROM mcp_fingerprints WHERE workload_name = $1 ORDER BY created_at DESC LIMIT 1',
            [w.name]
          );
          if (fpRes.rows.length > 0) {
            prevFingerprint = fpRes.rows[0].fingerprint;
            prevDescHash = fpRes.rows[0].tool_descriptions_hash;
            prevToolNames = fpRes.rows[0].tool_names || [];
          }
        } catch { /* table may not exist yet */ }

        // Compare
        const driftDetected = prevFingerprint !== null && (
          newFingerprint !== prevFingerprint || newDescHash !== prevDescHash
        );

        let driftDetails = null;
        if (driftDetected) {
          driftDetails = this._computeDriftDetails(prevToolNames, toolNames, prevDescHash, newDescHash);
          results.drifted++;
          results.findings.push({
            type: 'mcp-capability-drift',
            severity: 'high',
            workload: w.name,
            message: `MCP server "${w.name}" capabilities changed: ${driftDetails.summary}`,
            owasp: 'NHI8',
            drift_details: driftDetails,
          });
        }

        // Store new fingerprint row
        try {
          await dbClient.query(
            `INSERT INTO mcp_fingerprints (
              workload_name, server_name, server_version, protocol_version,
              fingerprint, tool_descriptions_hash, tool_count, tool_names,
              resource_count, prompt_count, capabilities_snapshot,
              previous_fingerprint, drift_detected, drift_details, scan_source
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            [
              w.name,
              caps.serverInfo?.name || caps.result?.serverInfo?.name || w.name,
              caps.serverInfo?.version || caps.result?.serverInfo?.version || null,
              caps.protocolVersion || caps.result?.protocolVersion || null,
              newFingerprint,
              newDescHash,
              toolNames.length,
              toolNames,
              (caps._introspected_resources || []).length,
              (caps._introspected_prompts || []).length,
              JSON.stringify({
                tools: toolNames,
                resources: (caps._introspected_resources || []).map(r => r.uri || r.name),
                prompts: (caps._introspected_prompts || []).map(p => p.name),
              }),
              prevFingerprint,
              driftDetected,
              driftDetails ? JSON.stringify(driftDetails) : null,
              'periodic',
            ]
          );
        } catch (e) {
          this.log(`MCP rescan: failed to store fingerprint for ${w.name}: ${e.message}`);
        }

        results.scanned++;
      } catch (e) {
        this.log(`MCP rescan: probe failed for ${w.name}: ${e.message}`);
      }
    }

    this.log(`MCP rescan complete: ${results.scanned} scanned, ${results.drifted} drifted`);
    return results;
  }

  /**
   * Compute drift details between previous and current tool lists.
   * @private
   */
  _computeDriftDetails(prevToolNames, newToolNames, prevDescHash, newDescHash) {
    const prevSet = new Set(prevToolNames || []);
    const newSet = new Set(newToolNames || []);

    const added = [...newSet].filter(t => !prevSet.has(t));
    const removed = [...prevSet].filter(t => !newSet.has(t));
    const hasDescriptionChange = prevDescHash !== newDescHash && added.length === 0 && removed.length === 0;

    const parts = [];
    if (added.length > 0) parts.push(`${added.length} tool(s) added: ${added.join(', ')}`);
    if (removed.length > 0) parts.push(`${removed.length} tool(s) removed: ${removed.join(', ')}`);
    if (hasDescriptionChange) parts.push('tool descriptions changed (possible poisoning)');
    if (parts.length === 0) parts.push('fingerprint changed');

    return {
      added,
      removed,
      hasDescriptionChange,
      summary: parts.join('; '),
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Health Endpoint Credential Self-Reporting
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Probe /health or /healthz for credential self-reporting.
   * Demo agents (and any compliant service) report their external API
   * connections via the health endpoint, e.g.:
   *   { "credentials": [{ "api": "salesforce", "type": "token", ... }] }
   */
  async _probeHealthCredentials(baseUrl) {
    const base = baseUrl.replace(/\/$/, '');
    const found = [];

    for (const path of ['/health', '/healthz']) {
      try {
        const raw = await this._get(`${base}${path}`, 2000);
        const data = JSON.parse(raw);
        const creds = data.credentials || data.external_credentials || data.integrations || [];
        if (!Array.isArray(creds) || creds.length === 0) continue;

        this.log(`Health endpoint ${base}${path} reports ${creds.length} credential(s)`, 'success');

        for (const c of creds) {
          const apiId = (c.api || c.provider || c.name || '').toLowerCase();
          const pat = EXTERNAL_APIS[apiId];
          if (!pat) continue; // unknown API, skip

          const credType = c.type || c.cred_type || 'api-key';
          const scope = c.scope || 'unknown';
          const isStatic = c.is_static !== false; // assume static unless explicitly marked otherwise
          let risk = 'medium';
          if (/secret|private/i.test(credType)) risk = 'high';
          if (c.risk) risk = c.risk;
          if (isStatic && /financial|crm/.test(pat.category)) risk = 'critical';

          found.push({
            id: apiId,
            label: pat.label,
            category: pat.category,
            credType,
            scope,
            risk,
            matchedKeys: c.env_keys || c.keys || [`${apiId.toUpperCase()}_TOKEN`],
            isStatic,
            source: 'health-endpoint',
          });
        }

        // Found creds on this path, no need to try next
        if (found.length > 0) break;
      } catch (e) {
        // health endpoint not available or doesn't report creds — fine
      }
    }
    return found;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Graph Node Builders
  // ═══════════════════════════════════════════════════════════════════════════

  _addA2A(w, wNodeId, card, score) {
    const id = `a2a:${w.id || w.name}`;
    const skills = card?.skills?.map(s => s.id || s.name) || [];
    const hasAuth = !!(card?.security?.length || card?.securitySchemes);

    // 4-state signature status: verified, invalid, unverified, unsigned
    let signatureStatus = 'unsigned';
    let signatureKid = null;
    if (card?.signature) {
      if (card._signatureVerified?.valid) {
        signatureStatus = 'verified';
        signatureKid = card._signatureVerified.kid;
      } else if (card._signatureVerified?.error === 'Could not fetch public key') {
        signatureStatus = 'unverified';
      } else if (card._signatureVerified) {
        signatureStatus = 'invalid';
      }
    }

    // Risk mapping: invalid → critical, unsigned → medium, unverified → medium, verified → low
    let signatureRisk = 'medium';
    if (signatureStatus === 'invalid') signatureRisk = 'critical';
    else if (signatureStatus === 'verified') signatureRisk = 'low';

    this._add({
      id, label: card?.name || w.name,
      type: 'a2a-agent', group: 'agent-protocol', protocol: 'a2a',
      trust: w.trust_level || 'none',
      risk: !hasAuth ? 'high' : signatureRisk,
      meta: {
        version: card?.version, description: card?.description,
        skills, has_auth: hasAuth,
        is_signed: signatureStatus !== 'unsigned',
        signature_status: signatureStatus,
        signature_kid: signatureKid,
        transport: card?.supportedInterfaces?.[0]?.transport || 'https',
        url: card?.url || this._getUrl(w),
        detection: score.signals,
      },
    });

    this._rel({ source: id, target: wNodeId, type: 'runs-as-protocol', protocol: 'a2a', discovered_by: 'A2A protocol probe', evidence: `Probed workload for /.well-known/agent.json (A2A Agent Card). Detection signals: ${(score.signals || []).join(', ')}. This workload implements the Google A2A protocol and can receive tasks from other agents.` });

    if (signatureStatus === 'invalid') {
      this.findings.push({
        id: `a2a-invalid-signature:${w.name}`,
        finding_type: 'a2a-invalid-signature', type: 'a2a-invalid-signature',
        title: `Invalid Agent Card Signature — ${card?.name || w.name}`,
        severity: 'high', workload: w.name,
        description: `A2A Agent "${card?.name || w.name}" has INVALID Agent Card signature. Card may have been tampered with.`,
        recommendation: 'Investigate whether the Agent Card has been tampered with. Re-sign the card using POST /api/v1/agent-card/sign on the token-service.',
        owasp: 'NHI2',
        entry_points: [w.name],
      });
    } else if (signatureStatus === 'unsigned') {
      this.findings.push({
        id: `a2a-unsigned-card:${w.name}`,
        finding_type: 'a2a-unsigned-card', type: 'a2a-unsigned-card',
        title: `Unsigned Agent Card — ${card?.name || w.name}`,
        severity: 'medium', workload: w.name,
        description: `A2A Agent "${card?.name || w.name}" serves an unsigned Agent Card. Without cryptographic signing, the card's authenticity cannot be verified.`,
        recommendation: 'Sign the Agent Card using the platform token-service: set TOKEN_SERVICE_URL env var and the agent will auto-sign on startup. Or call POST /api/v1/agent-card/sign with the card payload.',
        owasp: 'NHI2',
        entry_points: [w.name],
      });
    }
    if (!hasAuth) {
      this.findings.push({
        id: `a2a-no-auth:${w.name}`,
        finding_type: 'a2a-no-auth', type: 'a2a-no-auth',
        title: `No Authentication — ${card?.name || w.name}`,
        severity: 'high', workload: w.name,
        description: `A2A Agent "${card?.name || w.name}" accepts tasks without authentication. Any agent can invoke it.`,
        recommendation: 'Add authentication to the Agent Card security section. Configure bearer token or OAuth2 authentication.',
        owasp: 'NHI2',
        entry_points: [w.name],
      });
    }
  }

  _addMCP(w, wNodeId, caps, score) {
    const id = `mcp:${w.id || w.name}`;
    const serverName = caps?.serverInfo?.name || w.name;
    const staticCreds = this._hasStaticCreds(w);
    const hasOAuth = this._hasOAuth(w);
    const hasAuth = hasOAuth || this._hasMCPAuth(w);

    // Use introspected tools if available, otherwise fall back to capability keys
    const introspectedTools = caps?._introspected_tools || [];
    const toolNames = introspectedTools.length > 0
      ? introspectedTools.map(t => t.name)
      : (caps?.capabilities?.tools ? Object.keys(caps.capabilities.tools) : []);
    const introspectedResources = caps?._introspected_resources || [];
    const introspectedPrompts = caps?._introspected_prompts || [];

    // Identify dangerous tools
    const dangerousTools = introspectedTools.filter(t => t.risk_level === 'high');

    // ── P1.3: Tool poisoning detection ──
    const poisoningFindings = this._detectToolPoisoning(introspectedTools);

    // ── P1.3: Integrity verification ──
    const integrity = this._verifyMCPIntegrity(caps?.serverInfo, caps);

    // Risk escalation: poisoned tools or unverified server raises risk
    let riskLevel = 'medium';
    if (poisoningFindings.some(f => f.severity === 'critical')) riskLevel = 'critical';
    else if (dangerousTools.length > 0 && !hasAuth) riskLevel = 'critical';
    else if (poisoningFindings.length > 0) riskLevel = 'high';
    else if (staticCreds && !hasOAuth) riskLevel = 'high';
    else if (integrity.status === 'unverified') riskLevel = Math.max(riskLevel === 'medium' ? 0 : 1, 1) ? 'medium' : riskLevel;

    this._add({
      id, label: serverName,
      type: 'mcp-server', group: 'agent-protocol', protocol: 'mcp',
      trust: w.trust_level || 'none',
      risk: riskLevel,
      meta: {
        protocol_version: caps?.protocolVersion,
        server_name: serverName,
        server_version: caps?.serverInfo?.version,
        tools: toolNames,
        tool_details: introspectedTools.length > 0 ? introspectedTools : undefined,
        tool_count: toolNames.length,
        dangerous_tools: dangerousTools.length > 0 ? dangerousTools.map(t => t.name) : undefined,
        resources: introspectedResources.length > 0 ? introspectedResources : undefined,
        resource_count: introspectedResources.length,
        prompts: introspectedPrompts.length > 0 ? introspectedPrompts : undefined,
        prompt_count: introspectedPrompts.length,
        transport: caps?.transport || 'http',
        has_static_creds: staticCreds, has_oauth: hasOAuth, has_auth: hasAuth,
        detection: score.signals,
        // P1.3: Integrity status
        integrity_status: integrity.status,
        integrity_fingerprint: integrity.fingerprint,
        integrity_publisher: integrity.publisher || null,
        // P1.3: Tool poisoning summary
        poisoning_detected: poisoningFindings.length > 0,
        poisoned_tools: poisoningFindings.length > 0 ? poisoningFindings.map(f => f.tool_name) : undefined,
        poisoning_types: poisoningFindings.length > 0 ? [...new Set(poisoningFindings.map(f => f.poisoning_type))] : undefined,
      },
    });

    this._rel({ source: id, target: wNodeId, type: 'runs-as-protocol', protocol: 'mcp', discovered_by: 'MCP protocol probe', evidence: `Probed workload for MCP capabilities (initialize handshake). Detection signals: ${(score.signals || []).join(', ')}. This workload runs an MCP server exposing ${(caps?.capabilities?.tools ? Object.keys(caps.capabilities.tools).length : 0)} tools. Integrity: ${integrity.status}.` });

    // Finding: static credentials without OAuth
    if (staticCreds && !hasOAuth) {
      this.findings.push({
        type: 'mcp-static-credentials', severity: 'high', workload: w.name,
        message: `MCP Server "${serverName}" uses static env var credentials. Migrate to OAuth or WID Edge Gateway.`,
        owasp: 'NHI7',
      });
    }

    // Finding: dangerous tools without authentication
    if (dangerousTools.length > 0 && !hasAuth) {
      this.findings.push({
        type: 'mcp-dangerous-tool', severity: 'critical', workload: w.name,
        message: `MCP Server "${serverName}" exposes ${dangerousTools.length} dangerous tool(s) (${dangerousTools.map(t => t.name).join(', ')}) without OAuth/auth. These tools can execute commands, modify files, or access sensitive data.`,
        owasp: 'NHI6',
        tools: dangerousTools.map(t => t.name),
      });
    }

    // Finding: unauthenticated MCP endpoint
    if (!hasAuth && !staticCreds) {
      this.findings.push({
        type: 'mcp-unauthenticated', severity: 'high', workload: w.name,
        message: `MCP Server "${serverName}" has no authentication configured. Any client can connect and invoke tools.`,
        owasp: 'NHI1',
      });
    }

    // Finding: unscoped access — server has resources but no resource restrictions
    if (introspectedResources.length > 0 && !caps?.capabilities?.resources?.listChanged) {
      const writeableResources = introspectedResources.filter(r =>
        r.uri && !/^https?:\/\//.test(r.uri) // local resources (file://, db://)
      );
      if (writeableResources.length > 0) {
        this.findings.push({
          type: 'mcp-unscoped-access', severity: 'medium', workload: w.name,
          message: `MCP Server "${serverName}" exposes ${writeableResources.length} local resource(s) without scope restrictions.`,
          resources: writeableResources.map(r => r.uri),
        });
      }
    }

    // ── P1.3: Tool poisoning finding ──
    if (poisoningFindings.length > 0) {
      const criticalPoisoning = poisoningFindings.filter(f => f.severity === 'critical');
      const highPoisoning = poisoningFindings.filter(f => f.severity === 'high');
      const types = [...new Set(poisoningFindings.map(f => f.poisoning_type))];
      const affectedTools = [...new Set(poisoningFindings.map(f => f.tool_name))];

      this.findings.push({
        type: 'mcp-tool-poisoning',
        severity: criticalPoisoning.length > 0 ? 'critical' : 'high',
        workload: w.name,
        title: `Tool Poisoning Detected: ${serverName}`,
        message: `MCP Server "${serverName}" has ${poisoningFindings.length} tool poisoning indicator(s) across ${affectedTools.length} tool(s). Types: ${types.join(', ')}. Affected tools: ${affectedTools.join(', ')}. Tool descriptions contain hidden instructions that may cause prompt injection, credential exfiltration, or unauthorized actions.`,
        owasp: 'NHI6',
        poisoning_details: poisoningFindings,
        affected_tools: affectedTools,
        recommendation: 'Immediately disconnect this MCP server. Audit all previous tool invocations. Replace with a verified server from the MCP registry.',
      });

      this.log(`POISONING DETECTED: ${serverName} — ${poisoningFindings.length} indicators (${types.join(', ')})`, 'error');
    }

    // ── P1.3: Unverified server finding ──
    if (integrity.status === 'unverified') {
      this.findings.push({
        type: 'mcp-unverified-server',
        severity: 'medium',
        workload: w.name,
        title: `Unverified MCP Server: ${serverName}`,
        message: `MCP Server "${serverName}" is not in the known-good registry (${integrity.registry_size} verified packages). Cannot confirm publisher identity or package integrity. Fingerprint: ${integrity.fingerprint}.`,
        owasp: 'NHI2',
        integrity: integrity,
        recommendation: 'Verify server source and publisher. Pin to a specific version. Consider using an official @modelcontextprotocol/* package instead.',
      });
    }

    // ── P1.3: Outdated server finding ──
    if (integrity.status === 'outdated') {
      this.findings.push({
        type: 'mcp-outdated-version',
        severity: 'high',
        workload: w.name,
        title: `Outdated MCP Server: ${serverName}`,
        message: `MCP Server "${serverName}" is running version ${integrity.current_version} but minimum recommended is ${integrity.minimum_version} (publisher: ${integrity.publisher}). Outdated versions may have known security vulnerabilities.`,
        owasp: 'NHI8',
        integrity: integrity,
        recommendation: `Update ${serverName} to version ${integrity.minimum_version} or later. Run \`npm update ${serverName}\` or \`pip install --upgrade ${serverName}\`.`,
      });
    }
  }

  // Check if workload has MCP-specific auth configured
  _hasMCPAuth(w) {
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    return Object.keys(env).some(k => /MCP_AUTH|MCP_TOKEN|MCP_API_KEY|MCP_SECRET/i.test(k));
  }

  _addExtAPI(wNodeId, api, w) {
    const extId = `ext-api:${api.id}`;
    const credId = `cred:${w.id || w.name}:${api.id}`;

    this._add({
      id: extId, label: api.label, type: 'external-api', group: 'external',
      sensitive: true, risk: api.risk,
      meta: { provider: api.id, category: api.category },
    });

    this._add({
      id: credId, label: `${api.label} ${api.credType}`,
      type: 'external-credential', group: 'credential', risk: api.risk,
      meta: {
        api: api.id, cred_type: api.credType, scope: api.scope,
        is_static: api.isStatic, env_keys: api.matchedKeys, workload: w.name,
      },
    });

    this._rel({ source: wNodeId, target: credId, type: 'holds-credential', critical: api.risk === 'critical', discovered_by: 'Container environment scan', evidence: `Inspected container environment variables. Found keys matching known API credential patterns: ${(api.matchedKeys || []).join(', ')}. These are static credentials embedded in the container config.` });
    this._rel({ source: credId, target: extId, type: 'accesses-api', critical: api.risk === 'critical', scope: api.scope, discovered_by: 'Credential chain analysis', evidence: `The ${api.credType} credential (${(api.matchedKeys || [])[0] || 'key'}) authenticates to ${api.label} API with scope: ${api.scope || 'full access'}. This creates a direct attack path from the workload to the external service.` });

    if (api.isStatic) {
      this.findings.push({
        type: 'static-external-credential',
        severity: api.risk === 'critical' ? 'critical' : 'high',
        workload: w.name,
        title: `Static ${api.label} credential`,
        message: `${w.name} holds static ${api.credType} for ${api.label} (${api.matchedKeys.join(', ')}). Replace with Edge Gateway JIT tokens.`,
        owasp: 'NHI7',
        recommendation: `Route ${api.label} access through WID Edge Gateway: scope=${api.scope}, TTL=5min.`,
        env_keys: api.matchedKeys,
        api_id: api.id,
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Cross-cutting
  // ═══════════════════════════════════════════════════════════════════════════

  _linkAgents() {
    // Only create agent-to-agent and agent-to-MCP links when there is positive evidence
    // of an actual connection in the Agent Card skills or MCP server metadata.
    // Unconditional O(n²) all-to-all linking creates false attack paths and inflates blast radius.
    const agents = this.nodes.filter(n => n.type === 'a2a-agent');
    const mcps = this.nodes.filter(n => n.type === 'mcp-server');
    const extApis = this.nodes.filter(n => n.type === 'external-api');

    for (const a of agents) {
      // Agent → MCP: only if the agent's MCP tools list references this server by name
      const agentTools = a.meta?.tools || a.meta?.mcp_tools || [];
      for (const m of mcps) {
        const serverName = (m.meta?.server_name || m.label || '').toLowerCase();
        const mcpId = (m.id || '').toLowerCase();
        const hasEvidence = agentTools.some(t =>
          serverName.includes(t.toLowerCase()) || mcpId.includes(t.toLowerCase())
        ) || (agentTools.length === 0 && mcps.length === 1); // single MCP → likely connected
        if (hasEvidence) {
          this._rel({ source: a.id, target: m.id, type: 'uses-mcp-server', protocol: 'mcp', discovered_by: 'Agent Card cross-reference', evidence: `Parsed Agent Card for ${a.label}. The skills/tools list references MCP server '${m.label}'. This agent can invoke tools exposed by the MCP server.` });
        }
      }
    }

    // MCP → External API: detect if MCP tools reference external APIs
    // Creates 3-hop attack path: Agent → MCP Server → External API
    for (const m of mcps) {
      const mcpTools = m.meta?.tool_details || [];
      const mcpToolNames = m.meta?.tools || [];
      for (const api of extApis) {
        const apiLabel = (api.label || '').toLowerCase();
        const apiId = (api.meta?.provider || api.id || '').toLowerCase().replace('ext-api:', '');
        // Check if any MCP tool name or description references this API
        const toolRefsAPI = mcpTools.some(t => {
          const text = `${t.name} ${t.description}`.toLowerCase();
          return text.includes(apiLabel) || text.includes(apiId);
        }) || mcpToolNames.some(t => {
          const name = t.toLowerCase();
          return name.includes(apiId) || apiId.includes(name);
        });
        if (toolRefsAPI) {
          this._rel({ source: m.id, target: api.id, type: 'tool-accesses-api', protocol: 'mcp', discovered_by: 'MCP tool introspection', evidence: `Introspected MCP server tools via tools/list. Found tool(s) that reference ${api.label} in their name or description. The MCP server can access this external API through its tools.` });
        }
      }
    }

    // A2A delegation: only link agents that share the same workload host (co-located)
    // or whose Agent Card explicitly lists the target agent as a skill provider
    for (let i = 0; i < agents.length; i++) {
      const aSkills = agents[i].meta?.skills || [];
      for (let j = i + 1; j < agents.length; j++) {
        const bLabel = (agents[j].label || '').toLowerCase();
        const canDelegate = aSkills.some(s => s.toLowerCase().includes(bLabel));
        if (canDelegate) {
          this._rel({ source: agents[i].id, target: agents[j].id, type: 'can-delegate-to', protocol: 'a2a', discovered_by: 'Agent Card skill analysis', evidence: `Parsed Agent Card for ${agents[i].label}. Its skills list includes '${agents[j].label}' as a delegation target. This means ${agents[i].label} can send tasks to ${agents[j].label} via A2A protocol.` });
        }
      }
    }
  }

  _detectToxicCombos() {
    const wAPIs = {};
    for (const r of this.relationships.filter(r => r.type === 'holds-credential')) {
      const cred = this.nodes.find(n => n.id === r.target);
      if (cred?.meta?.api) (wAPIs[r.source] = wAPIs[r.source] || new Set()).add(cred.meta.api);
    }

    for (const [wid, apis] of Object.entries(wAPIs)) {
      if (apis.has('stripe') && apis.has('salesforce')) {
        const label = wid.replace('w:', '');
        this.findings.push({
          type: 'toxic-combo', severity: 'critical',
          title: `Toxic Combo: ${label}`,
          workload: label,
          message: `${label} holds both Stripe (financial) and Salesforce (CRM) credentials. Compromise → customer data + financial transactions.`,
          recommendation: 'Separate financial and CRM into distinct agents with dedicated identities. Use Edge Gateway with scope-limited JIT tokens.',
        });
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  _hasStaticCreds(w) {
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    const hasEnvCreds = Object.keys(env).some(k => /TOKEN|API_KEY|SECRET|PAT|CREDENTIALS/i.test(k));
    if (hasEnvCreds) return true;
    // Also check metadata.credentials array (from cloud scanners)
    const metaCreds = w.metadata?.credentials || [];
    return metaCreds.some(c => {
      const isManagedSecret = c.type === 'secret_manager_ref'
        || c.storage_method === 'secret-manager'
        || c.storage_method === 'secrets-manager'
        || c.storage_method === 'key-vault'
        || !!c.secret_manager_ref;
      const isStatic = c.is_static !== undefined ? c.is_static : !isManagedSecret;
      return isStatic;
    });
  }

  _hasOAuth(w) {
    const env = w.metadata?.env || w.metadata?.environment_variables || {};
    return Object.keys(env).some(k => /OAUTH|CLIENT_SECRET/i.test(k));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // AI Agent Enrichment — builds structured ai_enrichment profile
  // ═══════════════════════════════════════════════════════════════════════════

  enrichAIAgent(workload) {
    const env = workload.metadata?.env || workload.metadata?.environment_variables || {};
    const envKeys = Object.keys(env);
    const labels = workload.labels || workload.metadata?.labels || {};
    const metaCreds = workload.metadata?.credentials || [];
    const allText = JSON.stringify({ env: envKeys, labels, name: workload.name }).toLowerCase();

    // Build a unified set of credential key names from both env vars and metadata.credentials.
    // Cloud Run redacts env values as [secret], but the key names are still present.
    // When env vars are completely absent (e.g., some cloud scanners), metadata.credentials
    // is the only source. We merge both to maximise detection coverage.
    const credKeyNames = new Set(envKeys);
    for (const cred of metaCreds) {
      const credName = (cred.name || cred.key || '').toUpperCase();
      if (credName) credKeyNames.add(credName);
    }
    // Also build a map of credential-name → provider for metadata.credentials entries
    const metaCredProviders = new Map();
    for (const cred of metaCreds) {
      const provider = (cred.provider || cred.api || '').toLowerCase();
      if (provider) {
        const credName = (cred.name || cred.key || '').toUpperCase();
        if (credName) metaCredProviders.set(credName, provider);
      }
    }

    const enrichment = {
      llm_providers: [],
      models: [],
      embeddings_and_vectors: [],
      fine_tuning: null,
      frameworks: [],
      permissions_detected: [],
      projects_tenants: [],
      credential_count: 0,
      risk_flags: [],
    };

    const allCredKeys = [...credKeyNames];

    // ── LLM Providers + Models ──
    const aiProviders = this.registry.getAIProviders();
    for (const [id, provider] of aiProviders) {
      // Match against both env keys and metadata.credentials key names
      const matchedKeys = provider.keys.filter(k => credKeyNames.has(k));

      // Also match by provider name from metadata.credentials
      // (e.g., a credential with provider='openai' should match AI_PROVIDERS.openai)
      let matchedViaMetaProvider = false;
      if (matchedKeys.length === 0) {
        for (const cred of metaCreds) {
          const credProvider = (cred.provider || cred.api || '').toLowerCase();
          if (credProvider === id || credProvider === provider.label.toLowerCase()) {
            const credName = (cred.name || cred.key || '').toUpperCase();
            if (credName) matchedKeys.push(credName);
            matchedViaMetaProvider = true;
          }
        }
      }

      if (matchedKeys.length === 0) continue;

      const providerEntry = {
        id, label: provider.label, category: provider.category,
        credential_keys: matchedKeys,
        source: matchedViaMetaProvider ? 'metadata-credentials' : 'env',
      };

      // Detect model version — check env values first, then metadata.credentials
      let model = null;
      for (const mk of (provider.models || [])) {
        if (env[mk] && env[mk] !== '[secret]') { model = env[mk]; break; }
      }
      // Fall back: check metadata.credentials for model info
      if (!model) {
        for (const cred of metaCreds) {
          const credName = (cred.name || cred.key || '').toUpperCase();
          for (const mk of (provider.models || [])) {
            if (credName === mk && cred.value && cred.value !== '[secret]') {
              model = cred.value;
              break;
            }
          }
          if (model) break;
          // Also check cred.model field if the scanner provides it
          if (cred.model) { model = cred.model; break; }
        }
      }
      if (!model && provider.modelPatterns) {
        for (const p of provider.modelPatterns) {
          const match = allText.match(p);
          if (match) { model = match[0]; break; }
        }
      }
      providerEntry.model = model || provider.defaultModel || 'unknown';

      // Detect project/tenant
      const projectKeys = matchedKeys.filter(k => /ORG|PROJECT|TENANT|WORKSPACE|ACCOUNT/i.test(k));
      if (projectKeys.length > 0) {
        const project = { provider: id, keys: projectKeys, values: projectKeys.map(k => env[k] || '[set]') };
        enrichment.projects_tenants.push(project);
        providerEntry.project = projectKeys[0];
      }

      // Detect scopes from usage patterns
      if (provider.scopes) {
        const detectedScopes = [];
        for (const [scope, desc] of Object.entries(provider.scopes)) {
          if (allText.includes(scope) || allText.includes(desc.toLowerCase())) detectedScopes.push({ scope, description: desc });
        }
        if (detectedScopes.length === 0) detectedScopes.push({ scope: 'chat', description: 'Default — chat completions' });
        providerEntry.scopes = detectedScopes;
        enrichment.permissions_detected.push(...detectedScopes.map(s => `${id}:${s.scope}`));
      }

      enrichment.llm_providers.push(providerEntry);
      enrichment.models.push({ provider: id, model: providerEntry.model, label: provider.label });
      enrichment.credential_count++;
    }

    // ── Embedding / Vector Stores ──
    const matchedStoreIds = new Set();
    const embeddingStores = this.registry.getEmbeddingStores();
    for (const [id, store] of embeddingStores) {
      // Match against unified credential key set (env + metadata.credentials)
      const matchedKeys = store.keys.filter(k => credKeyNames.has(k));

      // Also match by provider name from metadata.credentials
      if (matchedKeys.length === 0) {
        for (const cred of metaCreds) {
          const credProvider = (cred.provider || cred.api || '').toLowerCase();
          if (credProvider === id || credProvider === store.label.toLowerCase()) {
            const credName = (cred.name || cred.key || '').toUpperCase();
            if (credName) matchedKeys.push(credName);
          }
        }
      }

      if (matchedKeys.length === 0) continue;
      matchedStoreIds.add(id);
      enrichment.embeddings_and_vectors.push({
        id, label: store.label, category: store.category,
        credential_keys: matchedKeys,
        index: env[`${id.toUpperCase()}_INDEX`] || env['PINECONE_INDEX'] || env['QDRANT_COLLECTION'] || null,
      });
      enrichment.credential_count++;
    }

    // ── Fine-tuning ──
    const fineTuningSignals = this.registry.getFineTuningSignals();
    const ftKeys = fineTuningSignals.env.filter(k => credKeyNames.has(k));
    const ftFromPatterns = fineTuningSignals.patterns.some(p => p.test(allText));
    if (ftKeys.length > 0 || ftFromPatterns) {
      enrichment.fine_tuning = {
        detected: true,
        signals: ftKeys,
        model_id: env['FINE_TUNED_MODEL'] || env['FT_MODEL_ID'] || env['CUSTOM_MODEL_ID'] || null,
        method: ftKeys.some(k => /LORA|PEFT|QLORA/i.test(k)) ? 'LoRA/PEFT' : ftKeys.some(k => /RLHF/i.test(k)) ? 'RLHF' : 'Full fine-tune',
      };
      enrichment.risk_flags.push('uses-fine-tuned-model');
    }

    // ── Frameworks ──
    const frameworkSignals = this.registry.getFrameworks();
    for (const [id, fw] of frameworkSignals) {
      // Match against unified credential key set
      const matchedKeys = fw.keys.filter(k => credKeyNames.has(k));
      if (matchedKeys.length > 0) {
        enrichment.frameworks.push({ id, label: fw.label, keys: matchedKeys });
      }
    }

    // ── LLM Gateways & Observability ──
    enrichment.llm_gateways = [];
    enrichment.llm_observability = [];
    const llmGatewaySignals = this.registry.getLLMGateways();
    for (const [id, gw] of llmGatewaySignals) {
      const matchedKeys = gw.keys.filter(k => credKeyNames.has(k));
      const imgMatch = gw.images?.some(p => p.test(workload.metadata?.image || ''));
      if (matchedKeys.length === 0 && !imgMatch) continue;

      const entry = { id, label: gw.label, category: gw.category, credential_keys: matchedKeys };
      if (gw.category === 'llm-gateway') {
        enrichment.llm_gateways.push(entry);
      } else {
        enrichment.llm_observability.push(entry);
      }
      enrichment.credential_count++;
    }

    // ── Cloud-native AI assets (from cloud scanner metadata) ──
    enrichment.cloud_ai_assets = [];
    if (workload.metadata?.ai_asset) {
      enrichment.cloud_ai_assets.push(workload.metadata.ai_asset);

      // Auto-add to llm_providers if this is a Vertex AI endpoint
      const asset = workload.metadata.ai_asset;
      if (asset.service === 'vertex-ai' && !enrichment.llm_providers.some(p => p.id === 'google_ai')) {
        enrichment.llm_providers.push({
          id: 'google_ai', label: 'Google AI / Vertex AI', category: 'llm-provider',
          credential_keys: [], source: 'cloud-api',
          model: asset.model_id || asset.model_family || 'vertex-custom',
          deployment_type: asset.deployment_type,
        });
      }
      if (asset.service === 'bedrock' && !enrichment.llm_providers.some(p => p.id === 'aws_bedrock')) {
        enrichment.llm_providers.push({
          id: 'aws_bedrock', label: 'AWS Bedrock', category: 'llm-provider',
          credential_keys: [], source: 'cloud-api',
          model: asset.model_id || 'bedrock-custom',
        });
      }
    }

    // ── AI egress detection (from firewall rules / proxy env vars) ──
    enrichment.ai_egress = [];
    const allEnvValues = Object.values(env).join(' ');
    const aiEgressEndpoints = this.registry.getAIEgressEndpoints();
    for (const ep of aiEgressEndpoints) {
      if (ep.pattern.test(allEnvValues) || ep.pattern.test(JSON.stringify(workload.metadata || ''))) {
        enrichment.ai_egress.push({ provider: ep.provider, label: ep.label });
      }
    }

    // ── Governance fields (human_in_loop, scope_ceiling) ──
    // Derive from workload metadata or agent card data
    const meta = workload.metadata || {};
    enrichment.human_in_loop = meta.human_in_loop !== undefined
      ? meta.human_in_loop
      : (meta.requires_human_delegator !== undefined ? meta.requires_human_delegator : undefined);
    enrichment.scope_ceiling = meta.scope_ceiling || null;

    // ── Risk flags ──
    if (enrichment.llm_providers.length > 1) enrichment.risk_flags.push('multi-provider');
    if (enrichment.credential_count > 3) enrichment.risk_flags.push('high-credential-count');
    if (enrichment.embeddings_and_vectors.length > 0 && enrichment.llm_providers.length > 0) {
      enrichment.risk_flags.push('rag-pipeline'); // LLM + vector store = RAG
    }
    if (enrichment.llm_gateways.length > 0) enrichment.risk_flags.push('centralized-llm-gateway');
    if (enrichment.cloud_ai_assets.some(a => a.access_pattern === 'public')) {
      enrichment.risk_flags.push('public-ai-endpoint');
    }
    if (enrichment.cloud_ai_assets.some(a => a.governance_status === 'unregistered')) {
      enrichment.risk_flags.push('unregistered-ai-endpoint');
    }

    return enrichment;
  }

  _get(url, timeout) {
    return new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { timeout: timeout || this.timeout }, (res) => {
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
        let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });
  }

  _post(url, body) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = url.startsWith('https') ? https : http;
      const req = mod.request({
        hostname: parsed.hostname, port: parsed.port, path: parsed.pathname,
        method: 'POST', timeout: this.timeout,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      }, (res) => {
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
        let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      req.write(body); req.end();
    });
  }

  // ── Enrich workload AI metadata from observed authorization logs ────────────
  static enrichFromLogs(decisions, registry) {
    const { ProviderRegistry } = require('./provider-registry');
    const reg = registry || ProviderRegistry.getInstance();
    const PROVIDER_DOMAINS = reg.getProviderDomains();

    const observed = {
      llm_providers: [],
      vector_stores: [],
      external_apis: [],
      call_counts: {},
      first_seen: {},
      last_seen: {},
    };
    const seen = new Set();

    for (const d of decisions) {
      const dst = d.destination_name || d.destination_principal || '';
      for (const [domain, meta] of Object.entries(PROVIDER_DOMAINS)) {
        if (dst.includes(domain)) {
          const key = meta.provider;
          observed.call_counts[key] = (observed.call_counts[key] || 0) + 1;
          const ts = d.created_at || new Date().toISOString();
          if (!observed.first_seen[key] || ts < observed.first_seen[key]) observed.first_seen[key] = ts;
          if (!observed.last_seen[key] || ts > observed.last_seen[key]) observed.last_seen[key] = ts;

          if (!seen.has(key)) {
            seen.add(key);
            const entry = { provider: key, label: meta.label, call_count: 0 };
            if (meta.type === 'llm') observed.llm_providers.push(entry);
            else if (meta.type === 'vector') observed.vector_stores.push(entry);
            else observed.external_apis.push(entry);
          }
        }
      }
    }

    // Update call counts on entries
    for (const list of [observed.llm_providers, observed.vector_stores, observed.external_apis]) {
      for (const entry of list) {
        entry.call_count = observed.call_counts[entry.provider] || 0;
        entry.first_seen = observed.first_seen[entry.provider];
        entry.last_seen = observed.last_seen[entry.provider];
      }
    }

    return observed;
  }
}

module.exports = ProtocolScanner;