// =============================================================================
// Provider Registry — DB-driven provider/domain pattern registry
// =============================================================================
// Replaces hardcoded constants in protocol-scanner.js with a DB-backed registry.
// Singleton with auto-reload: polls DB every 60s, compares checksum, rebuilds
// in-memory Maps only on change. Getters return the exact same shapes as the
// original constants (EXTERNAL_APIS, AI_PROVIDERS, EMBEDDING_STORES, etc.)
// so callers require minimal refactoring.
//
// Usage:
//   const { ProviderRegistry } = require('./provider-registry');
//   await ProviderRegistry.initialize(dbClient);
//   const registry = ProviderRegistry.getInstance();
//   const apis = registry.getExternalAPIs(); // same shape as old EXTERNAL_APIS
// =============================================================================

const crypto = require('crypto');

let _instance = null;
let _refreshTimer = null;

class ProviderRegistry {
  constructor() {
    this._dbClient = null;
    this._externalAPIs = new Map();
    this._aiProviders = new Map();
    this._embeddingStores = new Map();
    this._frameworks = new Map();
    this._llmGateways = new Map();
    this._aiEgressEndpoints = [];
    this._providerDomains = {};
    this._fineTuningSignals = { env: [], patterns: [] };
    this._checksum = '';
    this._lastLoadedAt = null;
    this._loadCount = 0;
    this._fallbackLoaded = false;
  }

  // ── Singleton lifecycle ────────────────────────────────────────────────────

  static async initialize(dbClient, opts = {}) {
    if (!_instance) {
      _instance = new ProviderRegistry();
    }
    _instance._dbClient = dbClient;

    await _instance.load();

    // Start auto-refresh timer (default 60s)
    const interval = opts.refreshIntervalMs || 60000;
    if (_refreshTimer) clearInterval(_refreshTimer);
    _refreshTimer = setInterval(() => _instance.reload().catch(e => {
      console.error('[ProviderRegistry] Auto-refresh failed:', e.message);
    }), interval);
    _refreshTimer.unref(); // Don't block process exit

    return _instance;
  }

  static getInstance() {
    if (!_instance) {
      _instance = new ProviderRegistry();
      _instance._loadFallbacks();
    }
    return _instance;
  }

  static destroy() {
    if (_refreshTimer) {
      clearInterval(_refreshTimer);
      _refreshTimer = null;
    }
    _instance = null;
  }

  // ── DB Load ────────────────────────────────────────────────────────────────

  async load() {
    if (!this._dbClient) {
      this._loadFallbacks();
      return;
    }

    try {
      const { rows } = await this._dbClient.query(
        'SELECT * FROM provider_registry WHERE enabled = TRUE ORDER BY sort_order, id'
      );

      // Checksum comparison — skip rebuild if unchanged
      const newChecksum = crypto
        .createHash('md5')
        .update(JSON.stringify(rows))
        .digest('hex');

      if (newChecksum === this._checksum && this._loadCount > 0) {
        return; // No changes
      }

      this._rebuild(rows);
      this._checksum = newChecksum;
      this._lastLoadedAt = new Date();
      this._loadCount++;
      this._fallbackLoaded = false;

      if (this._loadCount === 1) {
        console.log(`[ProviderRegistry] Loaded ${rows.length} entries from DB`);
      }
    } catch (err) {
      if (this._loadCount === 0) {
        console.warn('[ProviderRegistry] DB unavailable, loading fallback constants:', err.message);
        this._loadFallbacks();
      } else {
        console.warn('[ProviderRegistry] Reload failed, keeping last-known-good:', err.message);
      }
    }
  }

  async reload() {
    await this.load();
  }

  // ── Rebuild in-memory Maps from DB rows ────────────────────────────────────

  _rebuild(rows) {
    const externalAPIs = new Map();
    const aiProviders = new Map();
    const embeddingStores = new Map();
    const frameworks = new Map();
    const llmGateways = new Map();
    const aiEgressEndpoints = [];
    const providerDomains = {};
    const fineTuningSignals = { env: [], patterns: [] };

    for (const row of rows) {
      const { id, registry_type, label, category, credential_keys,
              ai_config, domain_patterns, domain_type,
              image_patterns, signal_patterns } = row;

      const keys = credential_keys || [];

      switch (registry_type) {
        case 'external_api':
          externalAPIs.set(id, { keys, label, category });
          break;

        case 'ai_provider': {
          const cfg = ai_config || {};
          const entry = {
            keys, label, category,
            models: cfg.models || [],
            modelPatterns: this._compilePatterns(cfg.modelPatterns || []),
            defaultModel: cfg.defaultModel || null,
            scopes: cfg.scopes || {},
          };
          aiProviders.set(id, entry);
          break;
        }

        case 'embedding_store':
          embeddingStores.set(id, { keys, label, category });
          break;

        case 'framework':
          frameworks.set(id, { keys, label });
          break;

        case 'llm_gateway': {
          const entry = {
            keys, label, category,
            images: this._compilePatterns(image_patterns || []),
          };
          llmGateways.set(id, entry);
          break;
        }

        case 'ai_egress':
          for (const pat of (signal_patterns || [])) {
            const compiled = this._safeRegex(pat);
            if (compiled) {
              aiEgressEndpoints.push({ pattern: compiled, provider: id, label });
            }
          }
          break;

        case 'provider_domain':
          for (const domain of (domain_patterns || [])) {
            providerDomains[domain] = {
              provider: id.replace('domain:', ''),
              label,
              type: domain_type || category,
            };
          }
          break;

        case 'fine_tuning':
          fineTuningSignals.env.push(...keys);
          for (const pat of (signal_patterns || [])) {
            const compiled = this._safeRegex(pat);
            if (compiled) fineTuningSignals.patterns.push(compiled);
          }
          break;
      }
    }

    this._externalAPIs = externalAPIs;
    this._aiProviders = aiProviders;
    this._embeddingStores = embeddingStores;
    this._frameworks = frameworks;
    this._llmGateways = llmGateways;
    this._aiEgressEndpoints = aiEgressEndpoints;
    this._providerDomains = providerDomains;
    this._fineTuningSignals = fineTuningSignals;
  }

  // ── Compile regex patterns from DB strings ─────────────────────────────────

  _compilePatterns(patterns) {
    const compiled = [];
    for (const p of patterns) {
      const re = this._safeRegex(p);
      if (re) compiled.push(re);
    }
    return compiled;
  }

  _safeRegex(pattern) {
    if (!pattern || typeof pattern !== 'string') return null;
    if (pattern.length > 500) {
      console.warn(`[ProviderRegistry] Skipping oversized regex (${pattern.length} chars)`);
      return null;
    }
    try {
      return new RegExp(pattern, 'i');
    } catch (e) {
      console.warn(`[ProviderRegistry] Invalid regex "${pattern}": ${e.message}`);
      return null;
    }
  }

  // ── Fallback: load from hardcoded defaults ─────────────────────────────────

  _loadFallbacks() {
    if (this._fallbackLoaded) return;
    const defaults = ProviderRegistry.getDefaults();
    this._rebuild(defaults);
    this._fallbackLoaded = true;
    this._lastLoadedAt = new Date();
    console.log(`[ProviderRegistry] Loaded ${defaults.length} fallback entries`);
  }

  // ── Getters — same shapes as the original constants ────────────────────────

  /** Returns Map<id, {keys, label, category}> — same as EXTERNAL_APIS */
  getExternalAPIs() {
    return this._externalAPIs;
  }

  /** Returns Map<id, {keys, label, category, models, modelPatterns, defaultModel, scopes}> — same as AI_PROVIDERS */
  getAIProviders() {
    return this._aiProviders;
  }

  /** Returns Map<id, {keys, label, category}> — same as EMBEDDING_STORES */
  getEmbeddingStores() {
    return this._embeddingStores;
  }

  /** Returns Map<id, {keys, label}> — same as FRAMEWORK_SIGNALS */
  getFrameworks() {
    return this._frameworks;
  }

  /** Returns Map<id, {keys, label, category, images}> — same as LLM_GATEWAY_SIGNALS */
  getLLMGateways() {
    return this._llmGateways;
  }

  /** Returns Array<{pattern, provider, label}> — same as AI_EGRESS_ENDPOINTS */
  getAIEgressEndpoints() {
    return this._aiEgressEndpoints;
  }

  /** Returns Object<domain, {provider, label, type}> — same as PROVIDER_DOMAINS */
  getProviderDomains() {
    return this._providerDomains;
  }

  /** Returns {env: string[], patterns: RegExp[]} — same as FINE_TUNING_SIGNALS */
  getFineTuningSignals() {
    return this._fineTuningSignals;
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  getStats() {
    return {
      externalAPIs: this._externalAPIs.size,
      aiProviders: this._aiProviders.size,
      embeddingStores: this._embeddingStores.size,
      frameworks: this._frameworks.size,
      llmGateways: this._llmGateways.size,
      aiEgressEndpoints: this._aiEgressEndpoints.length,
      providerDomains: Object.keys(this._providerDomains).length,
      fineTuningEnvKeys: this._fineTuningSignals.env.length,
      checksum: this._checksum,
      lastLoadedAt: this._lastLoadedAt,
      loadCount: this._loadCount,
      fallbackLoaded: this._fallbackLoaded,
    };
  }

  // ── Static: default entries for seeding ────────────────────────────────────
  // Returns rows in the same shape as provider_registry DB rows.
  // Used for: (1) seeding DB on first boot, (2) fallback when DB unavailable.

  static getDefaults() {
    const rows = [];

    // ── External APIs ──
    const EXTERNAL_APIS = {
      salesforce: { keys: ['SALESFORCE_TOKEN', 'SALESFORCE_API_KEY', 'SF_ACCESS_TOKEN', 'SF_CLIENT_ID', 'SF_CLIENT_SECRET', 'SALESFORCE_INSTANCE_URL', 'SF_REFRESH_TOKEN'], label: 'Salesforce', category: 'crm' },
      stripe: { keys: ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY', 'STRIPE_PUBLISHABLE_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_CONNECT_SECRET'], label: 'Stripe', category: 'financial' },
      slack: { keys: ['SLACK_TOKEN', 'SLACK_BOT_TOKEN', 'SLACK_API_TOKEN', 'SLACK_WEBHOOK_URL', 'SLACK_SIGNING_SECRET', 'SLACK_APP_TOKEN'], label: 'Slack', category: 'communication' },
      github: { keys: ['GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT', 'GITHUB_APP_PRIVATE_KEY', 'GITHUB_APP_ID', 'GH_APP_KEY'], label: 'GitHub', category: 'devops' },
      openai: { keys: ['OPENAI_API_KEY', 'OPENAI_ORG_ID'], label: 'OpenAI', category: 'ai-provider' },
      anthropic: { keys: ['ANTHROPIC_API_KEY'], label: 'Anthropic', category: 'ai-provider' },
      bigquery: { keys: ['BIGQUERY_CREDENTIALS', 'GOOGLE_APPLICATION_CREDENTIALS'], label: 'BigQuery', category: 'data' },
      snowflake: { keys: ['SNOWFLAKE_ACCOUNT', 'SNOWFLAKE_PASSWORD', 'SNOWFLAKE_PRIVATE_KEY'], label: 'Snowflake', category: 'data' },
      twilio: { keys: ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN'], label: 'Twilio', category: 'communication' },
      sendgrid: { keys: ['SENDGRID_API_KEY'], label: 'SendGrid', category: 'communication' },
      datadog: { keys: ['DD_API_KEY', 'DATADOG_API_KEY', 'DD_APP_KEY'], label: 'Datadog', category: 'observability' },
      pagerduty: { keys: ['PAGERDUTY_TOKEN', 'PAGERDUTY_API_KEY'], label: 'PagerDuty', category: 'observability' },
      jira: { keys: ['JIRA_TOKEN', 'JIRA_API_TOKEN', 'JIRA_PAT', 'ATLASSIAN_API_KEY'], label: 'Jira', category: 'devops' },
      servicenow: { keys: ['SERVICENOW_API_KEY', 'SN_API_KEY', 'SNOW_TOKEN'], label: 'ServiceNow', category: 'itsm' },
      workday: { keys: ['WORKDAY_TOKEN', 'WORKDAY_API_KEY', 'WD_CLIENT_SECRET'], label: 'Workday', category: 'hr' },
      epic: { keys: ['EPIC_FHIR_TOKEN', 'EPIC_CLIENT_SECRET', 'EPIC_API_KEY'], label: 'Epic FHIR', category: 'healthcare' },
      snyk: { keys: ['SNYK_TOKEN', 'SNYK_API_TOKEN'], label: 'Snyk', category: 'security' },
      zendesk: { keys: ['ZENDESK_API_TOKEN', 'ZENDESK_TOKEN', 'ZD_API_KEY'], label: 'Zendesk', category: 'support' },
      sonarqube: { keys: ['SONAR_TOKEN', 'SONARQUBE_TOKEN', 'SONAR_API_KEY'], label: 'SonarQube', category: 'security' },
    };

    for (const [id, v] of Object.entries(EXTERNAL_APIS)) {
      rows.push({
        id, registry_type: 'external_api', label: v.label, category: v.category,
        credential_keys: v.keys, ai_config: null,
        domain_patterns: [], domain_type: null, image_patterns: [], signal_patterns: [],
      });
    }

    // ── AI Providers ──
    const AI_PROVIDERS = {
      openai: {
        keys: ['OPENAI_API_KEY', 'OPENAI_ORG_ID', 'OPENAI_PROJECT_ID', 'OPENAI_API_BASE'],
        label: 'OpenAI', category: 'llm-provider',
        models: ['OPENAI_MODEL', 'GPT_MODEL', 'OPENAI_MODEL_NAME', 'OPENAI_DEPLOYMENT'],
        modelPatterns: ['gpt-4o?(-mini|-turbo)?', 'o[1-3](-mini|-preview)?', 'chatgpt', 'dall-e', 'whisper', 'tts'],
        defaultModel: 'gpt-4o',
        scopes: { chat: 'Chat completions', embeddings: 'Text embeddings', images: 'Image generation', audio: 'Speech/transcription', files: 'File management', 'fine-tuning': 'Model fine-tuning', assistants: 'Assistants API' },
      },
      anthropic: {
        keys: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_PROJECT_ID'],
        label: 'Anthropic', category: 'llm-provider',
        models: ['ANTHROPIC_MODEL', 'CLAUDE_MODEL', 'ANTHROPIC_MODEL_NAME'],
        modelPatterns: ['claude-[34](\\.[\\d])?(-sonnet|-opus|-haiku)', 'claude-instant'],
        defaultModel: 'claude-sonnet-4-5-20250514',
        scopes: { messages: 'Message completions', tools: 'Tool use', vision: 'Image analysis', batches: 'Batch processing' },
      },
      google_ai: {
        keys: ['GOOGLE_AI_API_KEY', 'GEMINI_API_KEY', 'VERTEX_AI_PROJECT', 'GOOGLE_GENAI_API_KEY'],
        label: 'Google AI / Gemini', category: 'llm-provider',
        models: ['GEMINI_MODEL', 'GOOGLE_AI_MODEL', 'VERTEX_MODEL'],
        modelPatterns: ['gemini-(pro|ultra|flash|nano|1\\.5|2\\.0)', 'palm'],
        defaultModel: 'gemini-2.0-flash',
        scopes: { generate: 'Content generation', embed: 'Embeddings', vision: 'Multimodal', code: 'Code generation' },
      },
      azure_openai: {
        keys: ['AZURE_OPENAI_API_KEY', 'AZURE_OPENAI_ENDPOINT', 'AZURE_OPENAI_DEPLOYMENT'],
        label: 'Azure OpenAI', category: 'llm-provider',
        models: ['AZURE_OPENAI_DEPLOYMENT', 'AZURE_OPENAI_MODEL'],
        modelPatterns: ['gpt-4', 'gpt-35-turbo'],
        defaultModel: 'gpt-4',
        scopes: { completions: 'Chat completions', embeddings: 'Embeddings', images: 'DALL-E' },
      },
      cohere: {
        keys: ['COHERE_API_KEY', 'CO_API_KEY'],
        label: 'Cohere', category: 'llm-provider',
        models: ['COHERE_MODEL'],
        modelPatterns: ['command(-r|-light|-nightly)?', 'embed-'],
        defaultModel: 'command-r-plus',
        scopes: { generate: 'Text generation', embed: 'Embeddings', rerank: 'Reranking' },
      },
      mistral: {
        keys: ['MISTRAL_API_KEY'],
        label: 'Mistral AI', category: 'llm-provider',
        models: ['MISTRAL_MODEL'],
        modelPatterns: ['mistral-(large|medium|small|tiny|7b)', 'mixtral', 'codestral'],
        defaultModel: 'mistral-large',
        scopes: { chat: 'Chat', embed: 'Embeddings', code: 'Code generation' },
      },
      huggingface: {
        keys: ['HUGGINGFACE_TOKEN', 'HF_TOKEN', 'HUGGINGFACE_API_KEY', 'HF_API_KEY'],
        label: 'Hugging Face', category: 'ml-platform',
        models: ['HF_MODEL', 'HUGGINGFACE_MODEL'],
        modelPatterns: ['meta-llama', 'bert', 't5', 'stable-diffusion'],
        scopes: { inference: 'Inference API', spaces: 'Spaces', models: 'Model Hub' },
      },
      replicate: {
        keys: ['REPLICATE_API_TOKEN', 'REPLICATE_API_KEY'],
        label: 'Replicate', category: 'ml-platform',
        models: ['REPLICATE_MODEL'],
        modelPatterns: ['replicate/'],
        scopes: { predictions: 'Run models', models: 'Model management' },
      },
      aws_bedrock: {
        keys: ['AWS_BEDROCK_REGION', 'BEDROCK_MODEL_ID', 'AWS_BEDROCK_ENDPOINT'],
        label: 'AWS Bedrock', category: 'llm-provider',
        models: ['BEDROCK_MODEL_ID', 'AWS_BEDROCK_MODEL'],
        modelPatterns: ['anthropic\\.claude', 'amazon\\.titan', 'ai21\\.jamba', 'meta\\.llama'],
        scopes: { invoke: 'Model invocation', agents: 'Bedrock Agents', knowledge: 'Knowledge Bases' },
      },
      groq: {
        keys: ['GROQ_API_KEY', 'GROQ_ORG_ID'],
        label: 'Groq', category: 'llm-provider',
        models: ['GROQ_MODEL'],
        modelPatterns: ['llama-3', 'mixtral', 'gemma'],
        defaultModel: 'llama-3-70b',
        scopes: { chat: 'Chat completions' },
      },
      together: {
        keys: ['TOGETHER_API_KEY', 'TOGETHERAI_API_KEY'],
        label: 'Together AI', category: 'llm-provider',
        models: ['TOGETHER_MODEL'],
        modelPatterns: ['together/'],
        scopes: { inference: 'Inference', fine_tuning: 'Fine-tuning' },
      },
      fireworks: {
        keys: ['FIREWORKS_API_KEY', 'FIREWORKS_ACCOUNT_ID'],
        label: 'Fireworks AI', category: 'llm-provider',
        models: ['FIREWORKS_MODEL'],
        modelPatterns: ['fireworks'],
        scopes: { inference: 'Inference' },
      },
      deepseek: {
        keys: ['DEEPSEEK_API_KEY'],
        label: 'DeepSeek', category: 'llm-provider',
        models: ['DEEPSEEK_MODEL'],
        modelPatterns: ['deepseek-(chat|coder|r1|v[23])'],
        defaultModel: 'deepseek-chat',
        scopes: { chat: 'Chat completions', code: 'Code generation' },
      },
    };

    for (const [id, v] of Object.entries(AI_PROVIDERS)) {
      rows.push({
        id, registry_type: 'ai_provider', label: v.label, category: v.category,
        credential_keys: v.keys,
        ai_config: { models: v.models, modelPatterns: v.modelPatterns, defaultModel: v.defaultModel || null, scopes: v.scopes },
        domain_patterns: [], domain_type: null, image_patterns: [], signal_patterns: [],
      });
    }

    // ── Embedding Stores ──
    const EMBEDDING_STORES = {
      pinecone: { keys: ['PINECONE_API_KEY', 'PINECONE_ENVIRONMENT', 'PINECONE_INDEX', 'PINECONE_PROJECT_ID'], label: 'Pinecone', category: 'vector-store' },
      weaviate: { keys: ['WEAVIATE_URL', 'WEAVIATE_API_KEY', 'WEAVIATE_CLUSTER_URL'], label: 'Weaviate', category: 'vector-store' },
      chromadb: { keys: ['CHROMA_HOST', 'CHROMA_API_KEY', 'CHROMADB_URL', 'CHROMA_SERVER_URL'], label: 'ChromaDB', category: 'vector-store' },
      qdrant: { keys: ['QDRANT_URL', 'QDRANT_API_KEY', 'QDRANT_HOST'], label: 'Qdrant', category: 'vector-store' },
      milvus: { keys: ['MILVUS_HOST', 'MILVUS_URI', 'MILVUS_TOKEN'], label: 'Milvus', category: 'vector-store' },
      pgvector: { keys: ['PGVECTOR_CONNECTION', 'VECTOR_DB_URL'], label: 'pgvector', category: 'vector-store' },
      supabase_vector: { keys: ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'], label: 'Supabase Vector', category: 'vector-store' },
    };

    for (const [id, v] of Object.entries(EMBEDDING_STORES)) {
      rows.push({
        id, registry_type: 'embedding_store', label: v.label, category: v.category,
        credential_keys: v.keys, ai_config: null,
        domain_patterns: [], domain_type: null, image_patterns: [], signal_patterns: [],
      });
    }

    // ── Frameworks ──
    const FRAMEWORKS = {
      langchain: { keys: ['LANGCHAIN_API_KEY', 'LANGCHAIN_TRACING_V2', 'LANGCHAIN_PROJECT', 'LANGSMITH_API_KEY'], label: 'LangChain / LangSmith' },
      llamaindex: { keys: ['LLAMA_CLOUD_API_KEY', 'LLAMAINDEX_CACHE_DIR'], label: 'LlamaIndex' },
      crewai: { keys: ['CREWAI_API_KEY'], label: 'CrewAI' },
      autogen: { keys: ['AUTOGEN_CONFIG'], label: 'AutoGen' },
      semantic_kernel: { keys: ['SEMANTIC_KERNEL_ENDPOINT'], label: 'Semantic Kernel' },
    };

    for (const [id, v] of Object.entries(FRAMEWORKS)) {
      rows.push({
        id, registry_type: 'framework', label: v.label, category: 'ai-framework',
        credential_keys: v.keys, ai_config: null,
        domain_patterns: [], domain_type: null, image_patterns: [], signal_patterns: [],
      });
    }

    // ── LLM Gateways ──
    const LLM_GATEWAYS = {
      litellm: { keys: ['LITELLM_PROXY_BASE_URL', 'LITELLM_MASTER_KEY', 'LITELLM_API_KEY', 'LITELLM_API_BASE'], label: 'LiteLLM', category: 'llm-gateway', images: ['litellm'] },
      portkey: { keys: ['PORTKEY_API_KEY', 'PORTKEY_GATEWAY_URL', 'PORTKEY_BASE_URL'], label: 'Portkey', category: 'llm-gateway', images: ['portkey'] },
      helicone: { keys: ['HELICONE_API_KEY', 'HELICONE_BASE_URL'], label: 'Helicone', category: 'llm-gateway', images: ['helicone'] },
      langfuse: { keys: ['LANGFUSE_SECRET_KEY', 'LANGFUSE_PUBLIC_KEY', 'LANGFUSE_HOST', 'LANGFUSE_BASEURL'], label: 'Langfuse', category: 'llm-observability' },
      arize_phoenix: { keys: ['PHOENIX_COLLECTOR_ENDPOINT', 'ARIZE_API_KEY', 'ARIZE_SPACE_KEY'], label: 'Arize / Phoenix', category: 'llm-observability' },
      braintrust: { keys: ['BRAINTRUST_API_KEY', 'BRAINTRUST_PROJECT'], label: 'Braintrust', category: 'llm-observability' },
      promptlayer: { keys: ['PROMPTLAYER_API_KEY'], label: 'PromptLayer', category: 'llm-observability' },
    };

    for (const [id, v] of Object.entries(LLM_GATEWAYS)) {
      rows.push({
        id, registry_type: 'llm_gateway', label: v.label, category: v.category,
        credential_keys: v.keys, ai_config: null,
        domain_patterns: [], domain_type: null,
        image_patterns: v.images || [], signal_patterns: [],
      });
    }

    // ── AI Egress Endpoints ──
    const AI_EGRESS = [
      { id: 'egress:openai', provider: 'openai', label: 'OpenAI API', pattern: 'api\\.openai\\.com' },
      { id: 'egress:anthropic', provider: 'anthropic', label: 'Anthropic API', pattern: 'api\\.anthropic\\.com' },
      { id: 'egress:google', provider: 'google', label: 'Google Generative AI', pattern: 'generativelanguage\\.googleapis\\.com' },
      { id: 'egress:bedrock', provider: 'bedrock', label: 'AWS Bedrock', pattern: 'bedrock-runtime\\..+\\.amazonaws\\.com' },
      { id: 'egress:azure_openai', provider: 'azure_openai', label: 'Azure OpenAI', pattern: '\\.openai\\.azure\\.com' },
      { id: 'egress:cohere', provider: 'cohere', label: 'Cohere API', pattern: 'api\\.cohere\\.ai' },
      { id: 'egress:mistral', provider: 'mistral', label: 'Mistral API', pattern: 'api\\.mistral\\.ai' },
      { id: 'egress:groq', provider: 'groq', label: 'Groq API', pattern: 'api\\.groq\\.com' },
      { id: 'egress:together', provider: 'together', label: 'Together AI API', pattern: 'api\\.together\\.xyz' },
      { id: 'egress:fireworks', provider: 'fireworks', label: 'Fireworks API', pattern: 'api\\.fireworks\\.ai' },
      { id: 'egress:deepseek', provider: 'deepseek', label: 'DeepSeek API', pattern: 'api\\.deepseek\\.com' },
    ];

    for (const e of AI_EGRESS) {
      rows.push({
        id: e.id, registry_type: 'ai_egress', label: e.label, category: 'ai-provider',
        credential_keys: [], ai_config: null,
        domain_patterns: [], domain_type: null, image_patterns: [],
        signal_patterns: [e.pattern],
      });
    }

    // ── Provider Domains (for enrichFromLogs) ──
    const PROVIDER_DOMAINS = {
      'domain:api.openai.com': { domains: ['api.openai.com'], provider: 'openai', label: 'OpenAI', type: 'llm' },
      'domain:api.anthropic.com': { domains: ['api.anthropic.com'], provider: 'anthropic', label: 'Anthropic', type: 'llm' },
      'domain:generativelanguage.googleapis.com': { domains: ['generativelanguage.googleapis.com'], provider: 'google', label: 'Google AI', type: 'llm' },
      'domain:api.cohere.ai': { domains: ['api.cohere.ai'], provider: 'cohere', label: 'Cohere', type: 'llm' },
      'domain:api.mistral.ai': { domains: ['api.mistral.ai'], provider: 'mistral', label: 'Mistral AI', type: 'llm' },
      'domain:api.pinecone.io': { domains: ['api.pinecone.io'], provider: 'pinecone', label: 'Pinecone', type: 'vector' },
      'domain:weaviate.io': { domains: ['weaviate.io'], provider: 'weaviate', label: 'Weaviate', type: 'vector' },
      'domain:api.stripe.com': { domains: ['api.stripe.com'], provider: 'stripe', label: 'Stripe', type: 'financial' },
      'domain:api.slack.com': { domains: ['api.slack.com'], provider: 'slack', label: 'Slack', type: 'messaging' },
      'domain:login.salesforce.com': { domains: ['login.salesforce.com'], provider: 'salesforce', label: 'Salesforce', type: 'crm' },
      'domain:api.github.com': { domains: ['api.github.com'], provider: 'github', label: 'GitHub', type: 'devops' },
      'domain:huggingface.co': { domains: ['huggingface.co'], provider: 'huggingface', label: 'Hugging Face', type: 'llm' },
      'domain:api.replicate.com': { domains: ['api.replicate.com'], provider: 'replicate', label: 'Replicate', type: 'llm' },
    };

    for (const [id, v] of Object.entries(PROVIDER_DOMAINS)) {
      rows.push({
        id, registry_type: 'provider_domain', label: v.label, category: v.type,
        credential_keys: [], ai_config: null,
        domain_patterns: v.domains, domain_type: v.type,
        image_patterns: [], signal_patterns: [],
      });
    }

    // ── Fine-tuning signals ──
    rows.push({
      id: 'fine_tuning_signals', registry_type: 'fine_tuning', label: 'Fine-tuning Signals', category: 'ai-training',
      credential_keys: ['FINE_TUNED_MODEL', 'FT_MODEL_ID', 'CUSTOM_MODEL_ID', 'FINE_TUNE_SUFFIX', 'TRAINING_DATA_PATH', 'LORA_ADAPTER', 'PEFT_MODEL_ID', 'RLHF_REWARD_MODEL'],
      ai_config: null, domain_patterns: [], domain_type: null, image_patterns: [],
      signal_patterns: ['ft[:-]gpt', 'ft[:-]claude', 'fine[-_]tuned', 'custom[-_]model', 'lora', 'qlora', 'peft'],
    });

    return rows;
  }
}

module.exports = { ProviderRegistry };
