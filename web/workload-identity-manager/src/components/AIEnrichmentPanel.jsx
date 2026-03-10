import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, Cpu, Database, GitBranch, Layers, Eye, RefreshCw,
  Loader, ChevronDown, ChevronRight, ExternalLink, Zap, Lock, Bot,
} from 'lucide-react';

const DISC = '/api/v1';

/* ── Provider logos/colors ── */
const PROVIDER_META = {
  openai:    { label: 'OpenAI',      color: '#10b981', icon: '🟢' },
  anthropic: { label: 'Anthropic',   color: '#d97706', icon: '🟠' },
  google:    { label: 'Google AI',   color: '#3b82f6', icon: '🔵' },
  google_ai: { label: 'Google AI / Vertex AI', color: '#3b82f6', icon: '🔵' },
  azure:     { label: 'Azure OpenAI',color: '#0ea5e9', icon: '☁️' },
  azure_openai: { label: 'Azure OpenAI', color: '#0ea5e9', icon: '☁️' },
  cohere:    { label: 'Cohere',      color: '#8b5cf6', icon: '🟣' },
  mistral:   { label: 'Mistral AI',  color: '#f97316', icon: '🔶' },
  huggingface:{ label: 'Hugging Face',color: '#fbbf24', icon: '🤗' },
  replicate: { label: 'Replicate',   color: '#a78bfa', icon: '🔄' },
  bedrock:   { label: 'AWS Bedrock', color: '#f59e0b', icon: '☁️' },
  aws_bedrock: { label: 'AWS Bedrock', color: '#f59e0b', icon: '☁️' },
  groq:      { label: 'Groq',       color: '#f97316', icon: '⚡' },
  together:  { label: 'Together AI', color: '#06b6d4', icon: '🤝' },
  fireworks: { label: 'Fireworks AI',color: '#ef4444', icon: '🎆' },
  deepseek:  { label: 'DeepSeek',   color: '#3b82f6', icon: '🔍' },
};

const VECTOR_META = {
  pinecone:  { label: 'Pinecone',    color: '#10b981', icon: '🌲' },
  weaviate:  { label: 'Weaviate',    color: '#22d3ee', icon: '🔷' },
  chromadb:  { label: 'ChromaDB',    color: '#f97316', icon: '🎨' },
  qdrant:    { label: 'Qdrant',      color: '#ef4444', icon: '🔴' },
  milvus:    { label: 'Milvus',      color: '#3b82f6', icon: '🐬' },
  pgvector:  { label: 'pgvector',    color: '#336791', icon: '🐘' },
  supabase:  { label: 'Supabase',    color: '#3ecf8e', icon: '⚡' },
};

const RISK_META = {
  'multi-provider':        { label: 'Multi-Provider',      color: '#f59e0b', icon: '⚠️' },
  'high-credential-count': { label: 'High Credential Count', color: '#f97316', icon: '🔑' },
  'rag-pipeline':          { label: 'RAG Pipeline',        color: '#8b5cf6', icon: '🔗' },
  'uses-fine-tuned-model': { label: 'Fine-Tuned Model',    color: '#06b6d4', icon: '🎯' },
  'centralized-llm-gateway':  { label: 'LLM Gateway',       color: '#3b82f6', icon: '🔀' },
  'public-ai-endpoint':       { label: 'Public AI Endpoint', color: '#ef4444', icon: '🌐' },
  'unregistered-ai-endpoint': { label: 'Unregistered AI',    color: '#f97316', icon: '📋' },
};

const GATEWAY_META = {
  litellm:       { label: 'LiteLLM',      color: '#10b981', icon: '🔀' },
  portkey:       { label: 'Portkey',       color: '#8b5cf6', icon: '🚪' },
  helicone:      { label: 'Helicone',      color: '#f59e0b', icon: '☀️' },
  langfuse:      { label: 'Langfuse',      color: '#06b6d4', icon: '📊' },
  arize_phoenix: { label: 'Arize/Phoenix', color: '#f97316', icon: '📈' },
  braintrust:    { label: 'Braintrust',    color: '#3b82f6', icon: '🧠' },
  promptlayer:   { label: 'PromptLayer',   color: '#a78bfa', icon: '📝' },
};

const AI_SERVICE_META = {
  'vertex-ai':    { label: 'Vertex AI',     color: '#4285f4', icon: '🔷' },
  'generative-ai':{ label: 'Gemini API',    color: '#34a853', icon: '✨' },
  'bedrock':      { label: 'AWS Bedrock',   color: '#ff9900', icon: '☁️' },
  'sagemaker':    { label: 'SageMaker',     color: '#ff9900', icon: '🔬' },
  'ai-platform-legacy': { label: 'AI Platform', color: '#4285f4', icon: '🤖' },
  'cloud-nlp':    { label: 'Cloud NLP',     color: '#4285f4', icon: '📖' },
  'cloud-vision': { label: 'Cloud Vision',  color: '#4285f4', icon: '👁️' },
  'cloud-speech': { label: 'Cloud Speech',  color: '#4285f4', icon: '🎤' },
  'cloud-translate':{ label: 'Translation', color: '#4285f4', icon: '🌍' },
  'document-ai':  { label: 'Document AI',   color: '#4285f4', icon: '📄' },
  'dialogflow':   { label: 'Dialogflow',    color: '#4285f4', icon: '💬' },
  'automl':       { label: 'AutoML',        color: '#4285f4', icon: '🔧' },
};

const Pill = ({ color, children }) => (
  <span className="text-[8px] font-bold px-1.5 py-0.5 rounded" style={{ background: `${color}15`, color, border: `1px solid ${color}25` }}>
    {children}
  </span>
);

/* ═══════════════════════════════════════════
   AI Enrichment Panel — unified AI card
   Shows: agent protocol info + enrichment data
   ═══════════════════════════════════════════ */
export function AIEnrichmentPanel({ workloadId, workloadName, workload, inline = false }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(true);
  const [observedData, setObservedData] = useState(null);
  const [observedLoading, setObservedLoading] = useState(false);

  // Extract agent metadata from workload prop
  const m = workload ? (typeof workload.metadata === 'string' ? (() => { try { return JSON.parse(workload.metadata); } catch { return {}; } })() : (workload.metadata || {})) : {};
  const protocol = m.protocol || m.transport || (workload?.is_mcp_server ? 'MCP' : workload?.is_ai_agent ? 'A2A' : null);
  const hasAuth = m.has_auth;
  const isSigned = m.is_signed;
  const delegator = m.requires_human_delegator;
  const scopeCeiling = m.scope_ceiling;
  const humanInLoop = m.human_in_loop;
  const skills = m.skills || [];
  const tools = m.tools || [];
  const [skillsExpanded, setSkillsExpanded] = useState(false);

  useEffect(() => {
    if (!workloadId) return;
    setLoading(true);
    fetch(`${DISC}/workloads/${workloadId}/ai-enrichment`, { credentials: 'include' })
      .then(r => r.json())
      .then(d => { setData(d.enrichment || d); setLoading(false); })
      .catch(() => setLoading(false));
    setObservedLoading(true);
    fetch(`${DISC}/workloads/${workloadId}/observed-enrichment`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { setObservedData(d); setObservedLoading(false); })
      .catch(() => setObservedLoading(false));
  }, [workloadId]);

  if (loading) return <div className="flex items-center gap-2 py-3"><Loader className="w-3 h-3 animate-spin text-accent" /><span className="text-[9px] text-nhi-dim">Loading AI data...</span></div>;

  const hasEnrichment = data && (data.llm_providers?.length > 0 || data.embeddings_and_vectors?.length > 0 || data.fine_tuning?.detected || data.frameworks?.length > 0 || data.cloud_ai_assets?.length > 0 || data.llm_gateways?.length > 0 || data.llm_observability?.length > 0);
  const hasProtocol = !!protocol;
  const hasSkills = skills.length > 0 || tools.length > 0;
  const hasIETF = !!m.ietf_aims;

  // Nothing to show at all
  if (!hasEnrichment && !hasProtocol && !hasSkills && !hasIETF) return null;

  const observedTotal = observedData ? (observedData.observed?.llm_providers?.length || 0) + (observedData.observed?.vector_stores?.length || 0) + (observedData.observed?.external_apis?.length || 0) : 0;

  return (
    <div className="mb-3 p-3 rounded-lg bg-violet-500/[0.04] border border-violet-500/15">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Bot className="w-3.5 h-3.5 text-violet-400" />
          <span className="text-[10px] text-violet-400 uppercase tracking-widest font-bold">AI Agent</span>
          {workload?.is_mcp_server && <Pill color="#22d3ee">MCP</Pill>}
          {observedTotal > 0 && <Pill color="#f59e0b">{observedTotal} observed in logs</Pill>}
          {data?.risk_flags?.length > 0 && <Pill color="#ef4444">{data.risk_flags.length} risks</Pill>}
        </div>
        <button onClick={() => setExpanded(!expanded)} className="text-nhi-ghost hover:text-nhi-muted">
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Protocol/Trust Posture Row — always visible */}
      {hasProtocol && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 mb-2 text-[11px]">
          <span className="text-nhi-ghost">Protocol: <span className="text-nhi-muted font-semibold">{protocol}</span></span>
          <span className="text-nhi-ghost">Auth: <span className={hasAuth ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>{hasAuth ? 'Required' : hasAuth === false ? 'None' : '\u2014'}</span></span>
          <span className="text-nhi-ghost">Signed: <span className={isSigned ? 'text-emerald-400 font-semibold' : 'text-nhi-dim font-semibold'}>{isSigned ? 'JWS' : isSigned === false ? 'Unsigned' : '\u2014'}</span></span>
          {delegator !== undefined && <span className="text-nhi-ghost">Delegator: <span className="text-nhi-muted font-semibold">{delegator ? 'Required' : 'Not required'}</span></span>}
          {scopeCeiling && <span className="text-nhi-ghost">Scope: <span className="text-nhi-muted font-mono font-semibold">{scopeCeiling}</span></span>}
          {humanInLoop !== undefined && <span className="text-nhi-ghost">Human-in-Loop: <span className={humanInLoop ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>{humanInLoop ? 'Yes' : 'No'}</span></span>}
        </div>
      )}

      {expanded && (
        <div className="space-y-3">
          {/* LLM Providers */}
          {data?.llm_providers?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">LLM Providers ({data.llm_providers.length})</div>
              <div className="space-y-1.5">
                {data.llm_providers.map((p, i) => {
                  const meta = PROVIDER_META[p.id] || { label: p.label, color: '#94a3b8', icon: '🤖' };
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-lg" style={{ background: `${meta.color}08`, border: `1px solid ${meta.color}15` }}>
                      <span className="text-sm">{meta.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] font-bold" style={{ color: meta.color }}>{meta.label}</div>
                        {p.model && <div className="text-[8px] font-mono text-nhi-dim">{p.model}</div>}
                      </div>
                      {p.project && <span className="text-[7px] font-mono text-nhi-ghost px-1.5 py-0.5 rounded bg-surface-3">{p.project}</span>}
                      <span className="text-[7px] text-nhi-ghost">{p.credential_keys?.length || 0} keys</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Credentials — prominent card (positioned after LLM Providers for visibility) */}
          {data?.credential_count > 0 && (
            <div className="rounded-lg px-2.5 py-2 border"
              style={{ background: 'rgba(245, 158, 11, 0.06)', borderColor: 'rgba(245, 158, 11, 0.18)' }}>
              <div className="flex items-center gap-2 mb-1.5">
                <Lock className="w-3 h-3 text-amber-400" />
                <span className="text-[9px] font-bold text-amber-400 uppercase tracking-wider">
                  Credentials ({data.credential_count})
                </span>
              </div>
              <div className="text-[10px] text-nhi-muted font-semibold">
                {data.credential_count} AI credential{data.credential_count > 1 ? 's' : ''} detected
              </div>
              {data.permissions_detected?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {data.permissions_detected.map((scope, i) => (
                    <span key={i} className="text-[8px] font-mono font-bold px-1.5 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20">
                      {scope}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Cloud AI Services */}
          {data?.cloud_ai_assets?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">Cloud AI Services ({data.cloud_ai_assets.length})</div>
              <div className="space-y-1.5">
                {data.cloud_ai_assets.map((asset, i) => {
                  const meta = AI_SERVICE_META[asset.service] || { label: asset.service, color: '#94a3b8', icon: '🤖' };
                  return (
                    <div key={i} className="px-2 py-1.5 rounded-lg" style={{ background: `${meta.color}08`, border: `1px solid ${meta.color}15` }}>
                      <div className="flex items-center gap-2">
                        <span className="text-sm">{meta.icon}</span>
                        <span className="text-[10px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                        {asset.model_id && <span className="text-[8px] font-mono text-nhi-dim">{asset.model_id}</span>}
                        {asset.governance_status === 'unregistered' && (
                          <span className="text-[6px] font-bold px-1 py-0.5 rounded bg-amber-500/15 text-amber-400 ml-auto">UNREGISTERED</span>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-2 mt-1">
                        {asset.deployment_type && <span className="text-[7px] text-nhi-ghost">{asset.deployment_type}</span>}
                        {asset.access_pattern && <span className="text-[7px] text-nhi-ghost">{asset.access_pattern}</span>}
                        {asset.auth_method && <span className="text-[7px] text-nhi-ghost">{asset.auth_method}</span>}
                        {asset.machine_type && <span className="text-[7px] font-mono text-nhi-ghost">{asset.machine_type}</span>}
                        {asset.accelerator?.type && <span className="text-[7px] font-mono text-cyan-400">{asset.accelerator.type} x{asset.accelerator.count}</span>}
                      </div>
                      {asset.service_account && (
                        <div className="text-[7px] font-mono text-nhi-faint mt-0.5 truncate">{asset.service_account}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* LLM Gateways */}
          {data?.llm_gateways?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">LLM Gateways ({data.llm_gateways.length})</div>
              <div className="space-y-1">
                {data.llm_gateways.map((gw, i) => {
                  const meta = GATEWAY_META[gw.id] || { label: gw.label, color: '#94a3b8', icon: '🔀' };
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-lg" style={{ background: `${meta.color}08`, border: `1px solid ${meta.color}15` }}>
                      <span className="text-sm">{meta.icon}</span>
                      <span className="text-[10px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                      <span className="text-[7px] text-nhi-ghost ml-auto">{gw.credential_keys?.length || 0} keys</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* LLM Observability */}
          {data?.llm_observability?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">Observability</div>
              <div className="flex flex-wrap gap-1">
                {data.llm_observability.map((obs, i) => {
                  const meta = GATEWAY_META[obs.id] || { label: obs.label, color: '#94a3b8', icon: '📊' };
                  return (
                    <span key={i} className="text-[8px] font-bold px-2 py-1 rounded-lg flex items-center gap-1"
                      style={{ background: `${meta.color}10`, color: meta.color, border: `1px solid ${meta.color}20` }}>
                      <span className="text-[10px]">{meta.icon}</span> {meta.label}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Vector Stores */}
          {data?.embeddings_and_vectors?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">Vector Stores ({data.embeddings_and_vectors.length})</div>
              <div className="space-y-1">
                {data.embeddings_and_vectors.map((v, i) => {
                  const meta = VECTOR_META[v.id] || { label: v.label, color: '#94a3b8', icon: '💾' };
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-lg" style={{ background: `${meta.color}08`, border: `1px solid ${meta.color}15` }}>
                      <span className="text-sm">{meta.icon}</span>
                      <span className="text-[10px] font-bold" style={{ color: meta.color }}>{meta.label}</span>
                      {v.index && <span className="text-[8px] font-mono text-nhi-dim ml-auto">{v.index}</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Frameworks */}
          {data?.frameworks?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">Frameworks</div>
              <div className="flex flex-wrap gap-1">
                {data.frameworks.map((f, i) => (
                  <span key={i} className="text-[8px] font-bold px-2 py-1 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/15">
                    {f.label}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Fine-tuning */}
          {data?.fine_tuning?.detected && (
            <div className="px-2 py-2 rounded-lg" style={{ background: 'rgba(6,182,212,0.05)', border: '1px solid rgba(6,182,212,0.15)' }}>
              <div className="text-[8px] font-bold text-cyan-400 uppercase mb-1">Fine-Tuned Model</div>
              <div className="text-[9px] font-mono text-nhi-text">{data.fine_tuning.model_id || 'Detected'}</div>
              {data.fine_tuning.method && <div className="text-[8px] text-nhi-dim mt-0.5">Method: {data.fine_tuning.method}</div>}
              {data.fine_tuning.signals?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {data.fine_tuning.signals.map((s, i) => <span key={i} className="text-[7px] font-mono px-1 py-0.5 rounded bg-cyan-500/10 text-cyan-400">{s}</span>)}
                </div>
              )}
            </div>
          )}

          {/* Skills & Tools */}
          {hasSkills && (
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[8px] font-bold text-nhi-ghost uppercase">Skills & Tools</span>
                {(skills.length + tools.length) > 6 && (
                  <button onClick={() => setSkillsExpanded(!skillsExpanded)} className="text-[8px] text-nhi-ghost hover:text-nhi-muted">
                    {skillsExpanded ? 'collapse' : 'show all'}
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(skillsExpanded ? skills : skills.slice(0, 3)).map((s, i) => (
                  <Pill key={`s-${i}`} color="#c084fc">{typeof s === 'string' ? s : s.name || s.id}</Pill>
                ))}
                {(skillsExpanded ? tools : tools.slice(0, 3)).map((t, i) => (
                  <Pill key={`t-${i}`} color="#67e8f9">{typeof t === 'string' ? t : t.name || t.id}</Pill>
                ))}
                {!skillsExpanded && (skills.length + tools.length) > 6 && (
                  <span className="text-[9px] text-nhi-ghost">+{skills.length + tools.length - 6} more</span>
                )}
              </div>
            </div>
          )}

          {/* Risk Flags */}
          {data?.risk_flags?.length > 0 && (
            <div>
              <div className="text-[8px] font-bold text-nhi-ghost uppercase mb-1.5">Risk Flags</div>
              <div className="flex flex-wrap gap-1">
                {data.risk_flags.map((rf, i) => {
                  const meta = RISK_META[rf] || { label: rf, color: '#f59e0b', icon: '⚠️' };
                  return (
                    <span key={i} className="text-[8px] font-bold px-2 py-1 rounded-lg flex items-center gap-1"
                      style={{ background: `${meta.color}10`, color: meta.color, border: `1px solid ${meta.color}20` }}>
                      <span className="text-[10px]">{meta.icon}</span> {meta.label}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* IETF AIMS Identity & Attestation */}
          {m.ietf_aims && (() => {
            const aims = m.ietf_aims;
            const attestColors = { tee: '#10b981', platform: '#3b82f6', software: '#f59e0b', none: '#ef4444' };
            const delegColors = { user_delegation: '#3b82f6', cross_domain: '#f97316', self_auth: '#10b981' };
            const cred = aims.credential_provisioning || {};
            const credColor = cred.method === 'jit' ? '#10b981' : cred.method === 'static' ? '#ef4444' : '#94a3b8';
            const driftColor = (aims.scope_drift_score || 0) > 0.3 ? '#ef4444' : (aims.scope_drift_score || 0) > 0.1 ? '#f59e0b' : '#10b981';

            return (
              <div className="pt-2 border-t border-white/[0.05]">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-3 h-3 text-cyan-400" />
                  <span className="text-[8px] font-bold text-cyan-400 uppercase tracking-wider">Identity & Attestation</span>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
                  <span className="text-nhi-ghost">Attestation</span>
                  <span className="font-semibold" style={{ color: attestColors[aims.attestation_type] || '#94a3b8' }}>{(aims.attestation_type || 'none').toUpperCase()}</span>
                  <span className="text-nhi-ghost">Delegation</span>
                  <span className="font-semibold" style={{ color: delegColors[aims.delegation_type] || '#94a3b8' }}>{aims.delegation_type ? aims.delegation_type.replace(/_/g, ' ').toUpperCase() : '\u2014'}</span>
                  <span className="text-nhi-ghost">Credentials</span>
                  <span className="font-semibold" style={{ color: credColor }}>{(cred.method || 'unknown').toUpperCase()}{cred.active_tokens > 0 ? ` (${cred.active_tokens} active)` : ''}</span>
                  <span className="text-nhi-ghost">Scope Drift</span>
                  <span className="font-semibold" style={{ color: driftColor }}>{(aims.scope_drift_score || 0).toFixed(2)}</span>
                </div>
                {(aims.observable_risk_indicators || []).length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {aims.observable_risk_indicators.map((ind, i) => (
                      <Pill key={i} color={ind.includes('delegation') || ind.includes('drift') ? '#f97316' : '#ef4444'}>{ind}</Pill>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Observed from Logs */}
          {observedData && observedTotal > 0 && (
            <div className="pt-2 border-t border-white/[0.05]">
              <div className="flex items-center gap-2 mb-2">
                <Eye className="w-3 h-3 text-amber-400" />
                <span className="text-[8px] font-bold text-amber-400 uppercase tracking-wider">Observed from Logs</span>
                <span className="text-[7px] text-nhi-ghost">{observedData.decision_count} decisions analyzed</span>
              </div>
              <div className="space-y-1.5">
                {[...(observedData.observed?.llm_providers || []), ...(observedData.observed?.vector_stores || []), ...(observedData.observed?.external_apis || [])].map((p, i) => {
                  const meta = PROVIDER_META[p.provider] || VECTOR_META[p.provider] || { label: p.label, color: '#94a3b8', icon: '🔗' };
                  const isNew = (observedData.delta?.new_llm_providers || []).some(d => d.provider === p.provider) ||
                                (observedData.delta?.new_vector_stores || []).some(d => d.provider === p.provider) ||
                                (observedData.delta?.new_external_apis || []).some(d => d.provider === p.provider);
                  const lastSeen = p.last_seen ? (() => {
                    const ms = Date.now() - new Date(p.last_seen).getTime();
                    if (ms < 60000) return 'just now';
                    if (ms < 3600000) return `${Math.floor(ms/60000)}m ago`;
                    if (ms < 86400000) return `${Math.floor(ms/3600000)}h ago`;
                    return `${Math.floor(ms/86400000)}d ago`;
                  })() : null;
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-lg" style={{ background: `${meta.color}06`, border: `1px solid ${meta.color}12` }}>
                      <span className="text-sm">{meta.icon || '🔗'}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-bold" style={{ color: meta.color }}>{meta.label || p.label}</span>
                          {isNew && <span className="text-[6px] font-bold px-1 py-0.5 rounded bg-amber-500/15 text-amber-400">NEW</span>}
                        </div>
                        <div className="flex items-center gap-2 text-[7px] text-nhi-ghost">
                          <span>{p.call_count} call{p.call_count !== 1 ? 's' : ''}</span>
                          {lastSeen && <span>last {lastSeen}</span>}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
          {observedLoading && (
            <div className="pt-2 border-t border-white/[0.05] flex items-center gap-2">
              <Loader className="w-3 h-3 animate-spin text-amber-400" />
              <span className="text-[8px] text-nhi-ghost">Loading observed data from logs...</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   AI Agents Overview — standalone page/panel
   ═══════════════════════════════════════════ */
export function AIAgentsOverview() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    fetch(`${DISC}/ai-enrichment/all`)
      .then(r => r.json())
      .then(d => { setAgents(d.agents || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const enriched = agents.filter(a => a.enrichment?.llm_providers?.length > 0 || a.enrichment?.embeddings_and_vectors?.length > 0);

  return (
    <div className="p-4">
      <div className="flex items-center gap-2 mb-4">
        <Bot className="w-5 h-5 text-purple-400" />
        <h2 className="text-sm font-bold text-nhi-text">AI Agent Intelligence</h2>
        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400">{enriched.length} enriched</span>
        <span className="text-[9px] text-nhi-ghost">{agents.length} total</span>
      </div>

      {loading ? (
        <div className="flex justify-center py-8"><Loader className="w-5 h-5 text-accent animate-spin" /></div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {agents.map(a => {
            const e = a.enrichment || {};
            const hasEnrich = e.llm_providers?.length > 0 || e.embeddings_and_vectors?.length > 0;
            return (
              <div key={a.workload_id} onClick={() => setSelected(selected === a.workload_id ? null : a.workload_id)}
                className={`rounded-xl border p-3 cursor-pointer transition-all ${selected === a.workload_id ? 'border-purple-500/30 bg-purple-500/[0.03]' : 'border-[var(--border)] hover:border-purple-500/15'}`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">{a.is_ai_agent ? '🤖' : a.type === 'mcp-server' ? '🔌' : '⚙️'}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[11px] font-bold text-nhi-text truncate">{a.workload_name}</div>
                    <div className="text-[8px] text-nhi-ghost">{a.type}</div>
                  </div>
                  {hasEnrich ? (
                    <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full bg-purple-500/10 text-purple-400">ENRICHED</span>
                  ) : (
                    <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full bg-surface-3 text-nhi-ghost">NO DATA</span>
                  )}
                </div>

                {hasEnrich && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {e.llm_providers?.map((p, i) => (
                      <span key={i} className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{ background: `${(PROVIDER_META[p.id]||{}).color || '#94a3b8'}10`, color: (PROVIDER_META[p.id]||{}).color || '#94a3b8' }}>
                        {(PROVIDER_META[p.id]||{}).icon} {p.model || p.label}
                      </span>
                    ))}
                    {e.embeddings_and_vectors?.map((v, i) => (
                      <span key={`v${i}`} className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{ background: `${(VECTOR_META[v.id]||{}).color || '#94a3b8'}10`, color: (VECTOR_META[v.id]||{}).color || '#94a3b8' }}>
                        {(VECTOR_META[v.id]||{}).icon} {v.label}
                      </span>
                    ))}
                    {e.risk_flags?.map((rf, i) => {
                      const rm = RISK_META[rf] || { color: '#f59e0b', icon: '⚠️', label: rf };
                      return <span key={`r${i}`} className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{ background: `${rm.color}10`, color: rm.color }}>{rm.icon} {rm.label}</span>;
                    })}
                  </div>
                )}

                {selected === a.workload_id && hasEnrich && (
                  <AIEnrichmentPanel workloadId={a.workload_id} workloadName={a.workload_name} inline />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default AIEnrichmentPanel;
