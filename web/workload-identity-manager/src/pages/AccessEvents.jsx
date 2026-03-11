import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { RefreshCw, Activity, Shield, ShieldOff, Clock, Zap, ChevronRight, ChevronDown,
         AlertTriangle, CheckCircle2, XCircle, Layers, ArrowRight, GitBranch, Play, Loader,
         Search, TrendingUp, TrendingDown, ExternalLink, Filter, BarChart3,
         SkipForward, Square, RotateCcw, FastForward, Pause, X, PanelLeftClose,
         FileText, Download } from 'lucide-react';
import { jsPDF } from 'jspdf';

const RouteIcon = (p) => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/></svg>;
const ListIcon = (p) => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>;

const VERDICT_CFG = {
  allow:     { label: 'ALLOW', color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.2)', icon: CheckCircle2 },
  granted:   { label: 'ALLOW', color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.2)', icon: CheckCircle2 },
  'audit-deny': { label: 'AUDIT DENY', color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.2)', icon: AlertTriangle },
  deny:      { label: 'DENY', color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', icon: XCircle },
  denied:    { label: 'DENY', color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', icon: XCircle },
  'no-match':{ label: 'NO MATCH', color: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.2)', icon: AlertTriangle },
};
const verdictFor = v => VERDICT_CFG[v] || VERDICT_CFG['no-match'];

function timeAgo(ts) {
  if (!ts) return '';
  const ms = Date.now() - new Date(ts).getTime();
  if (ms < 1000) return 'now'; if (ms < 60000) return Math.floor(ms/1000)+'s';
  if (ms < 3600000) return Math.floor(ms/60000)+'m'; if (ms < 86400000) return Math.floor(ms/3600000)+'h';
  return Math.floor(ms/86400000)+'d';
}

const TYPE_MAP = {
  stripe: { type: 'Financial API', abbr: 'FIN', color: '#635bff' },
  salesforce: { type: 'CRM API', abbr: 'CRM', color: '#00a1e0' },
  slack: { type: 'Messaging', abbr: 'MSG', color: '#4a154b' },
  mcp: { type: 'MCP Server', abbr: 'MCP', color: '#06b6d4' },
  agent: { type: 'AI Agent', abbr: 'AGT', color: '#8b5cf6' },
  demo: { type: 'AI Agent', abbr: 'AGT', color: '#8b5cf6' },
  credential: { type: 'Credential', abbr: 'CRD', color: '#f59e0b' },
  vault: { type: 'Credential', abbr: 'CRD', color: '#f59e0b' },
  token: { type: 'Credential', abbr: 'CRD', color: '#f59e0b' },
  user: { type: 'User', abbr: 'USR', color: '#3b82f6' },
  alice: { type: 'User', abbr: 'USR', color: '#3b82f6' },
  relay: { type: 'Gateway', abbr: 'GW', color: '#06b6d4' },
  discovery: { type: 'Discovery', abbr: 'DSC', color: '#3b82f6' },
  policy: { type: 'Policy', abbr: 'POL', color: '#10b981' },
  public: { type: 'External', abbr: 'EXT', color: '#ef4444' },
  internet: { type: 'External', abbr: 'EXT', color: '#ef4444' },
};

function detectType(name) {
  if (!name) return { type: 'Unknown', abbr: '?', color: '#64748b' };
  const n = name.toLowerCase();
  if (n.includes('mcp') && n.includes('server')) return TYPE_MAP.mcp;
  for (const [key, val] of Object.entries(TYPE_MAP)) {
    if (n.includes(key)) return val;
  }
  return { type: 'Service', abbr: 'SVC', color: '#64748b' };
}

function TypeBadge({ name, size = 'sm' }) {
  const t = detectType(name);
  const sz = size === 'lg' ? 'w-8 h-8 text-[9px]' : 'w-5 h-5 text-[7px]';
  return (
    <div className={`${sz} rounded flex items-center justify-center font-bold flex-shrink-0`}
      style={{ background: t.color + '18', color: t.color, border: `1px solid ${t.color}25` }}>
      {t.abbr}
    </div>
  );
}

const TIME_RANGES = [
  { key: '1h',  label: '1H',  hours: 1 },
  { key: '6h',  label: '6H',  hours: 6 },
  { key: '24h', label: '24H', hours: 24 },
  { key: '7d',  label: '7D',  hours: 168 },
];

/* ==================== Sparkline (SVG) ==================== */
function Sparkline({ data, width = 80, height = 24, color = '#10b981', fillOpacity = 0.15 }) {
  if (!data || data.length < 2) return <div style={{ width, height }} />;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((v - min) / range) * (height - 2) - 1;
    return `${x},${y}`;
  });
  return (
    <svg width={width} height={height} style={{ display: 'block' }}>
      <polyline points={points.join(' ')} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
      <polygon points={`${points.join(' ')} ${width},${height} 0,${height}`} fill={color} fillOpacity={fillOpacity} />
    </svg>
  );
}

/* ==================== Trust Level Pill ==================== */
function TrustPill({ level }) {
  const cfg = {
    cryptographic: { bg: '#10b98120', color: '#10b981', label: 'CRYPTO' },
    'very-high': { bg: '#10b98118', color: '#10b981', label: 'V-HIGH' },
    high: { bg: '#3b82f618', color: '#3b82f6', label: 'HIGH' },
    medium: { bg: '#f59e0b18', color: '#f59e0b', label: 'MED' },
    low: { bg: '#ef444418', color: '#ef4444', label: 'LOW' },
    none: { bg: '#64748b18', color: '#64748b', label: 'NONE' },
  };
  const c = cfg[level] || cfg.none;
  return <span className="text-[6px] font-bold px-1 py-0.5 rounded" style={{ background: c.bg, color: c.color }}>{c.label}</span>;
}

/* ==================== Collapsible Section ==================== */
function CollapsibleSection({ title, icon, summaryText, accentColor, defaultExpanded = false, children }) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  return (
    <div className="mb-1" style={{ borderBottom: '1px solid var(--border)' }}>
      <div onClick={() => setExpanded(e => !e)}
        className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-surface-3/50 transition-colors select-none">
        <ChevronRight className="w-3 h-3 flex-shrink-0 transition-transform duration-150"
          style={{ color: accentColor || 'var(--text-faint)', transform: expanded ? 'rotate(90deg)' : 'none' }} />
        {icon}
        <span className="text-[9px] font-bold uppercase" style={{ color: accentColor || 'var(--text-secondary)' }}>
          {title}
        </span>
        {!expanded && summaryText && (
          <span className="text-[8px] text-nhi-faint font-mono truncate ml-auto">{summaryText}</span>
        )}
      </div>
      {expanded && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

/* ==================== Enforcement Branch Timeline (Vertical Railroad) ==================== */
function EnforcementBranchTimeline({ hops, selectedHop, onHopClick, phaseCfg }) {
  const ACCENT = '#7c6ff0';
  const firstHop = hops[0];
  const src = firstHop?.source_name || firstHop?.source || '';
  const dst = firstHop?.destination_name || firstHop?.destination || '';
  const srcType = detectType(src);
  const dstType = detectType(dst);

  // Branch colors based on phase + verdict
  const getBranchColor = (idx) => {
    const h = hops[idx];
    if (idx === selectedHop) return ACCENT;
    if (idx === 0) return '#64748b'; // BASELINE = gray
    if (idx === 1) return '#f59e0b'; // AUDIT = amber
    // ENFORCE: red for deny, green for allow
    const v = h?.verdict;
    return (v === 'deny' || v === 'denied') ? '#ef4444' : '#10b981';
  };

  const getVerdictLabel = (h) => {
    if (!h) return 'N/A';
    const v = h.verdict;
    if (v === 'allow' || v === 'granted') return 'ALLOW';
    if (h.adapter_mode === 'audit') return 'WOULD_BLOCK';
    if (v === 'deny' || v === 'denied') return 'DENY';
    return v?.toUpperCase() || 'N/A';
  };

  const W = 380;
  const trunkH = 75;
  const branchStartY = trunkH + 20;
  const branchLen = 130;
  const cx = W / 2;
  const branchSpacing = 100;
  const branchXs = hops.length === 3
    ? [cx - branchSpacing, cx, cx + branchSpacing]
    : hops.length === 2
    ? [cx - branchSpacing / 2, cx + branchSpacing / 2]
    : [cx];
  const totalH = branchStartY + branchLen + 80;

  return (
    <div className="pb-2 pt-1 flex justify-center">
      <svg width={W} height={totalH} style={{ display: 'block' }}>
        {/* Trunk: Source node */}
        <circle cx={cx} cy={20} r={16} fill="var(--surface-3)" stroke="var(--border)" strokeWidth={1.5} />
        <text x={cx} y={24} textAnchor="middle" fill={srcType.color} fontSize={9} fontWeight={700}>{srcType.abbr}</text>
        {/* Source name below circle */}
        <foreignObject x={cx - 60} y={38} width={120} height={18}>
          <div style={{ fontSize: 9, fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {src.replace(/^wid-dev-/, '').substring(0, 20)}
          </div>
        </foreignObject>

        {/* Trunk line to branch point */}
        <line x1={cx} y1={38} x2={cx} y2={branchStartY - 12} stroke="#64748b50" strokeWidth={2} />

        {/* Request context label */}
        <foreignObject x={cx + 22} y={50} width={150} height={18}>
          <div style={{ fontSize: 8, color: 'var(--text-faint)', fontFamily: 'monospace' }}>
            {(firstHop?.method || 'POST')} → {dst.replace(/^wid-dev-/, '').substring(0, 18)}
          </div>
        </foreignObject>

        {/* Diamond branch point */}
        <g transform={`translate(${cx}, ${branchStartY})`}>
          <rect x={-10} y={-10} width={20} height={20} rx={3} transform="rotate(45)" fill="#7c6ff015" stroke="#7c6ff050" strokeWidth={1.5} />
          <text x={0} y={3} textAnchor="middle" fill="#7c6ff0" fontSize={6} fontWeight={700}>EVAL</text>
        </g>

        {/* Branches */}
        {hops.map((h, idx) => {
          const bx = branchXs[idx] || cx;
          const color = getBranchColor(idx);
          const isActive = idx === selectedHop;
          const phaseName = phaseCfg[idx]?.label || `PHASE ${idx}`;
          const verdictLabel = getVerdictLabel(h);
          const verdictColor = (h.verdict === 'allow' || h.verdict === 'granted') ? '#10b981' : (h.adapter_mode === 'audit' ? '#f59e0b' : '#ef4444');

          return (
            <g key={idx} onClick={() => onHopClick(idx)} style={{ cursor: 'pointer' }}>
              {/* Branch line from diamond to branch node */}
              <line x1={cx} y1={branchStartY + 14} x2={bx} y2={branchStartY + 40} stroke={`${color}60`} strokeWidth={isActive ? 2.5 : 2} strokeDasharray={isActive ? 'none' : '4,3'} />
              {/* Vertical branch line */}
              <line x1={bx} y1={branchStartY + 40} x2={bx} y2={branchStartY + branchLen} stroke={isActive ? color : `${color}50`} strokeWidth={isActive ? 2.5 : 2} />
              {/* Branch glow for active */}
              {isActive && (
                <line x1={bx} y1={branchStartY + 40} x2={bx} y2={branchStartY + branchLen} stroke={color} strokeWidth={6} opacity={0.15} />
              )}
              {/* Branch circle node */}
              <circle cx={bx} cy={branchStartY + 40} r={isActive ? 12 : 10} fill={isActive ? color : `${color}20`} stroke={color} strokeWidth={isActive ? 2 : 1.5} />
              {isActive && <circle cx={bx} cy={branchStartY + 40} r={16} fill="none" stroke={color} strokeWidth={1} opacity={0.3} />}
              {/* Phase label inside circle */}
              <text x={bx} y={branchStartY + 43} textAnchor="middle" fill={isActive ? '#fff' : color} fontSize={7} fontWeight={700}>
                {phaseName.substring(0, 3)}
              </text>
              {/* Phase name below node */}
              <text x={bx} y={branchStartY + 60} textAnchor="middle" fill={isActive ? '#eceaf4' : color} fontSize={8} fontWeight={isActive ? 700 : 600}>
                {phaseName}
              </text>

              {/* Decision details along branch */}
              <foreignObject x={bx - 50} y={branchStartY + 68} width={100} height={branchLen - 38}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                  {/* Policy name */}
                  <div style={{ fontSize: 7, fontFamily: 'monospace', color: isActive ? 'var(--text-secondary)' : 'var(--text-faint)', textAlign: 'center', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 96 }}>
                    {h.policy_name || 'default-deny'}
                  </div>
                  {/* Verdict badge */}
                  <div style={{
                    fontSize: 7, fontWeight: 700, letterSpacing: '0.5px',
                    padding: '2px 6px', borderRadius: 4,
                    background: `${verdictColor}18`, color: verdictColor,
                    border: `1px solid ${verdictColor}30`,
                  }}>
                    {verdictLabel}
                  </div>
                  {/* Enforcement action */}
                  <div style={{ fontSize: 7, color: isActive ? 'var(--text-secondary)' : 'var(--text-ghost)', textAlign: 'center' }}>
                    {h.enforcement_action || (h.verdict === 'deny' || h.verdict === 'denied' ? 'REJECT_REQUEST' : h.adapter_mode === 'audit' ? 'LOG_VIOLATION' : 'FORWARD_REQUEST')}
                  </div>
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ==================== Trace/Enforcement Detail (Right Panel) ==================== */
function TraceDetail({ traceHops, selectedDecision, initialHopIndex, onNavigateGraph, onReplayActive }) {
  const [selectedHop, setSelectedHop] = useState(0);
  const [rerunResults, setRerunResults] = useState(null);
  const [rerunning, setRerunning] = useState(false);
  const [rerunProgress, setRerunProgress] = useState({ hop: -1, step: '', total: 0 });
  const [auditReplay, setAuditReplay] = useState(null);
  const [auditReplayLoading, setAuditReplayLoading] = useState(false);
  const userPickedHop = useRef(false); // tracks whether user manually clicked a hop
  const prevTraceId = useRef(null);

  // Step-by-step replay state
  const [replayMode, setReplayMode] = useState(null); // null | 'auto' | 'step'
  const [currentStepIdx, setCurrentStepIdx] = useState(-1);
  const [completedSteps, setCompletedSteps] = useState([]); // { step, request, response, logs, error, duration, dataBridge }
  const [activeStepTab, setActiveStepTab] = useState({}); // { [stepIdx]: 'request' | 'response' | 'logs' }
  const stepGateRef = useRef(null); // { resolve } — gate for step mode
  const abortRef = useRef(false);

  const hops = traceHops && traceHops.length > 0 ? traceHops : (selectedDecision ? [selectedDecision] : null);
  const currentTraceId = hops?.[0]?.trace_id || selectedDecision?.id;

  // Only reset selectedHop when the TRACE changes (different trace_id), not on auto-refresh
  useEffect(() => {
    if (initialHopIndex !== null && initialHopIndex !== undefined) {
      setSelectedHop(initialHopIndex);
      userPickedHop.current = true;
    }
  }, [initialHopIndex]);

  useEffect(() => {
    if (currentTraceId !== prevTraceId.current) {
      // Genuinely new trace selected — reset
      setRerunResults(null);
      setSelectedHop(initialHopIndex || 0);
      userPickedHop.current = false;
      prevTraceId.current = currentTraceId;
      setAuditReplay(null);
      setAuditReplayLoading(false);
      // Reset replay state
      setReplayMode(null);
      setCurrentStepIdx(-1);
      setCompletedSteps([]);
      setActiveStepTab({});
      abortRef.current = true;
    }
    // Auto-refresh with same trace: don't reset selectedHop
  }, [currentTraceId, initialHopIndex]);

  const handleHopClick = (hopIdx) => {
    setSelectedHop(hopIdx);
    userPickedHop.current = true;
  };

  const API = ''; // URLs already include /api/v1 prefix; proxy handles routing

  // ── Audit Replay: fetch historical replay data from backend ──
  const fetchAuditReplay = async () => {
    if (!traceId) return;
    if (auditReplay) { setAuditReplay(null); return; } // toggle off
    setAuditReplayLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/access/decisions/replay/${encodeURIComponent(traceId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      // Backend wraps in { replay: {...} } — normalize
      setAuditReplay(data.replay || data);
    } catch (e) {
      console.error('Audit replay fetch failed:', e);
      setAuditReplay({ error: e.message });
    } finally {
      setAuditReplayLoading(false);
    }
  };

  // ── PDF Export: generate downloadable compliance report ──
  const generatePDF = (replayData) => {
    if (!replayData || replayData.error) return;
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    const W = doc.internal.pageSize.getWidth();
    let y = 20;
    const lineH = 5;
    const checkPage = (need = 20) => { if (y + need > 275) { doc.addPage(); y = 20; } };

    // Title
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Authorization Decision Replay Report', W / 2, y, { align: 'center' });
    y += 10;

    // Meta
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const meta = [
      ['Trace ID', replayData.trace_id || traceId],
      ['Generated At', replayData.generated_at || new Date().toISOString()],
      ['Origin', replayData.origin || 'N/A'],
      ['Final Verdict', (replayData.final_verdict || 'N/A').toUpperCase()],
      ['Chain Authorized', replayData.chain_authorized ? 'YES' : 'NO'],
      ['Total Hops', String(replayData.hops?.length || 0)],
    ];
    for (const [k, v] of meta) {
      doc.setFont('helvetica', 'bold');
      doc.text(`${k}:`, 15, y);
      doc.setFont('helvetica', 'normal');
      doc.text(v, 55, y);
      y += lineH;
    }
    y += 5;

    // Hops
    const hopsData = replayData.hops || [];
    for (let i = 0; i < hopsData.length; i++) {
      checkPage(40);
      const h = hopsData[i];
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(`Hop ${i + 1}: ${h.source || 'unknown'} → ${h.destination || 'unknown'}`, 15, y);
      y += 6;
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      const hopFields = [
        ['Verdict', (h.verdict || 'N/A').toUpperCase()],
        ['Policy', h.policy_name || h.policy?.name || 'default-deny'],
        ['Policy Version', h.policy_version_hash || h.policy?.version || 'N/A'],
        ['Method / Path', `${h.method || 'POST'} ${h.path || '/'}`],
        ['Enforcement', h.enforcement_action || 'N/A'],
        ['Latency', `${h.latency_ms || 0}ms`],
      ];
      for (const [k, v] of hopFields) {
        doc.setFont('helvetica', 'bold');
        doc.text(`  ${k}:`, 15, y);
        doc.setFont('helvetica', 'normal');
        doc.text(v, 55, y);
        y += lineH;
      }

      // Policy snapshot
      if (h.policy_snapshot || h.policy?.snapshot) {
        const ps = h.policy_snapshot || h.policy.snapshot;
        checkPage(25);
        y += 2;
        doc.setFont('helvetica', 'bold');
        doc.text('  Policy Snapshot:', 15, y);
        y += lineH;
        doc.setFont('helvetica', 'normal');
        const psFields = [
          ['Effect', ps.effect || 'deny'],
          ['Enforcement Mode', ps.enforcement_mode || 'enforce'],
          ['Severity', ps.severity || 'N/A'],
        ];
        for (const [k, v] of psFields) {
          doc.text(`    ${k}: ${v}`, 15, y);
          y += lineH;
        }
        if (ps.conditions?.length) {
          doc.text(`    Conditions: ${ps.conditions.map(c => `${c.field} ${c.operator} ${c.value || ''}`).join('; ')}`, 15, y);
          y += lineH;
        }
        if (ps.actions?.length) {
          doc.text(`    Actions: ${ps.actions.map(a => a.type || a).join(', ')}`, 15, y);
          y += lineH;
        }
      }

      // Token context
      if (h.token_context) {
        checkPage(15);
        const tc = typeof h.token_context === 'string' ? JSON.parse(h.token_context) : h.token_context;
        doc.text(`  Trust Level: ${tc.trust_level || 'N/A'}`, 15, y);
        y += lineH;
        doc.text(`  Attestation: ${tc.attestation_method || 'N/A'}`, 15, y);
        y += lineH;
      }
      y += 5;
    }

    // Chain integrity
    checkPage(15);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    const chainOk = replayData.chain_authorized !== false;
    doc.text(`Chain Integrity: ${chainOk ? 'ALL HOPS AUTHORIZED' : 'CHAIN VIOLATION DETECTED'}`, 15, y);
    y += 10;

    // Footer
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(128);
    doc.text('Generated by WID Platform — Deterministic Decision Replay', W / 2, 287, { align: 'center' });
    doc.setTextColor(0);

    const dateStr = new Date().toISOString().split('T')[0];
    doc.save(`replay-${(traceId || 'unknown').replace(/[^a-zA-Z0-9-]/g, '_')}-${dateStr}.pdf`);
  };

  // ── Build the full list of steps for replay ──
  const buildStepList = () => {
    if (!hops || hops.length === 0) return [];
    const steps = [];
    for (let i = 0; i < hops.length; i++) {
      const h = hops[i];
      const src = h.source_name || h.source;
      const dst = h.destination_name || h.destination;
      steps.push({ type: 'attest', hopIdx: i, title: `Attest ${src}`, src, dst });
      steps.push({ type: 'token', hopIdx: i, title: `Issue WID Token`, src, dst });
      steps.push({ type: 'gateway', hopIdx: i, title: `Gateway: ${src} → ${dst}`, src, dst });
    }
    return steps;
  };

  // ── Execute a single step ──
  const executeStep = async (stepDef, attestCache) => {
    const start = performance.now();
    const logs = [];
    const log = (msg) => logs.push({ ts: new Date().toISOString(), msg });
    let request = null, response = null, error = null, dataBridge = null;
    const { type, src, dst, hopIdx } = stepDef;
    const h = hops[hopIdx];

    try {
      if (type === 'attest') {
        if (attestCache[src]) {
          log(`Using cached attestation for ${src} (trust: ${attestCache[src].trust})`);
          response = { cached: true, trust_level: attestCache[src].trust };
          dataBridge = `trust: ${attestCache[src].trust}`;
        } else {
          log(`Looking up workload ${src}...`);
          request = { method: 'POST', url: `/api/v1/workloads/{id}/verify`, body: { method: 'attest' } };
          const wResp = await fetch(`${API}/api/v1/workloads`);
          if (!wResp.ok && !(wResp.headers.get('content-type')||'').includes('json')) throw new Error(`Workload lookup failed: HTTP ${wResp.status}`);
          const wData = await wResp.json();
          const wl = (wData.workloads||[]).find(w => w.name === src);
          if (wl) {
            log(`Found workload ${wl.id}, sending attestation request...`);
            request.url = `/api/v1/workloads/${wl.id}/verify`;
            const aResp = await fetch(`${API}/api/v1/workloads/${wl.id}/verify`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({method:'attest'}) });
            if (!aResp.ok && !(aResp.headers.get('content-type')||'').includes('json')) throw new Error(`Attestation failed: HTTP ${aResp.status}`);
            const aData = await aResp.json();
            attestCache[src] = { trust: aData.trust_level, method: aData.verification_method, token: aData.token };
            response = { trust_level: aData.trust_level, method: aData.verification_method, token_issued: !!aData.token };
            log(`Attestation complete: trust=${aData.trust_level}, method=${aData.verification_method}`);
            dataBridge = `trust: ${aData.trust_level}`;
          } else {
            attestCache[src] = { trust: 'none' };
            response = { trust_level: 'none', note: 'External entity — no attestation' };
            log(`Workload ${src} not found — treating as external`);
            dataBridge = 'trust: none (external)';
          }
        }
      } else if (type === 'token') {
        const cached = attestCache[src];
        if (cached?.token?.token) {
          log(`Token already issued during attestation`);
          response = { spiffe_id: cached.token.spiffe_id, trust_level: cached.token.trust_level, ttl: cached.token.ttl_seconds };
          dataBridge = `token: ${cached.token.spiffe_id}`;
        } else if (cached?.trust && cached.trust !== 'none') {
          request = { method: 'POST', url: '/api/v1/tokens/issue', body: { workload_name: src } };
          log(`Requesting WID token for ${src}...`);
          const tR = await fetch(`${API}/api/v1/tokens/issue`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({workload_name: src}) });
          if (!tR.ok && !(tR.headers.get('content-type')||'').includes('json')) throw new Error(`Token issuance failed: HTTP ${tR.status}`);
          const tD = await tR.json();
          if (tR.status < 400 && tD.token) {
            attestCache[src].token = tD;
            response = { spiffe_id: tD.spiffe_id, trust_level: tD.trust_level, ttl: tD.ttl_seconds };
            log(`Token issued: ${tD.spiffe_id}, TTL ${tD.ttl_seconds}s`);
            dataBridge = `token: ${tD.spiffe_id}`;
          } else {
            response = { error: tD.error || 'Token issuance failed' };
            log(`Token issuance failed: ${tD.error || 'unknown error'}`);
          }
        } else {
          log(`Skipping token — trust level is 'none'`);
          response = { skipped: true, reason: 'No attestation or trust=none' };
        }
      } else if (type === 'gateway') {
        const cached = attestCache[src];
        const token = cached?.token?.token || null;
        request = { method: 'POST', url: '/api/v1/gateway/evaluate', body: { source: src, destination: dst, method: h.method || 'POST', path: h.path_pattern || '/', wid_token: token ? '(attached)' : 'none' } };
        log(`Evaluating gateway policy: ${src} → ${dst}`);
        const gR = await fetch(`${API}/api/v1/gateway/evaluate`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ source: src, destination: dst, method: h.method || 'POST', path: h.path_pattern || '/', ...(token ? { wid_token: token } : {}) }) });
        const gContentType = gR.headers.get('content-type') || '';
        if (!gContentType.includes('application/json')) {
          const txt = await gR.text();
          throw new Error(`Gateway returned ${gR.status} (non-JSON). Endpoint may not be routed correctly.`);
        }
        const gD = await gR.json();
        if (gD.error) {
          response = { error: gD.error, status: gR.status };
          log(`Gateway error: ${gD.error}`);
        } else {
          response = { verdict: gD.verdict, policy_name: gD.policy_name, enforcement_action: gD.enforcement_action, latency_ms: gD.latency_ms };
          log(`Gateway verdict: ${gD.verdict?.toUpperCase()} | policy: ${gD.policy_name} | ${gD.latency_ms}ms`);
          dataBridge = `verdict: ${gD.verdict?.toUpperCase()}`;
        }
      }
    } catch (e) {
      error = e.message;
      log(`ERROR: ${e.message}`);
    }

    const duration = Math.round(performance.now() - start);
    const status = error ? 'fail' : (type === 'gateway' && response?.verdict && response.verdict !== 'allow') ? 'deny' : (response?.skipped) ? 'skip' : 'pass';
    return { step: stepDef, request, response, logs, error, duration, status, dataBridge };
  };

  // ── Run replay (auto or step mode) ──
  const runReplay = async (mode) => {
    if (!hops || hops.length === 0) return;
    abortRef.current = false;
    setReplayMode(mode);
    setCompletedSteps([]);
    setCurrentStepIdx(0);
    setRerunResults(null);
    setActiveStepTab({});

    const stepList = buildStepList();
    const attestCache = {};
    const results = [];

    for (let i = 0; i < stepList.length; i++) {
      if (abortRef.current) break;
      setCurrentStepIdx(i);

      // In step mode, wait for user to click "Next Step" (except for the first step)
      if (mode === 'step' && i > 0) {
        await new Promise(resolve => { stepGateRef.current = { resolve }; });
        if (abortRef.current) break;
      }

      const result = await executeStep(stepList[i], attestCache);
      results.push(result);
      setCompletedSteps([...results]);

      // If gateway denied, mark remaining steps as skipped
      if (result.step.type === 'gateway' && result.status === 'deny') {
        for (let j = i + 1; j < stepList.length; j++) {
          results.push({ step: stepList[j], request: null, response: null, logs: [{ ts: new Date().toISOString(), msg: `Skipped — upstream gateway denied at step ${i + 1}` }], error: null, duration: 0, status: 'blocked', dataBridge: null });
        }
        setCompletedSteps([...results]);
        break;
      }

      // In auto mode, add delay between steps for animation
      if (mode === 'auto' && i < stepList.length - 1) {
        await new Promise(r => setTimeout(r, 500));
      }
    }

    setCurrentStepIdx(-1);
    setReplayMode(results.length > 0 ? 'done' : null);

    // Also populate legacy rerunResults for the before/after comparison
    const legacyResults = [];
    for (let hi = 0; hi < hops.length; hi++) {
      const hopSteps = results.filter(r => r.step.hopIdx === hi);
      const gwStep = hopSteps.find(r => r.step.type === 'gateway');
      legacyResults.push({
        hop: hi,
        source: hops[hi].source_name || hops[hi].source,
        destination: hops[hi].destination_name || hops[hi].destination,
        verdict: gwStep?.response?.verdict || (gwStep?.status === 'blocked' ? 'blocked' : undefined),
        policy: gwStep?.response?.policy_name,
        enforcement: gwStep?.response?.enforcement_action,
        latency: gwStep?.response?.latency_ms,
        steps: hopSteps.map(r => ({
          title: r.step.title, status: r.status,
          subtitle: r.error || (r.response ? Object.entries(r.response).map(([k,v]) => `${k}: ${v}`).join(' | ') : ''),
          request: r.request, response: r.response,
        })),
      });
    }
    setRerunResults(legacyResults);
  };

  const advanceStep = () => { stepGateRef.current?.resolve(); };
  const switchToAuto = () => { setReplayMode('auto'); stepGateRef.current?.resolve(); };
  const stopReplay = () => { abortRef.current = true; stepGateRef.current?.resolve(); setReplayMode(null); setCompletedSteps([]); setCurrentStepIdx(-1); setRerunResults(null); setActiveStepTab({}); };
  const resetReplay = () => { setReplayMode(null); setCompletedSteps([]); setCurrentStepIdx(-1); setRerunResults(null); setActiveStepTab({}); };

  // Signal replay state to parent for layout changes
  const isReplayActive = replayMode === 'auto' || replayMode === 'step' || replayMode === 'done';
  useEffect(() => { onReplayActive?.(isReplayActive); }, [isReplayActive, onReplayActive]);

  // Legacy rerunChain (kept for the "Re-run Chain" button)
  const rerunChain = () => runReplay('auto');

  if (!hops) return (
    <div className="flex-1 flex items-center justify-center text-nhi-faint">
      <div className="text-center"><Layers className="w-10 h-10 mx-auto mb-3 opacity-20" /><div className="text-sm">Select a trace to view</div></div>
    </div>
  );

  const allAllow = hops.every(h => h.verdict === 'allow' || h.verdict === 'granted');
  const traceId = hops[0]?.trace_id;
  const isEnforcement = traceId?.endsWith('-enforce');
  const PHASE_CFG = [
    { label: 'BASELINE', color: '#10b981', desc: 'Baseline traffic flowing with static credential' },
    { label: 'AUDIT',    color: '#f59e0b', desc: 'Audit: static credential violation detected' },
    { label: 'ENFORCE',  color: '#ef4444', desc: 'Enforce: static credential rejected' },
  ];
  const hop = hops[Math.min(selectedHop, hops.length - 1)];
  const hopVc = hop ? verdictFor(hop.verdict) : null;
  const isDeny = hop?.verdict === 'deny' || hop?.verdict === 'denied';
  const phase = isEnforcement ? (PHASE_CFG[selectedHop] || PHASE_CFG[PHASE_CFG.length - 1]) : null;

  // Enforcement diff strip: compare current phase vs previous phase
  const enforcementDiffStrip = (() => {
    if (!isEnforcement || selectedHop <= 0) return null;
    const cur = hops[selectedHop];
    const prev = hops[selectedHop - 1];
    if (!cur || !prev) return null;
    const fields = [
      { key: 'verdict', label: 'verdict', fmt: v => v === 'allow' || v === 'granted' ? 'allow' : v === 'deny' || v === 'denied' ? 'deny' : v || 'n/a' },
      { key: 'policy_name', label: 'policy', fmt: v => v || 'default-deny' },
      { key: 'enforcement_action', label: 'action', fmt: v => v || (cur.verdict === 'deny' || cur.verdict === 'denied' ? 'REJECT_REQUEST' : 'FORWARD_REQUEST') },
      { key: 'adapter_mode', label: 'mode', fmt: v => v || 'live' },
    ];
    const diffs = fields
      .map(f => ({ ...f, oldVal: f.fmt(prev[f.key]), newVal: f.fmt(cur[f.key]) }))
      .filter(d => d.oldVal !== d.newVal);
    if (diffs.length === 0) return null;
    const prevPhase = PHASE_CFG[selectedHop - 1] || PHASE_CFG[0];
    return (
      <div className="flex items-center gap-2 mb-2 px-2.5 py-1.5 rounded-md" style={{ background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.25)', borderLeft: '3px solid #f59e0b' }}>
        <Zap className="w-3.5 h-3.5 flex-shrink-0" style={{ color: '#f59e0b' }} />
        <span className="text-[9px] font-bold flex-shrink-0" style={{ color: '#f59e0b' }}>vs {prevPhase.label}:</span>
        <div className="flex items-center gap-3 flex-wrap min-w-0">
          {diffs.map((d, i) => {
            const newColor = d.key === 'verdict' ? (d.newVal === 'allow' ? '#10b981' : '#ef4444') : '#f59e0b';
            return (
              <span key={i} className="text-[9px] flex items-center gap-1">
                <span className="text-nhi-dim font-medium">{d.label}:</span>
                <span className="line-through" style={{ color: 'var(--text-faint)' }}>{d.oldVal.substring(0, 20)}</span>
                <span style={{ color: 'var(--text-faint)' }}>→</span>
                <span className="font-bold" style={{ color: newColor }}>{d.newVal.substring(0, 20)}</span>
              </span>
            );
          })}
        </div>
      </div>
    );
  })();

  // Build chain nodes with proper hop-to-edge mapping
  // Each chain edge (chain[j] → chain[j+1]) maps to chainEdgeMap[j] = hop index
  const chain = []; const chainEdgeMap = [];
  for (let hi = 0; hi < hops.length; hi++) {
    const h = hops[hi];
    const src = h.source_name || h.source;
    const dst = h.destination_name || h.destination;
    if (chain.length === 0) {
      chain.push({ name: src });
    } else if (chain[chain.length - 1].name !== src) {
      // Gap: prev destination != this source. Show as a return/transition edge (no hop data)
      chain.push({ name: src });
      chainEdgeMap.push(null); // gap edge has no hop
    }
    chain.push({ name: dst });
    chainEdgeMap.push(hi);
  }
  const rerunHop = rerunResults ? rerunResults[Math.min(selectedHop, rerunResults.length-1)] : null;
  const srcType = detectType(hop.source_name || hop.source);
  const dstType = detectType(hop.destination_name || hop.destination);

  // ── Header bar (shared between layouts) ──
  const headerBar = (
    <div className="flex items-center gap-2 mb-3">
      {isEnforcement && <Shield className="w-4 h-4" style={{ color: '#10b981' }} />}
      <span className="text-[13px] font-bold text-nhi-text">{isEnforcement ? 'Enforcement Timeline' : traceId ? 'Trace' : 'Decision'}</span>
      {traceId && <span className="text-[8px] font-mono px-2 py-0.5 rounded border" style={{ color: '#8b5cf6', background: 'rgba(139,92,246,0.06)', borderColor: 'rgba(139,92,246,0.15)' }}>{traceId}</span>}
      <div className="flex-1" />
      {traceId && <span className="text-[8px] font-bold px-2 py-1 rounded" style={{ background: allAllow ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)', color: allAllow ? '#10b981' : '#ef4444' }}>{allAllow ? 'CHAIN PASS' : 'CHAIN FAIL'}</span>}
      <span className="text-[9px] text-nhi-dim">{isEnforcement ? `${hops.length} phases` : `${hops.length} hops`}{chainEdgeMap.includes(null) ? ` · ${chain.length} nodes` : ''}</span>
      {onNavigateGraph && hop && (
        <button onClick={() => onNavigateGraph(hop.source_name || hop.source)}
          className="text-[8px] font-bold px-2 py-1 rounded-md border text-blue-400 bg-blue-400/10 border-blue-400/20 hover:bg-blue-400/20 flex items-center gap-1">
          <ExternalLink className="w-2.5 h-2.5" /> Graph
        </button>
      )}
      {hops.length > 1 && !replayMode && (
            <div className="flex items-center gap-1 ml-1">
              <button onClick={() => runReplay('auto')}
                className="text-[8px] font-bold px-2 py-1 rounded-md border text-accent bg-accent/10 border-accent/30 hover:bg-accent/20 flex items-center gap-1">
                <Play className="w-2.5 h-2.5" /> Run All
              </button>
              <button onClick={() => runReplay('step')}
                className="text-[8px] font-bold px-2 py-1 rounded-md border text-purple-400 bg-purple-400/10 border-purple-400/30 hover:bg-purple-400/20 flex items-center gap-1">
                <SkipForward className="w-2.5 h-2.5" /> Step Through
              </button>
            </div>
          )}
          {replayMode === 'done' && (
            <>
              <button onClick={resetReplay}
                className="text-[8px] font-bold px-2 py-1 rounded-md border text-accent bg-accent/10 border-accent/30 hover:bg-accent/20 flex items-center gap-1 ml-1">
                <RotateCcw className="w-2.5 h-2.5" /> Re-run
              </button>
              <button onClick={resetReplay}
                className="text-[8px] font-bold px-2 py-1 rounded-md border text-nhi-dim bg-surface-3 border-[var(--border)] hover:bg-surface-2 flex items-center gap-1 ml-1"
                title="Close replay and return to event list">
                <X className="w-2.5 h-2.5" /> Close
              </button>
            </>
          )}
          {(replayMode === 'step' || replayMode === 'auto') && (
            <button onClick={stopReplay}
              className="text-[8px] font-bold px-2 py-1 rounded-md border text-red-400 bg-red-400/10 border-red-400/30 hover:bg-red-400/20 flex items-center gap-1 ml-1">
              <Square className="w-2.5 h-2.5" /> Stop
            </button>
          )}
          {traceId && !replayMode && (
            <button onClick={fetchAuditReplay} disabled={auditReplayLoading}
              className={`text-[8px] font-bold px-2 py-1 rounded-md border flex items-center gap-1 ml-1 ${auditReplay && !auditReplay.error ? 'text-amber-400 bg-amber-400/15 border-amber-400/30' : 'text-slate-400 bg-slate-400/10 border-slate-400/20 hover:bg-slate-400/20'}`}>
              {auditReplayLoading ? <Loader className="w-2.5 h-2.5 animate-spin" /> : <FileText className="w-2.5 h-2.5" />}
              {auditReplay && !auditReplay.error ? 'Close Replay' : 'Audit Replay'}
            </button>
          )}
          {auditReplay && !auditReplay.error && (
            <button onClick={() => generatePDF(auditReplay)}
              className="text-[8px] font-bold px-2 py-1 rounded-md border text-emerald-400 bg-emerald-400/10 border-emerald-400/30 hover:bg-emerald-400/20 flex items-center gap-1">
              <Download className="w-2.5 h-2.5" /> Export PDF
            </button>
          )}
    </div>
  );

  // ── Stepper panel (extracted for 2-pane layout) ──
  const stepperPanel = (() => {
    if (!(replayMode === 'auto' || replayMode === 'step' || replayMode === 'done') || completedSteps.length === 0) return null;
    const stepList = buildStepList();
    return (
      <div className="rounded-lg border overflow-hidden h-full flex flex-col" style={{ borderColor: 'rgba(124,111,240,0.25)', background: 'rgba(124,111,240,0.03)' }}>
        <div className="px-3 py-2 flex items-center gap-2 flex-shrink-0" style={{ background: 'rgba(124,111,240,0.06)', borderBottom: '1px solid rgba(124,111,240,0.12)' }}>
          <RefreshCw className="w-3 h-3 text-accent" />
          <span className="text-[10px] font-bold text-accent">RE-RUN CHAIN</span>
          <span className="text-[8px] text-nhi-dim">{completedSteps.length} / {stepList.length} steps</span>
          <div className="flex-1" />
          {replayMode === 'step' && currentStepIdx >= 0 && (
            <div className="flex items-center gap-1">
              <button onClick={advanceStep}
                className="text-[8px] font-bold px-2 py-1 rounded-md border text-purple-400 bg-purple-400/10 border-purple-400/30 hover:bg-purple-400/20 flex items-center gap-1">
                <SkipForward className="w-2.5 h-2.5" /> Next Step
              </button>
              <button onClick={switchToAuto}
                className="text-[8px] font-bold px-2 py-0.5 rounded-md border text-accent bg-accent/10 border-accent/20 hover:bg-accent/20 flex items-center gap-1">
                <FastForward className="w-2.5 h-2.5" /> Run Remaining
              </button>
            </div>
          )}
          {replayMode === 'done' && (
            <>
              <span className="text-[8px] font-bold px-2 py-0.5 rounded text-emerald-400 bg-emerald-400/10">COMPLETE</span>
              <button onClick={resetReplay} className="text-nhi-faint hover:text-nhi-text p-0.5 rounded hover:bg-surface-3 transition-colors" title="Close replay">
                <X className="w-3 h-3" />
              </button>
            </>
          )}
          {(replayMode === 'step' || replayMode === 'auto') && (
            <button onClick={stopReplay} className="text-nhi-faint hover:text-red-400 p-0.5 rounded hover:bg-red-400/10 transition-colors" title="Cancel and close">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        <div className="px-3 py-2 flex-1 overflow-y-auto">
          {stepList.map((sd, si) => {
            const result = completedSteps[si];
            const isActive = si === currentStepIdx && (replayMode === 'auto' || replayMode === 'step');
            const isCompleted = !!result && si !== currentStepIdx;
            const isPending = !result && si !== currentStepIdx;
            const stepColor = result ? (result.status === 'pass' ? '#10b981' : result.status === 'fail' ? '#ef4444' : result.status === 'deny' ? '#ef4444' : result.status === 'blocked' ? '#64748b' : result.status === 'skip' ? '#f59e0b' : '#7c6ff0') : isActive ? '#7c6ff0' : '#64748b';
            const stepIcon = result ? (result.status === 'pass' ? '✓' : result.status === 'fail' || result.status === 'deny' ? '✗' : result.status === 'blocked' ? '—' : result.status === 'skip' ? '!' : '✓') : isActive ? '●' : '○';
            const tabKey = activeStepTab[si] || 'response';

            return (
              <div key={si} className="flex gap-2.5">
                <div className="flex flex-col items-center flex-shrink-0" style={{ width: 22 }}>
                  <div style={{
                    width: 20, height: 20, borderRadius: '50%',
                    background: isActive ? `${stepColor}30` : `${stepColor}15`,
                    border: `2px solid ${isActive ? stepColor : stepColor + '50'}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, fontWeight: 700, color: stepColor,
                    boxShadow: isActive ? `0 0 8px ${stepColor}40` : 'none',
                  }}>{isActive ? <Loader className="w-2.5 h-2.5 animate-spin" /> : stepIcon}</div>
                  {si < stepList.length - 1 && (
                    <div style={{ width: 2, flex: 1, minHeight: 8, background: `${stepColor}25`, marginTop: 2, marginBottom: 2 }} />
                  )}
                </div>
                <div className="flex-1 min-w-0 pb-2">
                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                    <span className={`text-[10px] font-semibold ${isPending ? 'text-nhi-faint' : 'text-nhi-text'}`}>{sd.title}</span>
                    {result && (
                      <>
                        <span className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{ background: `${stepColor}15`, color: stepColor }}>
                          {result.status === 'pass' ? 'PASS' : result.status === 'fail' ? 'FAIL' : result.status === 'deny' ? 'DENY' : result.status === 'blocked' ? 'BLOCKED' : result.status === 'skip' ? 'SKIP' : 'DONE'}
                        </span>
                        <span className="text-[8px] text-nhi-faint">{result.duration}ms</span>
                      </>
                    )}
                    {isActive && <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-accent/15 text-accent animate-pulse">RUNNING</span>}
                    {isPending && <span className="text-[7px] text-nhi-ghost">pending</span>}
                  </div>
                  {(isCompleted || (isActive && result)) && result && (
                    <div className="mt-1">
                      <div className="flex gap-0.5 mb-1">
                        {['request', 'response', 'logs'].map(tab => (
                          <button key={tab} onClick={() => setActiveStepTab(p => ({ ...p, [si]: tab }))}
                            className={`text-[7px] font-bold px-2 py-0.5 rounded ${tabKey === tab ? 'bg-accent/15 text-accent' : 'text-nhi-faint hover:text-nhi-dim'}`}>
                            {tab.charAt(0).toUpperCase() + tab.slice(1)}
                          </button>
                        ))}
                      </div>
                      <div className="rounded p-2" style={{ background: 'var(--surface-1)', border: '1px solid var(--border)' }}>
                        {tabKey === 'request' && result.request ? (
                          <div className="font-mono text-[8px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                            <div className="text-cyan-400 mb-1">{result.request.method || 'POST'} {result.request.url}</div>
                            {result.request.body && (
                              <pre className="text-nhi-dim whitespace-pre-wrap">{typeof result.request.body === 'string' ? result.request.body : JSON.stringify(result.request.body, null, 2)}</pre>
                            )}
                          </div>
                        ) : tabKey === 'request' ? (
                          <div className="text-[8px] text-nhi-ghost">No request data</div>
                        ) : null}
                        {tabKey === 'response' && result.response ? (
                          <div className="font-mono text-[8px] leading-relaxed">
                            {Object.entries(result.response).map(([k, v], x) => (
                              <div key={x} style={{ color: k === 'verdict' ? (v === 'allow' ? '#10b981' : '#ef4444') : k === 'trust_level' ? '#f59e0b' : 'var(--text-secondary)' }}>
                                <span className="text-nhi-faint">{k}: </span>{String(v)}
                              </div>
                            ))}
                          </div>
                        ) : tabKey === 'response' ? (
                          <div className="text-[8px] text-nhi-ghost">{result.error || 'No response data'}</div>
                        ) : null}
                        {tabKey === 'logs' && (
                          <div className="font-mono text-[8px] leading-relaxed space-y-0.5">
                            {result.logs.map((l, x) => (
                              <div key={x}><span className="text-nhi-ghost">{new Date(l.ts).toLocaleTimeString()}</span> <span className={l.msg.startsWith('ERROR') ? 'text-red-400' : 'text-nhi-dim'}>{l.msg}</span></div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                  {result?.dataBridge && si < stepList.length - 1 && (
                    <div className="mt-1 text-[8px] text-accent/70 flex items-center gap-1">
                      <span>↓</span> <span className="font-mono">{result.dataBridge}</span>
                    </div>
                  )}
                  {result?.error && (
                    <div className="mt-1 text-[8px] text-red-400 flex items-center gap-2">
                      <span>{result.error}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  })();

  // ═══════ TWO-PANE LAYOUT when replay is active ═══════
  if (isReplayActive && stepperPanel) {
    return (
      <div className="flex h-full">
        {/* Left pane: Stepper */}
        <div className="w-[420px] flex-shrink-0 flex flex-col overflow-hidden p-3" style={{ borderRight: '1px solid var(--border)' }}>
          {stepperPanel}
        </div>
        {/* Right pane: Header + Branch Timeline + Hop Detail */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="p-3 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface-2)' }}>
            {headerBar}
            {/* Conditional: enforcement horizontal phases vs flat chain */}
            {isEnforcement && hops.length >= 2 ? (
              <div className="flex items-center justify-center gap-1 overflow-x-auto pb-2 pt-1">
                {/* Source node */}
                <div className="flex flex-col items-center gap-1 flex-shrink-0">
                  <div style={{
                    width: 40, height: 40, borderRadius: '50%',
                    background: 'var(--surface-3)', border: '1.5px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: srcType.color }}>{srcType.abbr}</span>
                  </div>
                  <div style={{ fontSize: 8, fontWeight: 600, color: 'var(--text-secondary)', maxWidth: 72, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>
                    {(hops[0]?.source_name || hops[0]?.source || '').replace(/^wid-dev-/, '').substring(0, 16)}
                  </div>
                </div>
                {/* Phase nodes */}
                {hops.map((h, idx) => {
                  const pCfg2 = PHASE_CFG[idx] || PHASE_CFG[PHASE_CFG.length - 1];
                  const isActive2 = idx === selectedHop;
                  const hVc2 = verdictFor(h.verdict);
                  const ACCENT2 = '#7c6ff0';
                  return (
                    <React.Fragment key={idx}>
                      {/* Edge arrow */}
                      <div className="flex items-center flex-shrink-0 mx-1" style={{ minWidth: 36, paddingTop: 4 }}>
                        <div style={{ height: 2, flex: 1, background: isActive2 ? pCfg2.color : `${pCfg2.color}50`, borderRadius: 1, boxShadow: isActive2 ? `0 0 6px ${pCfg2.color}40` : 'none' }} />
                        <div style={{ width: 0, height: 0, borderTop: '4px solid transparent', borderBottom: '4px solid transparent', borderLeft: `6px solid ${isActive2 ? pCfg2.color : pCfg2.color + '60'}`, flexShrink: 0 }} />
                      </div>
                      {/* Phase circle */}
                      <div onClick={() => handleHopClick(idx)}
                        className="flex flex-col items-center gap-1 cursor-pointer transition-all duration-200 flex-shrink-0"
                        style={{ position: 'relative', zIndex: isActive2 ? 10 : 1 }}>
                        <div style={{
                          width: isActive2 ? 48 : 40, height: isActive2 ? 48 : 40, borderRadius: '50%',
                          background: isActive2 ? ACCENT2 : `${pCfg2.color}15`,
                          border: isActive2 ? '2px solid #a78bfa' : `1.5px solid ${pCfg2.color}40`,
                          boxShadow: isActive2 ? `0 0 14px rgba(124,111,240,0.5)` : 'none',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          transition: 'all 0.2s ease',
                        }}>
                          <span style={{ fontSize: isActive2 ? 11 : 10, fontWeight: 700, color: isActive2 ? '#fff' : pCfg2.color }}>{pCfg2.label.substring(0, 3)}</span>
                        </div>
                        <div className="text-center" style={{ maxWidth: 80 }}>
                          <div style={{ fontSize: 8, fontWeight: 700, color: pCfg2.color, marginBottom: 1 }}>{pCfg2.label}</div>
                          <span className="font-bold px-1.5 py-0.5 rounded" style={{ background: `${hVc2.color}15`, color: hVc2.color, fontSize: 7 }}>
                            {h.verdict === 'allow' || h.verdict === 'granted' ? 'ALLOW' : h.adapter_mode === 'audit' ? 'WOULD_BLOCK' : 'DENY'}
                          </span>
                        </div>
                      </div>
                    </React.Fragment>
                  );
                })}
                {/* Destination node */}
                <div className="flex items-center flex-shrink-0 mx-1" style={{ paddingTop: 4 }}>
                  <div style={{ height: 2, width: 20, background: '#64748b40', borderRadius: 1 }} />
                  <div style={{ width: 0, height: 0, borderTop: '3px solid transparent', borderBottom: '3px solid transparent', borderLeft: '4px solid #64748b40' }} />
                </div>
                <div className="flex flex-col items-center gap-1 flex-shrink-0">
                  <div style={{
                    width: 40, height: 40, borderRadius: '50%',
                    background: 'var(--surface-3)', border: '1.5px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: dstType.color }}>{dstType.abbr}</span>
                  </div>
                  <div style={{ fontSize: 8, fontWeight: 600, color: 'var(--text-secondary)', maxWidth: 72, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>
                    {(hops[0]?.destination_name || hops[0]?.destination || '').replace(/^wid-dev-/, '').substring(0, 16)}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-1 overflow-x-auto pb-2 pt-1">
                {chain.map((node, ci) => {
                  const edgeHopIdx2 = ci < chainEdgeMap.length ? chainEdgeMap[ci] : null;
                  const hopIdx2 = edgeHopIdx2 !== null ? edgeHopIdx2 : (ci > 0 && chainEdgeMap[ci-1] !== null ? chainEdgeMap[ci-1] : null);
                  const isActive2 = hopIdx2 === selectedHop;
                  const nt2 = detectType(node.name);
                  const ACCENT2 = '#7c6ff0';
                  return (
                    <React.Fragment key={`${node.name}-${ci}`}>
                      <div onClick={() => hopIdx2 !== null && handleHopClick(hopIdx2)}
                        className="flex flex-col items-center gap-1 cursor-pointer transition-all duration-200 flex-shrink-0"
                        style={{ position: 'relative', zIndex: isActive2 ? 10 : 1 }}>
                        <div style={{
                          width: isActive2 ? 40 : 34, height: isActive2 ? 40 : 34, borderRadius: '50%',
                          background: isActive2 ? ACCENT2 : 'var(--surface-3)',
                          border: isActive2 ? '2px solid #a78bfa' : '1.5px solid var(--border)',
                          boxShadow: isActive2 ? '0 0 12px rgba(124,111,240,0.4)' : 'none',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                        }}>
                          <span style={{ fontSize: 8, fontWeight: 700, color: isActive2 ? '#fff' : nt2.color }}>{nt2.abbr}</span>
                        </div>
                        <div style={{ fontSize: 7, fontWeight: 600, color: isActive2 ? '#eceaf4' : 'var(--text-faint)', maxWidth: 56, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>
                          {node.name.replace(/^wid-dev-/, '').substring(0, 14)}
                        </div>
                      </div>
                      {ci < chain.length - 1 && (
                        <div className="flex items-center flex-shrink-0 mx-0.5" style={{ paddingTop: 4 }}>
                          <div style={{ height: 2, width: 20, background: '#64748b40', borderRadius: 1 }} />
                          <div style={{ width: 0, height: 0, borderTop: '3px solid transparent', borderBottom: '3px solid transparent', borderLeft: '4px solid #64748b40' }} />
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            )}
          </div>
          {/* Hop detail (scrollable) — compact summary + collapsible sections */}
          {hop && (
            <div className="flex-1 overflow-auto p-3">
              {/* Compact summary row */}
              <div className="flex items-center gap-2 mb-2 px-2.5 py-2 rounded-lg" style={{
                background: phase ? `${phase.color}06` : 'var(--surface-2)',
                border: `1px solid ${phase ? `${phase.color}20` : 'var(--border)'}`,
              }}>
                {phase && (
                  <span className="text-[8px] font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: `${phase.color}18`, color: phase.color }}>{phase.label}</span>
                )}
                {!phase && hops.length > 1 && (
                  <span className="text-[8px] font-bold text-nhi-faint flex-shrink-0">Hop {hop.hop_index ?? selectedHop}</span>
                )}
                <TypeBadge name={hop.source_name || hop.source} size="sm" />
                <span className="text-[10px] font-bold text-nhi-text font-mono truncate max-w-[100px]">{(hop.source_name || hop.source).replace(/^wid-dev-/, '')}</span>
                <ArrowRight className="w-3 h-3 flex-shrink-0" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />
                <TypeBadge name={hop.destination_name || hop.destination} size="sm" />
                <span className={`text-[10px] font-bold text-nhi-text font-mono truncate max-w-[100px] ${isDeny ? 'opacity-35' : ''}`}>{(hop.destination_name || hop.destination).replace(/^wid-dev-/, '')}</span>
                <div className="flex-1" />
                <span className="text-[7px] font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: hopVc.color + '18', color: hopVc.color }}>
                  {phase ? (hop.verdict === 'allow' || hop.verdict === 'granted' ? 'ALLOW' : hop.adapter_mode === 'audit' ? 'WOULD_BLOCK' : 'DENY') : hopVc.label}
                </span>
                <span className="text-[8px] font-mono text-nhi-faint truncate max-w-[100px] flex-shrink-0">{hop.policy_name || 'default-deny'}</span>
                <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-surface-3 text-nhi-dim flex-shrink-0">{hop.enforcement_action || (isDeny ? 'REJECT' : 'FORWARD')}</span>
                <span className="text-[8px] text-nhi-faint flex-shrink-0">{hop.latency_ms || 0}ms</span>
              </div>

              {enforcementDiffStrip}

              {/* Request & Response (expanded) */}
              <CollapsibleSection
                title="Request & Response"
                icon={<Activity className="w-3 h-3" style={{ color: '#06b6d4' }} />}
                accentColor="#06b6d4"
                defaultExpanded={true}
                summaryText={`${hop.method || 'POST'} /api/v1/gateway/evaluate → HTTP ${isDeny ? '403' : '200'} ${hopVc.label}`}
              >
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg border p-2.5" style={{ borderColor: 'rgba(6,182,212,0.15)', background: 'rgba(6,182,212,0.03)' }}>
                    <div className="flex items-center gap-1.5 mb-2">
                      <ArrowRight className="w-3 h-3" style={{ color: '#06b6d4' }} />
                      <span className="text-[8px] font-bold uppercase" style={{ color: '#06b6d4' }}>Request</span>
                      <span className="text-[7px] font-mono text-nhi-faint ml-auto">POST</span>
                    </div>
                    <div className="rounded bg-surface-1 border p-2 font-mono text-[8px] leading-[1.7]" style={{ borderColor: 'var(--border)' }}>
                      <div><span className="text-nhi-faint">{'{'}</span></div>
                      {[
                        ['source', hop.source_name || hop.source],
                        ['destination', hop.destination_name || hop.destination],
                        ['method', hop.method || 'POST'],
                        ['path', hop.path_pattern || '/api/v1/credentials/fetch'],
                        ['wid_token', hop.token_context ? '(WID-TOKEN attached)' : 'null'],
                      ].map(([k,v],i) => (
                        <div key={i} className="pl-2">
                          <span className="text-cyan-400">"{k}"</span><span className="text-nhi-faint">: </span>
                          <span className={k === 'wid_token' && v.includes('attached') ? 'text-purple-400' : 'text-amber-300'}>"{v}"</span>
                          <span className="text-nhi-faint">,</span>
                        </div>
                      ))}
                      <div className="pl-2"><span className="text-cyan-400">"headers"</span><span className="text-nhi-faint">: {'{'}</span></div>
                      <div className="pl-4"><span className="text-nhi-dim">"X-WID-Source": </span><span className="text-amber-300">"{hop.source_name || hop.source}"</span><span className="text-nhi-faint">,</span></div>
                      <div className="pl-4"><span className="text-nhi-dim">"X-WID-Destination": </span><span className="text-amber-300">"{hop.destination_name || hop.destination}"</span></div>
                      <div className="pl-2"><span className="text-nhi-faint">{'}'}</span></div>
                      <div><span className="text-nhi-faint">{'}'}</span></div>
                    </div>
                  </div>
                  <div className="rounded-lg border p-2.5" style={{ borderColor: isDeny ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', background: isDeny ? 'rgba(239,68,68,0.03)' : 'rgba(16,185,129,0.03)' }}>
                    <div className="flex items-center gap-1.5 mb-2">
                      <ArrowRight className="w-3 h-3 rotate-180" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />
                      <span className="text-[8px] font-bold uppercase" style={{ color: isDeny ? '#ef4444' : '#10b981' }}>Response</span>
                      <span className="text-[7px] font-bold px-1 py-0.5 rounded ml-auto" style={{ background: isDeny ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)', color: isDeny ? '#ef4444' : '#10b981' }}>
                        HTTP {isDeny ? '403' : '200'}
                      </span>
                    </div>
                    <div className="rounded bg-surface-1 border p-2 font-mono text-[8px] leading-[1.7]" style={{ borderColor: 'var(--border)' }}>
                      <div><span className="text-nhi-faint">{'{'}</span></div>
                      {[
                        ['decision_id', hop.decision_id || `gw-${hop.id || 'n/a'}`],
                        ['verdict', hop.verdict],
                        ['allowed', hop.verdict === 'allow' || hop.verdict === 'granted' ? 'true' : 'false'],
                        ['enforcement', hop.enforcement_action || (isDeny ? 'REJECT_REQUEST' : 'FORWARD_REQUEST')],
                        ['policy_name', hop.policy_name || 'default-deny'],
                        ['latency_ms', String(hop.latency_ms || 0)],
                      ].map(([k,v],i) => (
                        <div key={i} className="pl-2">
                          <span className="text-cyan-400">"{k}"</span><span className="text-nhi-faint">: </span>
                          <span className={
                            k === 'verdict' ? (v === 'allow' || v === 'granted' ? 'text-emerald-400' : 'text-red-400') :
                            k === 'allowed' ? (v === 'true' ? 'text-emerald-400' : 'text-red-400') :
                            k === 'enforcement' ? (v === 'FORWARD_REQUEST' ? 'text-emerald-400' : 'text-red-400') :
                            'text-amber-300'
                          }>{k === 'latency_ms' || k === 'allowed' ? v : `"${v}"`}</span>
                          <span className="text-nhi-faint">,</span>
                        </div>
                      ))}
                      <div className="pl-2"><span className="text-cyan-400">"source"</span><span className="text-nhi-faint">: {'{'} </span><span className="text-nhi-muted">name: "{hop.source_name||hop.source}" </span><span className="text-nhi-faint">{'}'}</span><span className="text-nhi-faint">,</span></div>
                      <div className="pl-2"><span className="text-cyan-400">"destination"</span><span className="text-nhi-faint">: {'{'} </span><span className="text-nhi-muted">name: "{hop.destination_name||hop.destination}" </span><span className="text-nhi-faint">{'}'}</span></div>
                      {hop.token_context && (() => {
                        const tc2 = typeof hop.token_context === 'string' ? (() => { try { return JSON.parse(hop.token_context); } catch { return null; } })() : hop.token_context;
                        return tc2 ? (
                          <>
                            <div className="pl-2"><span className="text-cyan-400">"token_validation"</span><span className="text-nhi-faint">: {'{'}</span></div>
                            <div className="pl-4"><span className="text-nhi-dim">"valid": </span><span className="text-emerald-400">true</span><span className="text-nhi-faint">,</span></div>
                            <div className="pl-4"><span className="text-nhi-dim">"trust_level": </span><span className="text-amber-300">"{tc2.trust_level}"</span></div>
                            <div className="pl-2"><span className="text-nhi-faint">{'}'}</span></div>
                          </>
                        ) : null;
                      })()}
                      <div><span className="text-nhi-faint">{'}'}</span></div>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3 mt-2 text-[8px] text-nhi-faint">
                  <span>Time: {hop.created_at ? new Date(hop.created_at).toLocaleString() : 'n/a'}</span>
                  <span>Hop: {hop.hop_index != null ? `${hop.hop_index+1} of ${hop.total_hops||hops.length}` : 'Single'}</span>
                  {hop.trace_id && <span>Trace: {hop.trace_id}</span>}
                  <span className="ml-auto">{hop.latency_ms || 0}ms</span>
                </div>
              </CollapsibleSection>

              {/* Policy Decision (collapsed) */}
              <CollapsibleSection
                title="Policy Decision"
                icon={<Shield className="w-3 h-3" style={{ color: hopVc.color }} />}
                accentColor={hopVc.color}
                summaryText={`${hop.policy_name || 'default-deny'} → ${hopVc.label} (${hop.enforcement_action || (isDeny ? 'REJECT_REQUEST' : 'FORWARD_REQUEST')})`}
              >
                <div className="rounded-lg border p-3" style={{ borderColor: hopVc.border, background: hopVc.bg }}>
                  <div className="text-[8px] font-bold text-nhi-dim uppercase mb-1">Matched Policy</div>
                  <div className="text-[11px] font-bold text-nhi-text">{hop.policy_name || 'Default deny (zero-trust)'}</div>
                  <div className="text-[9px] mt-1" style={{ color: hopVc.color }}>{isDeny ? 'Request explicitly denied' : 'Request explicitly allowed'}</div>
                </div>
              </CollapsibleSection>

              {/* Gateway Log (collapsed) */}
              <CollapsibleSection
                title="Gateway Log"
                icon={<Shield className="w-3 h-3" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />}
                accentColor={isDeny ? '#ef4444' : '#10b981'}
                summaryText={`${isDeny ? 'Rejected' : 'Forwarded'} ${hop.method || 'POST'} → HTTP ${isDeny ? '403' : '200'}`}
              >
                <div className="rounded bg-surface-1 border p-2.5 font-mono text-[9px] leading-relaxed" style={{ borderColor: 'var(--border)', color: 'var(--text-secondary)' }}>
                  {hop.enforcement_detail || `Hop ${hop.hop_index ?? selectedHop}: Edge gateway ${isDeny ? 'rejected' : 'forwarded'} ${hop.method || 'POST'} from ${hop.source_name||hop.source} to ${hop.destination_name||hop.destination}. ${isDeny ? 'No allow policy matches (default deny).' : `Policy: ${hop.policy_name || 'default-allow'}.`} Returned HTTP ${isDeny ? '403' : '200'}.`}
                </div>
              </CollapsibleSection>

              {/* Attestation + WID Token (collapsed) */}
              {(() => {
                const srcName2 = hop.source_name || hop.source;
                const isUser2 = srcType.abbr === 'USR';
                const spiffeId2 = hop.source_principal || (isUser2 ? `user://${srcName2}` : `spiffe://wid-platform/workload/${srcName2}`);
                const tc2 = hop.token_context ? (typeof hop.token_context === 'string' ? (() => { try { return JSON.parse(hop.token_context); } catch { return null; } })() : hop.token_context) : null;
                return (
                  <>
                    <CollapsibleSection
                      title="Attestation"
                      icon={<Shield className="w-3 h-3" style={{ color: isUser2 ? '#64748b' : '#10b981' }} />}
                      accentColor={isUser2 ? '#64748b' : '#10b981'}
                      summaryText={isUser2 ? `User: ${srcName2}` : `${srcType.type} | trust: ${tc2?.trust_level || 'medium'} | attested`}
                    >
                      {isUser2 ? (
                        <div className="text-[9px] text-nhi-dim leading-relaxed">
                          <span className="font-mono text-nhi-text">{srcName2}</span> is a human user. Users authenticate via session/SSO — workload attestation is not applicable.
                        </div>
                      ) : (
                        <div className="space-y-1">
                          {[
                            ['Identity (SPIFFE)', spiffeId2],
                            ['Workload Type', srcType.type + (hop.source_type ? ` (${hop.source_type})` : '')],
                            ['Attestation Method', tc2?.attestation_method || hop.verification_method || 'abac-multi-signal'],
                            ['Trust Level', tc2?.trust_level || 'medium'],
                            ['Verified', 'Yes — cryptographic attestation passed'],
                            ['AI Agent', srcType.abbr === 'AGT' ? 'Yes — A2A agent workload' : 'No'],
                            ['Environment', hop.environment || 'gcp-cloud-run'],
                          ].map(([label, value], j) => (
                            <div key={j} className="flex items-start gap-2 text-[9px]">
                              <span className="text-nhi-faint flex-shrink-0 w-[120px] font-medium">{label}</span>
                              <span className={`font-mono break-all ${label.includes('SPIFFE') ? 'text-cyan-400' : label === 'Trust Level' ? 'text-amber-400 font-bold' : label === 'AI Agent' && value.startsWith('Yes') ? 'text-purple-400' : 'text-nhi-text'}`}>{value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </CollapsibleSection>
                    <CollapsibleSection
                      title="WID Token"
                      icon={<Shield className="w-3 h-3" style={{ color: isUser2 ? '#64748b' : '#8b5cf6' }} />}
                      accentColor={isUser2 ? '#64748b' : '#8b5cf6'}
                      summaryText={isUser2 ? 'No WID token (user identity)' : `${spiffeId2.substring(0, 40)}... | TTL: ${tc2?.trust_level === 'cryptographic' ? '3600' : tc2?.trust_level === 'high' ? '1800' : '900'}s`}
                    >
                      {isUser2 ? (
                        <div className="text-[9px] text-nhi-dim leading-relaxed">Users use session tokens, not WID tokens.</div>
                      ) : (
                        <div className="space-y-1">
                          {[
                            ['SPIFFE ID (sub)', spiffeId2],
                            ['Token Type', 'WID-TOKEN'],
                            ['Algorithm', 'HS256 (HMAC-SHA256)'],
                            ['Issuer (iss)', 'wid-platform://wid-platform.local'],
                            ['Audience (aud)', 'wid-gateway://wid-platform.local'],
                            ['Trust Level', tc2?.trust_level || 'medium'],
                            ['TTL', (tc2?.trust_level === 'cryptographic' ? '3600' : tc2?.trust_level === 'high' ? '1800' : '900') + 's (based on trust level)'],
                            ['Validation', tc2?.valid ? 'Signature verified + expiry checked + claims validated' : 'Token eligible — issued on attestation, validated per request'],
                            ...(tc2?.attestation_method ? [['Attestation in Token', tc2.attestation_method]] : []),
                          ].map(([label, value], j) => (
                            <div key={j} className="flex items-start gap-2 text-[9px]">
                              <span className="text-nhi-faint flex-shrink-0 w-[120px] font-medium">{label}</span>
                              <span className={`font-mono break-all ${label.includes('SPIFFE') ? 'text-cyan-400' : label === 'Trust Level' ? 'text-amber-400 font-bold' : label === 'Validation' && value.startsWith('Signature') ? 'text-emerald-400' : 'text-nhi-text'}`}>{value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </CollapsibleSection>
                  </>
                );
              })()}
            </div>
          )}
        </div>
      </div>
    );
  }

  // ═══════ DEFAULT SINGLE-COLUMN LAYOUT ═══════
  return (
    <div className="flex flex-col h-full">
      {/* Top: chain flow */}
      <div className="p-4 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface-2)' }}>
        {headerBar}
        {/* Conditional: compact enforcement phases vs flat chain */}
        {isEnforcement && hops.length >= 2 ? (
          <div className="flex items-center justify-center gap-1 overflow-x-auto pb-2 pt-1">
            {/* Source node */}
            <div className="flex flex-col items-center gap-1 flex-shrink-0">
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'var(--surface-3)', border: '1.5px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <span style={{ fontSize: 9, fontWeight: 700, color: srcType.color }}>{srcType.abbr}</span>
              </div>
              <div style={{ fontSize: 8, fontWeight: 600, color: 'var(--text-secondary)', maxWidth: 64, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>
                {(hops[0]?.source_name || hops[0]?.source || '').replace(/^wid-dev-/, '').substring(0, 14)}
              </div>
            </div>
            {/* Phase nodes */}
            {hops.map((h, idx) => {
              const pCfg = PHASE_CFG[idx] || PHASE_CFG[PHASE_CFG.length - 1];
              const isActive = idx === selectedHop;
              const hVc = verdictFor(h.verdict);
              const ACCENT = '#7c6ff0';
              return (
                <React.Fragment key={idx}>
                  {/* Edge arrow */}
                  <div className="flex items-center flex-shrink-0 mx-1" style={{ minWidth: 30, paddingTop: 4 }}>
                    <div style={{ height: 2, flex: 1, background: isActive ? pCfg.color : `${pCfg.color}50`, borderRadius: 1 }} />
                    <div style={{ width: 0, height: 0, borderTop: '4px solid transparent', borderBottom: '4px solid transparent', borderLeft: `6px solid ${isActive ? pCfg.color : pCfg.color + '60'}`, flexShrink: 0 }} />
                  </div>
                  {/* Phase circle */}
                  <div onClick={() => handleHopClick(idx)}
                    className="flex flex-col items-center gap-1 cursor-pointer transition-all duration-200 flex-shrink-0"
                    style={{ position: 'relative', zIndex: isActive ? 10 : 1 }}>
                    <div style={{
                      width: isActive ? 44 : 36, height: isActive ? 44 : 36, borderRadius: '50%',
                      background: isActive ? ACCENT : `${pCfg.color}15`,
                      border: isActive ? '2px solid #a78bfa' : `1.5px solid ${pCfg.color}40`,
                      boxShadow: isActive ? `0 0 12px rgba(124,111,240,0.4)` : 'none',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      transition: 'all 0.2s ease',
                    }}>
                      <span style={{ fontSize: isActive ? 10 : 9, fontWeight: 700, color: isActive ? '#fff' : pCfg.color }}>{pCfg.label.substring(0, 3)}</span>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 8, fontWeight: 700, color: pCfg.color, marginBottom: 1 }}>{pCfg.label}</div>
                      <span className="font-bold px-1 py-0.5 rounded" style={{ background: `${hVc.color}15`, color: hVc.color, fontSize: 7 }}>
                        {h.verdict === 'allow' || h.verdict === 'granted' ? 'ALLOW' : h.adapter_mode === 'audit' ? 'WOULD_BLOCK' : 'DENY'}
                      </span>
                    </div>
                  </div>
                </React.Fragment>
              );
            })}
            {/* Destination node */}
            <div className="flex items-center flex-shrink-0 mx-1" style={{ paddingTop: 4 }}>
              <div style={{ height: 2, width: 16, background: '#64748b40', borderRadius: 1 }} />
              <div style={{ width: 0, height: 0, borderTop: '3px solid transparent', borderBottom: '3px solid transparent', borderLeft: '4px solid #64748b40' }} />
            </div>
            <div className="flex flex-col items-center gap-1 flex-shrink-0">
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'var(--surface-3)', border: '1.5px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <span style={{ fontSize: 9, fontWeight: 700, color: dstType.color }}>{dstType.abbr}</span>
              </div>
              <div style={{ fontSize: 8, fontWeight: 600, color: 'var(--text-secondary)', maxWidth: 64, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }}>
                {(hops[0]?.destination_name || hops[0]?.destination || '').replace(/^wid-dev-/, '').substring(0, 14)}
              </div>
            </div>
          </div>
        ) : (
        <div className="flex items-center gap-1 overflow-x-auto pb-2 pt-1">
          {chain.map((node, i) => {
            const edgeHopIdx = i < chainEdgeMap.length ? chainEdgeMap[i] : null;
            const hopIdx = edgeHopIdx !== null ? edgeHopIdx : (i > 0 && chainEdgeMap[i-1] !== null ? chainEdgeMap[i-1] : null);
            const isActive = hopIdx === selectedHop;
            const edgeData = edgeHopIdx !== null ? hops[edgeHopIdx] : null;
            const edgeAllow = !edgeData || edgeData.verdict === 'allow' || edgeData.verdict === 'granted';
            const isGapEdge = i < chainEdgeMap.length && chainEdgeMap[i] === null;
            const prevDenied = i > 0 && chainEdgeMap[i-1] !== null && hops[chainEdgeMap[i-1]] && (hops[chainEdgeMap[i-1]].verdict === 'deny' || hops[chainEdgeMap[i-1]].verdict === 'denied');
            const nt = detectType(node.name);
            const ACCENT = '#7c6ff0';
            return (
              <React.Fragment key={`${node.name}-${i}`}>
                <div onClick={() => hopIdx !== null && handleHopClick(hopIdx)}
                  className={`flex flex-col items-center gap-1 cursor-pointer transition-all duration-200 flex-shrink-0 ${prevDenied ? 'opacity-30' : ''}`}
                  style={{ position: 'relative', zIndex: isActive ? 10 : 1 }}>
                  {/* Node circle — always accent purple when active */}
                  <div style={{
                    width: isActive ? 52 : 44,
                    height: isActive ? 52 : 44,
                    borderRadius: '50%',
                    background: isActive ? ACCENT : 'var(--surface-3)',
                    border: isActive ? `2px solid #a78bfa` : '1.5px solid var(--border)',
                    boxShadow: isActive ? `0 0 16px rgba(124,111,240,0.5), 0 0 32px rgba(124,111,240,0.2)` : 'none',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    transition: 'all 0.2s ease',
                  }}>
                    <span className="font-bold" style={{
                      fontSize: isActive ? 11 : 10,
                      color: isActive ? '#fff' : nt.color,
                      letterSpacing: '0.5px',
                    }}>{nt.abbr}</span>
                  </div>
                  {/* Node name */}
                  <div className="text-center" style={{ maxWidth: 72 }}>
                    <div style={{
                      fontSize: 9,
                      fontWeight: isActive ? 700 : 600,
                      color: isActive ? '#eceaf4' : 'var(--text-secondary)',
                      lineHeight: 1.2,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}>{node.name.replace(/^wid-dev-/,'').substring(0, 18)}</div>
                    <div style={{
                      fontSize: 7,
                      fontWeight: 600,
                      color: isActive ? 'rgba(167,139,250,0.9)' : 'var(--text-faint)',
                      marginTop: 1,
                    }}>{nt.type}</div>
                  </div>
                  {/* Active indicator dot */}
                  {isActive && (
                    <div style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: ACCENT,
                      boxShadow: '0 0 8px #7c6ff080',
                      marginTop: -2,
                    }} />
                  )}
                </div>
                {/* Edge arrow */}
                {i < chain.length - 1 && (() => {
                  const edgeIsActive = edgeHopIdx === selectedHop;
                  const phaseEdge = isEnforcement && edgeHopIdx !== null ? PHASE_CFG[edgeHopIdx] : null;
                  const edgeColor = phaseEdge ? phaseEdge.color : isGapEdge ? '#a78bfa' : edgeAllow ? '#10b981' : '#ef4444';
                  const edgeLabel = phaseEdge ? phaseEdge.label : isGapEdge ? 'RETURN' : edgeData?.verdict?.toUpperCase() || '';
                  return (
                    <div className="flex flex-col items-center flex-shrink-0 mx-1" style={{ minWidth: 36, paddingTop: 8 }}>
                      {/* Verdict / phase label */}
                      <span style={{
                        fontSize: 7,
                        fontWeight: 700,
                        color: edgeColor,
                        opacity: edgeIsActive ? 1 : 0.7,
                        marginBottom: 2,
                        letterSpacing: '0.3px',
                      }}>{edgeLabel}</span>
                      {/* Line + arrow */}
                      <div style={{ position: 'relative', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <div style={{
                          height: 2,
                          flex: 1,
                          background: edgeIsActive ? edgeColor : `${edgeColor}50`,
                          borderRadius: 1,
                          boxShadow: edgeIsActive ? `0 0 6px ${edgeColor}40` : 'none',
                        }} />
                        <div style={{
                          width: 0, height: 0,
                          borderTop: '4px solid transparent',
                          borderBottom: '4px solid transparent',
                          borderLeft: `6px solid ${edgeIsActive ? edgeColor : edgeColor + '60'}`,
                          flexShrink: 0,
                        }} />
                      </div>
                    </div>
                  );
                })()}
              </React.Fragment>
            );
          })}
        </div>
        )}
      </div>

      {/* Audit Replay Panel */}
      {auditReplay && !auditReplay.error && (
        <div className="flex-shrink-0 border-b overflow-auto" style={{ borderColor: 'rgba(245,158,11,0.2)', background: 'rgba(245,158,11,0.03)', maxHeight: '50%' }}>
          <div className="px-4 py-3">
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-amber-400" />
              <span className="text-[11px] font-bold text-amber-400">AUDIT REPLAY — DETERMINISTIC DECISION RECORD</span>
              <span className="text-[8px] font-mono text-nhi-faint ml-auto">{auditReplay.generated_at || new Date().toISOString()}</span>
            </div>
            {/* Replay metadata */}
            <div className="grid grid-cols-4 gap-2 mb-3">
              {[
                ['Trace ID', auditReplay.trace_id || traceId],
                ['Origin', auditReplay.origin || 'N/A'],
                ['Final Verdict', (auditReplay.final_verdict || 'N/A').toUpperCase()],
                ['Chain Authorized', auditReplay.chain_authorized ? 'YES' : 'NO'],
              ].map(([label, value], idx) => (
                <div key={idx} className="rounded-lg px-2.5 py-1.5" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
                  <div className="text-[7px] font-bold uppercase text-nhi-faint">{label}</div>
                  <div className={`text-[10px] font-bold font-mono truncate ${
                    label === 'Final Verdict' ? (value === 'ALLOW' || value === 'GRANTED' ? 'text-emerald-400' : 'text-red-400') :
                    label === 'Chain Authorized' ? (value === 'YES' ? 'text-emerald-400' : 'text-red-400') :
                    'text-nhi-text'
                  }`}>{value}</div>
                </div>
              ))}
            </div>
            {/* Hops */}
            {(auditReplay.hops || []).map((rh, ri) => (
              <div key={ri} className="rounded-lg border mb-2 overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                <div className="px-3 py-2 flex items-center gap-2" style={{ background: 'var(--surface-2)' }}>
                  <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-amber-400/15 text-amber-400">HOP {ri + 1}</span>
                  <TypeBadge name={rh.source || ''} size="sm" />
                  <span className="text-[9px] font-bold text-nhi-text font-mono">{(rh.source || '').replace(/^wid-dev-/, '').substring(0, 20)}</span>
                  <ArrowRight className="w-3 h-3 text-nhi-faint" />
                  <TypeBadge name={rh.destination || ''} size="sm" />
                  <span className="text-[9px] font-bold text-nhi-text font-mono">{(rh.destination || '').replace(/^wid-dev-/, '').substring(0, 20)}</span>
                  <div className="flex-1" />
                  <span className={`text-[7px] font-bold px-1.5 py-0.5 rounded ${
                    rh.verdict === 'allow' || rh.verdict === 'granted' ? 'bg-emerald-400/15 text-emerald-400' : 'bg-red-400/15 text-red-400'
                  }`}>{(rh.verdict || 'N/A').toUpperCase()}</span>
                  <span className="text-[8px] font-mono text-nhi-faint">{rh.policy_name || rh.policy?.name || 'default-deny'}</span>
                  <span className="text-[8px] text-nhi-faint">{rh.latency_ms || 0}ms</span>
                </div>
                {(rh.policy_snapshot || rh.policy?.snapshot) && (() => {
                  const snap = rh.policy_snapshot || rh.policy?.snapshot;
                  const vHash = rh.policy_version_hash || rh.policy?.version;
                  return (
                  <div className="px-3 py-2" style={{ background: 'var(--surface-1)', borderTop: '1px solid var(--border)' }}>
                    <div className="text-[7px] font-bold uppercase text-nhi-faint mb-1">Policy Snapshot</div>
                    <div className="grid grid-cols-3 gap-2 text-[8px]">
                      <div><span className="text-nhi-faint">Version: </span><span className="text-nhi-text font-mono">{vHash || 'N/A'}</span></div>
                      <div><span className="text-nhi-faint">Effect: </span><span className="text-nhi-text">{snap.effect || 'deny'}</span></div>
                      <div><span className="text-nhi-faint">Mode: </span><span className="text-nhi-text">{snap.enforcement_mode || 'enforce'}</span></div>
                    </div>
                    {snap.conditions?.length > 0 && (
                      <div className="mt-1">
                        <span className="text-[7px] font-bold text-nhi-faint">Conditions: </span>
                        {snap.conditions.map((c, ci) => (
                          <span key={ci} className="text-[8px] font-mono text-cyan-400 mr-2">{c.field} {c.operator} {c.value || ''}</span>
                        ))}
                      </div>
                    )}
                    {snap.actions?.length > 0 && (
                      <div className="mt-0.5">
                        <span className="text-[7px] font-bold text-nhi-faint">Actions: </span>
                        {snap.actions.map((a, ai) => (
                          <span key={ai} className="text-[8px] font-mono text-amber-300 mr-2">{a.type || a}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  );
                })()}
                {rh.token_context && (
                  <div className="px-3 py-1.5 flex items-center gap-3 text-[8px]" style={{ background: 'var(--surface-1)', borderTop: '1px solid var(--border)' }}>
                    <span className="text-nhi-faint">Trust:</span>
                    <span className="text-amber-400 font-bold">{(typeof rh.token_context === 'string' ? JSON.parse(rh.token_context) : rh.token_context)?.trust_level || 'N/A'}</span>
                    <span className="text-nhi-faint">Attestation:</span>
                    <span className="text-nhi-text">{(typeof rh.token_context === 'string' ? JSON.parse(rh.token_context) : rh.token_context)?.attestation_method || 'N/A'}</span>
                  </div>
                )}
              </div>
            ))}
            {/* Chain integrity assessment */}
            <div className="rounded-lg px-3 py-2 mt-2" style={{
              background: auditReplay.chain_authorized !== false ? 'rgba(16,185,129,0.06)' : 'rgba(239,68,68,0.06)',
              border: `1px solid ${auditReplay.chain_authorized !== false ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}>
              <div className="flex items-center gap-2">
                {auditReplay.chain_authorized !== false
                  ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  : <XCircle className="w-3.5 h-3.5 text-red-400" />}
                <span className={`text-[9px] font-bold ${auditReplay.chain_authorized !== false ? 'text-emerald-400' : 'text-red-400'}`}>
                  {auditReplay.chain_authorized !== false ? 'ALL HOPS AUTHORIZED — Chain integrity verified' : 'CHAIN VIOLATION — One or more hops unauthorized'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
      {auditReplay?.error && (
        <div className="flex-shrink-0 px-4 py-2 border-b" style={{ borderColor: 'rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.05)' }}>
          <div className="flex items-center gap-2 text-[9px] text-red-400">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span className="font-bold">Audit Replay Error:</span>
            <span>{auditReplay.error}</span>
          </div>
        </div>
      )}

      {/* Bottom: selected hop detail */}
      {hop && (
        <div className="flex-1 overflow-auto p-4">
          {/* Compact summary row — replaces 3 separate cards */}
          <div className="flex items-center gap-2 mb-2 px-2.5 py-2 rounded-lg" style={{
            background: phase ? `${phase.color}06` : 'var(--surface-2)',
            border: `1px solid ${phase ? `${phase.color}20` : 'var(--border)'}`,
          }}>
            {/* Phase label (enforcement only) */}
            {phase && (
              <span className="text-[8px] font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: `${phase.color}18`, color: phase.color }}>{phase.label}</span>
            )}
            {/* Hop label (normal traces) */}
            {!phase && hops.length > 1 && (
              <span className="text-[8px] font-bold text-nhi-faint flex-shrink-0">Hop {hop.hop_index ?? selectedHop}</span>
            )}
            {/* Source → Dest */}
            <TypeBadge name={hop.source_name || hop.source} size="sm" />
            <span className="text-[10px] font-bold text-nhi-text font-mono truncate max-w-[100px]">{(hop.source_name || hop.source).replace(/^wid-dev-/, '')}</span>
            <ArrowRight className="w-3 h-3 flex-shrink-0" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />
            <TypeBadge name={hop.destination_name || hop.destination} size="sm" />
            <span className={`text-[10px] font-bold text-nhi-text font-mono truncate max-w-[100px] ${isDeny ? 'opacity-35' : ''}`}>{(hop.destination_name || hop.destination).replace(/^wid-dev-/, '')}</span>
            <div className="flex-1" />
            {/* Verdict badge */}
            <span className="text-[7px] font-bold px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: hopVc.color + '18', color: hopVc.color }}>
              {phase ? (hop.verdict === 'allow' || hop.verdict === 'granted' ? 'ALLOW' : hop.adapter_mode === 'audit' ? 'WOULD_BLOCK' : 'DENY') : hopVc.label}
            </span>
            {/* Policy name */}
            <span className="text-[8px] font-mono text-nhi-faint truncate max-w-[100px] flex-shrink-0">{hop.policy_name || 'default-deny'}</span>
            {/* Enforcement action */}
            <span className="text-[7px] font-bold px-1.5 py-0.5 rounded bg-surface-3 text-nhi-dim flex-shrink-0">{hop.enforcement_action || (isDeny ? 'REJECT' : 'FORWARD')}</span>
            {/* Latency */}
            <span className="text-[8px] text-nhi-faint flex-shrink-0">{hop.latency_ms || 0}ms</span>
          </div>

          {enforcementDiffStrip}

          {/* ── Request & Response (expanded by default, side-by-side) ── */}
          <CollapsibleSection
            title="Request & Response"
            icon={<Activity className="w-3 h-3" style={{ color: '#06b6d4' }} />}
            accentColor="#06b6d4"
            defaultExpanded={true}
            summaryText={`${hop.method || 'POST'} /api/v1/gateway/evaluate → HTTP ${isDeny ? '403' : '200'} ${hopVc.label}`}
          >
            <div className="grid grid-cols-2 gap-3">
              {/* Request */}
              <div className="rounded-lg border p-2.5" style={{ borderColor: 'rgba(6,182,212,0.15)', background: 'rgba(6,182,212,0.03)' }}>
                <div className="flex items-center gap-1.5 mb-2">
                  <ArrowRight className="w-3 h-3" style={{ color: '#06b6d4' }} />
                  <span className="text-[8px] font-bold uppercase" style={{ color: '#06b6d4' }}>Request</span>
                  <span className="text-[7px] font-mono text-nhi-faint ml-auto">POST</span>
                </div>
                <div className="rounded bg-surface-1 border p-2 font-mono text-[8px] leading-[1.7]" style={{ borderColor: 'var(--border)' }}>
                  <div><span className="text-nhi-faint">{'{'}</span></div>
                  {[
                    ['source', hop.source_name || hop.source],
                    ['destination', hop.destination_name || hop.destination],
                    ['method', hop.method || 'POST'],
                    ['path', hop.path_pattern || '/api/v1/credentials/fetch'],
                    ['wid_token', hop.token_context ? '(WID-TOKEN attached)' : 'null'],
                  ].map(([k,v],i) => (
                    <div key={i} className="pl-2">
                      <span className="text-cyan-400">"{k}"</span><span className="text-nhi-faint">: </span>
                      <span className={k === 'wid_token' && v.includes('attached') ? 'text-purple-400' : 'text-amber-300'}>"{v}"</span>
                      <span className="text-nhi-faint">,</span>
                    </div>
                  ))}
                  <div className="pl-2"><span className="text-cyan-400">"headers"</span><span className="text-nhi-faint">: {'{'}</span></div>
                  <div className="pl-4"><span className="text-nhi-dim">"X-WID-Source": </span><span className="text-amber-300">"{hop.source_name || hop.source}"</span><span className="text-nhi-faint">,</span></div>
                  <div className="pl-4"><span className="text-nhi-dim">"X-WID-Destination": </span><span className="text-amber-300">"{hop.destination_name || hop.destination}"</span></div>
                  <div className="pl-2"><span className="text-nhi-faint">{'}'}</span></div>
                  <div><span className="text-nhi-faint">{'}'}</span></div>
                </div>
              </div>

              {/* Response */}
              <div className="rounded-lg border p-2.5" style={{ borderColor: isDeny ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)', background: isDeny ? 'rgba(239,68,68,0.03)' : 'rgba(16,185,129,0.03)' }}>
                <div className="flex items-center gap-1.5 mb-2">
                  <ArrowRight className="w-3 h-3 rotate-180" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />
                  <span className="text-[8px] font-bold uppercase" style={{ color: isDeny ? '#ef4444' : '#10b981' }}>Response</span>
                  <span className="text-[7px] font-bold px-1 py-0.5 rounded ml-auto" style={{ background: isDeny ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)', color: isDeny ? '#ef4444' : '#10b981' }}>
                    HTTP {isDeny ? '403' : '200'}
                  </span>
                </div>
                <div className="rounded bg-surface-1 border p-2 font-mono text-[8px] leading-[1.7]" style={{ borderColor: 'var(--border)' }}>
                  <div><span className="text-nhi-faint">{'{'}</span></div>
                  {[
                    ['decision_id', hop.decision_id || `gw-${hop.id || 'n/a'}`],
                    ['verdict', hop.verdict],
                    ['allowed', hop.verdict === 'allow' || hop.verdict === 'granted' ? 'true' : 'false'],
                    ['enforcement', hop.enforcement_action || (isDeny ? 'REJECT_REQUEST' : 'FORWARD_REQUEST')],
                    ['policy_name', hop.policy_name || 'default-deny'],
                    ['latency_ms', String(hop.latency_ms || 0)],
                  ].map(([k,v],i) => (
                    <div key={i} className="pl-2">
                      <span className="text-cyan-400">"{k}"</span><span className="text-nhi-faint">: </span>
                      <span className={
                        k === 'verdict' ? (v === 'allow' || v === 'granted' ? 'text-emerald-400' : 'text-red-400') :
                        k === 'allowed' ? (v === 'true' ? 'text-emerald-400' : 'text-red-400') :
                        k === 'enforcement' ? (v === 'FORWARD_REQUEST' ? 'text-emerald-400' : 'text-red-400') :
                        'text-amber-300'
                      }>{k === 'latency_ms' || k === 'allowed' ? v : `"${v}"`}</span>
                      <span className="text-nhi-faint">,</span>
                    </div>
                  ))}
                  <div className="pl-2"><span className="text-cyan-400">"source"</span><span className="text-nhi-faint">: {'{'} </span><span className="text-nhi-muted">name: "{hop.source_name||hop.source}" </span><span className="text-nhi-faint">{'}'}</span><span className="text-nhi-faint">,</span></div>
                  <div className="pl-2"><span className="text-cyan-400">"destination"</span><span className="text-nhi-faint">: {'{'} </span><span className="text-nhi-muted">name: "{hop.destination_name||hop.destination}" </span><span className="text-nhi-faint">{'}'}</span></div>
                  {hop.token_context && (() => {
                    const tc2 = typeof hop.token_context === 'string' ? (() => { try { return JSON.parse(hop.token_context); } catch { return null; } })() : hop.token_context;
                    return tc2 ? (
                      <>
                        <div className="pl-2"><span className="text-cyan-400">"token_validation"</span><span className="text-nhi-faint">: {'{'}</span></div>
                        <div className="pl-4"><span className="text-nhi-dim">"valid": </span><span className="text-emerald-400">true</span><span className="text-nhi-faint">,</span></div>
                        <div className="pl-4"><span className="text-nhi-dim">"trust_level": </span><span className="text-amber-300">"{tc2.trust_level}"</span></div>
                        <div className="pl-2"><span className="text-nhi-faint">{'}'}</span></div>
                      </>
                    ) : null;
                  })()}
                  <div><span className="text-nhi-faint">{'}'}</span></div>
                </div>
              </div>
            </div>
            {/* Metadata row below both panels */}
            <div className="flex items-center gap-3 mt-2 text-[8px] text-nhi-faint">
              <span>Time: {hop.created_at ? new Date(hop.created_at).toLocaleString() : 'n/a'}</span>
              <span>Hop: {hop.hop_index != null ? `${hop.hop_index+1} of ${hop.total_hops||hops.length}` : 'Single'}</span>
              {hop.trace_id && <span>Trace: {hop.trace_id}</span>}
              <span className="ml-auto">{hop.latency_ms || 0}ms</span>
            </div>
          </CollapsibleSection>

          {/* ── Policy Decision (collapsed by default) ── */}
          <CollapsibleSection
            title="Policy Decision"
            icon={<Shield className="w-3 h-3" style={{ color: hopVc.color }} />}
            accentColor={hopVc.color}
            summaryText={`${hop.policy_name || 'default-deny'} → ${hopVc.label} (${hop.enforcement_action || (isDeny ? 'REJECT_REQUEST' : 'FORWARD_REQUEST')})`}
          >
            <div className="rounded-lg border p-3" style={{ borderColor: hopVc.border, background: hopVc.bg }}>
              <div className="text-[8px] font-bold text-nhi-dim uppercase mb-1">Matched Policy</div>
              <div className="text-[11px] font-bold text-nhi-text">{hop.policy_name || 'Default deny (zero-trust)'}</div>
              <div className="text-[9px] mt-1" style={{ color: hopVc.color }}>{isDeny ? 'Request explicitly denied' : 'Request explicitly allowed'}</div>
            </div>
          </CollapsibleSection>

          {/* ── Gateway Log (collapsed by default) ── */}
          <CollapsibleSection
            title="Gateway Log"
            icon={<Shield className="w-3 h-3" style={{ color: isDeny ? '#ef4444' : '#10b981' }} />}
            accentColor={isDeny ? '#ef4444' : '#10b981'}
            summaryText={`${isDeny ? 'Rejected' : 'Forwarded'} ${hop.method || 'POST'} → HTTP ${isDeny ? '403' : '200'}`}
          >
            <div className="rounded bg-surface-1 border p-2.5 font-mono text-[9px] leading-relaxed" style={{ borderColor: 'var(--border)', color: 'var(--text-secondary)' }}>
              {hop.enforcement_detail || `Hop ${hop.hop_index ?? selectedHop}: Edge gateway ${isDeny ? 'rejected' : 'forwarded'} ${hop.method || 'POST'} from ${hop.source_name||hop.source} to ${hop.destination_name||hop.destination}. ${isDeny ? 'No allow policy matches (default deny).' : `Policy: ${hop.policy_name || 'default-allow'}.`} Returned HTTP ${isDeny ? '403' : '200'}.`}
            </div>
          </CollapsibleSection>

          {/* ── Attestation + WID Token (collapsed by default) ── */}
          {(() => {
            const srcName = hop.source_name || hop.source;
            const isUser = srcType.abbr === 'USR';
            const spiffeId = hop.source_principal || (isUser ? `user://${srcName}` : `spiffe://wid-platform/workload/${srcName}`);
            const tc = hop.token_context ? (typeof hop.token_context === 'string' ? (() => { try { return JSON.parse(hop.token_context); } catch { return null; } })() : hop.token_context) : null;

            return (
              <>
                <CollapsibleSection
                  title="Attestation"
                  icon={<Shield className="w-3 h-3" style={{ color: isUser ? '#64748b' : '#10b981' }} />}
                  accentColor={isUser ? '#64748b' : '#10b981'}
                  summaryText={isUser ? `User: ${srcName}` : `${srcType.type} | trust: ${tc?.trust_level || 'medium'} | attested`}
                >
                  {isUser ? (
                    <div className="text-[9px] text-nhi-dim leading-relaxed">
                      <span className="font-mono text-nhi-text">{srcName}</span> is a human user. Users authenticate via session/SSO — workload attestation is not applicable. Identity verified through authentication layer.
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {[
                        ['Identity (SPIFFE)', spiffeId],
                        ['Workload Type', srcType.type + (hop.source_type ? ` (${hop.source_type})` : '')],
                        ['Attestation Method', tc?.attestation_method || hop.verification_method || 'abac-multi-signal'],
                        ['Trust Level', tc?.trust_level || 'medium'],
                        ['Verified', 'Yes — cryptographic attestation passed'],
                        ['AI Agent', srcType.abbr === 'AGT' ? 'Yes — A2A agent workload' : 'No'],
                        ['Environment', hop.environment || 'gcp-cloud-run'],
                      ].map(([label, value], j) => (
                        <div key={j} className="flex items-start gap-2 text-[9px]">
                          <span className="text-nhi-faint flex-shrink-0 w-[120px] font-medium">{label}</span>
                          <span className={`font-mono break-all ${label.includes('SPIFFE') ? 'text-cyan-400' : label === 'Trust Level' ? 'text-amber-400 font-bold' : label === 'AI Agent' && value.startsWith('Yes') ? 'text-purple-400' : 'text-nhi-text'}`}>{value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </CollapsibleSection>

                <CollapsibleSection
                  title="WID Token"
                  icon={<Shield className="w-3 h-3" style={{ color: isUser ? '#64748b' : '#8b5cf6' }} />}
                  accentColor={isUser ? '#64748b' : '#8b5cf6'}
                  summaryText={isUser ? 'No WID token (user identity)' : `${spiffeId.substring(0, 40)}... | TTL: ${tc?.trust_level === 'cryptographic' ? '3600' : tc?.trust_level === 'high' ? '1800' : '900'}s`}
                >
                  {isUser ? (
                    <div className="text-[9px] text-nhi-dim leading-relaxed">Users use session tokens, not WID tokens. The gateway identifies this as a user request and evaluates policy based on user identity.</div>
                  ) : (
                    <div className="space-y-1">
                      {[
                        ['SPIFFE ID (sub)', spiffeId],
                        ['Token Type', 'WID-TOKEN'],
                        ['Algorithm', 'HS256 (HMAC-SHA256)'],
                        ['Issuer (iss)', 'wid-platform://wid-platform.local'],
                        ['Audience (aud)', 'wid-gateway://wid-platform.local'],
                        ['Trust Level', tc?.trust_level || 'medium'],
                        ['TTL', (tc?.trust_level === 'cryptographic' ? '3600' : tc?.trust_level === 'high' ? '1800' : '900') + 's (based on trust level)'],
                        ['Validation', tc?.valid ? 'Signature verified + expiry checked + claims validated' : 'Token eligible — issued on attestation, validated per request'],
                        ...(tc?.attestation_method ? [['Attestation in Token', tc.attestation_method]] : []),
                      ].map(([label, value], j) => (
                        <div key={j} className="flex items-start gap-2 text-[9px]">
                          <span className="text-nhi-faint flex-shrink-0 w-[120px] font-medium">{label}</span>
                          <span className={`font-mono break-all ${label.includes('SPIFFE') ? 'text-cyan-400' : label === 'Trust Level' ? 'text-amber-400 font-bold' : label === 'Validation' && value.startsWith('Signature') ? 'text-emerald-400' : 'text-nhi-text'}`}>{value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </CollapsibleSection>
              </>
            );
          })()}

          {/* Re-run results — prominent before/after comparison */}
          {rerunResults && rerunResults.length > 0 && (
            <div className="mt-3 rounded-xl overflow-hidden" style={{ border: '2px solid rgba(124,111,240,0.3)', background: 'rgba(124,111,240,0.04)' }}>
              {/* Header */}
              <div className="px-4 py-3 flex items-center gap-3" style={{ background: 'rgba(124,111,240,0.08)', borderBottom: '1px solid rgba(124,111,240,0.15)' }}>
                <RefreshCw className="w-4 h-4 text-accent" />
                <span className="text-[12px] font-bold text-accent">Live Re-run Results</span>
                <div className="flex-1" />
                {(() => {
                  const origVerdict = hop?.verdict;
                  const newVerdict = rerunHop?.verdict;
                  const changed = origVerdict !== newVerdict;
                  return (
                    <div className="flex items-center gap-2">
                      {changed ? (
                        <span className="text-[9px] font-bold px-2.5 py-1 rounded-full" style={{ background: 'rgba(245,158,11,0.15)', color: '#f59e0b' }}>VERDICT CHANGED</span>
                      ) : (
                        <span className="text-[9px] font-bold px-2.5 py-1 rounded-full" style={{ background: 'rgba(100,116,139,0.12)', color: 'var(--text-faint)' }}>SAME RESULT</span>
                      )}
                    </div>
                  );
                })()}
                <button onClick={() => setRerunResults(null)} className="text-nhi-faint hover:text-nhi-text text-[9px] px-1.5">✕</button>
              </div>

              {/* Before vs After comparison */}
              <div className="px-4 py-3 grid grid-cols-2 gap-3" style={{ borderBottom: '1px solid rgba(124,111,240,0.1)' }}>
                <div className="rounded-lg p-3" style={{ background: 'var(--surface-1)', border: '1px solid var(--border)' }}>
                  <div className="text-[8px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-faint)' }}>Original Decision</div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[8px] font-bold px-2 py-0.5 rounded" style={{
                      background: (hop?.verdict === 'allow' || hop?.verdict === 'granted') ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                      color: (hop?.verdict === 'allow' || hop?.verdict === 'granted') ? '#10b981' : '#ef4444',
                    }}>{hop?.verdict?.toUpperCase()}</span>
                    <span className="text-[9px] text-nhi-dim font-mono">{hop?.policy_name || 'default-deny'}</span>
                  </div>
                  <div className="text-[8px] text-nhi-dim">{hop?.enforcement_action || (isDeny ? 'REJECT_REQUEST' : 'FORWARD_REQUEST')}</div>
                  <div className="text-[7px] text-nhi-faint mt-1">{hop?.created_at ? new Date(hop.created_at).toLocaleString() : ''}</div>
                </div>
                <div className="rounded-lg p-3" style={{
                  background: rerunHop?.verdict === 'allow' ? 'rgba(16,185,129,0.06)' : rerunHop?.verdict === 'deny' ? 'rgba(239,68,68,0.06)' : 'var(--surface-1)',
                  border: `1px solid ${rerunHop?.verdict === 'allow' ? 'rgba(16,185,129,0.2)' : rerunHop?.verdict === 'deny' ? 'rgba(239,68,68,0.2)' : 'var(--border)'}`,
                }}>
                  <div className="text-[8px] font-bold uppercase tracking-wider mb-2" style={{ color: '#7c6ff0' }}>Re-run (Now)</div>
                  {rerunHop ? (
                    <>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[8px] font-bold px-2 py-0.5 rounded" style={{
                          background: rerunHop.verdict === 'allow' ? 'rgba(16,185,129,0.15)' : rerunHop.verdict === 'deny' ? 'rgba(239,68,68,0.15)' : 'rgba(100,116,139,0.12)',
                          color: rerunHop.verdict === 'allow' ? '#10b981' : rerunHop.verdict === 'deny' ? '#ef4444' : 'var(--text-faint)',
                        }}>{rerunHop.verdict?.toUpperCase() || 'N/A'}</span>
                        <span className="text-[9px] text-nhi-dim font-mono">{rerunHop.policy || 'default-deny'}</span>
                      </div>
                      <div className="text-[8px] text-nhi-dim">{rerunHop.enforcement || ''}</div>
                      <div className="text-[7px] text-nhi-faint mt-1">Latency: {rerunHop.latency || 0}ms</div>
                    </>
                  ) : (
                    <div className="text-[9px] text-nhi-faint">Blocked by upstream hop</div>
                  )}
                </div>
              </div>

              {/* Step-by-step pipeline */}
              <div className="px-4 py-3">
                <div className="text-[9px] font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-faint)' }}>Pipeline Steps (Hop {selectedHop})</div>
                {(rerunHop?.steps || []).map((step, j) => {
                  const sp = step.status === 'pass'; const sf = step.status === 'fail' || step.status === 'deny';
                  const sw = step.status === 'warn' || step.status === 'skip'; const sb = step.status === 'blocked';
                  const stepColor = sp ? '#10b981' : sf ? '#ef4444' : sw ? '#f59e0b' : sb ? '#64748b' : '#7c6ff0';
                  return (
                    <div key={j} className="flex items-start gap-2.5 mb-2 last:mb-0">
                      {/* Step indicator */}
                      <div className="flex flex-col items-center flex-shrink-0" style={{ minWidth: 20 }}>
                        <div style={{
                          width: 20, height: 20, borderRadius: '50%',
                          background: `${stepColor}18`,
                          border: `1.5px solid ${stepColor}40`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 9, fontWeight: 700, color: stepColor,
                        }}>{sp ? '✓' : sf ? '✗' : sw ? '!' : sb ? '—' : j + 1}</div>
                        {j < (rerunHop?.steps || []).length - 1 && (
                          <div style={{ width: 1.5, height: 16, background: `${stepColor}25`, marginTop: 2 }} />
                        )}
                      </div>
                      {/* Step content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-[10px] font-semibold" style={{ color: 'var(--text-primary)' }}>{step.title}</span>
                          <span className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{
                            background: `${stepColor}15`, color: stepColor,
                          }}>{sp ? 'PASS' : sf ? 'FAIL' : sw ? 'WARN' : sb ? 'BLOCKED' : 'RUN'}</span>
                        </div>
                        <div className="text-[9px]" style={{ color: 'var(--text-tertiary)' }}>{step.subtitle}</div>
                        {(step.request || step.response) && (
                          <div className="grid grid-cols-2 gap-2 mt-1.5">
                            {step.request && (
                              <div className="rounded p-2" style={{ background: 'var(--surface-1)', border: '1px solid var(--border)' }}>
                                <div className="text-[7px] font-bold uppercase mb-1" style={{ color: '#06b6d4' }}>Request</div>
                                {Object.entries(step.request).map(([k, v], x) => (
                                  <div key={x} className="text-[8px] font-mono" style={{ color: 'var(--text-secondary)' }}>
                                    <span style={{ color: 'var(--text-faint)' }}>{k}: </span>{String(v)}
                                  </div>
                                ))}
                              </div>
                            )}
                            {step.response && (
                              <div className="rounded p-2" style={{ background: 'var(--surface-1)', border: '1px solid var(--border)' }}>
                                <div className="text-[7px] font-bold uppercase mb-1" style={{ color: stepColor }}>Response</div>
                                {Object.entries(step.response).map(([k, v], x) => (
                                  <div key={x} className="text-[8px] font-mono" style={{ color: k === 'verdict' ? (v === 'allow' ? '#10b981' : '#ef4444') : 'var(--text-secondary)' }}>
                                    <span style={{ color: 'var(--text-faint)' }}>{k}: </span>{String(v)}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Summary footer for all hops */}
              {rerunResults.length > 1 && (
                <div className="px-4 py-2.5 flex items-center gap-3 flex-wrap" style={{ background: 'rgba(124,111,240,0.06)', borderTop: '1px solid rgba(124,111,240,0.1)' }}>
                  <span className="text-[8px] font-bold uppercase" style={{ color: 'var(--text-faint)' }}>All hops:</span>
                  {rerunResults.map((rh, ri) => {
                    const v = rh.verdict;
                    const vColor = v === 'allow' ? '#10b981' : v === 'deny' ? '#ef4444' : v === 'blocked' ? '#64748b' : '#f59e0b';
                    return (
                      <button key={ri} onClick={() => handleHopClick(ri)}
                        className="flex items-center gap-1.5 px-2 py-1 rounded-md transition-all" style={{
                          background: ri === selectedHop ? `${vColor}18` : 'transparent',
                          border: ri === selectedHop ? `1px solid ${vColor}30` : '1px solid transparent',
                        }}>
                        <span className="text-[7px] font-bold" style={{ color: 'var(--text-secondary)' }}>Hop {ri}</span>
                        <span className="text-[7px] font-bold px-1 py-0.5 rounded" style={{ background: `${vColor}15`, color: vColor }}>{(v || '?').toUpperCase()}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ==================== TraceGroup ==================== */
function TraceGroup({ traceId, hops, selected, onSelect, isExpanded, onToggle, wlCtx, onNavigateGraph }) {
  if (!hops || hops.length === 0) return null;
  const allAllow = hops.every(h => h.verdict==='allow'||h.verdict==='granted');
  const chainVc = allAllow ? verdictFor('allow') : verdictFor('deny');
  const firstHop = hops[0];
  const isEnforce = traceId?.endsWith('-enforce');
  const chainNodes = [];
  for (const h of hops) {
    if (chainNodes.length===0||chainNodes[chainNodes.length-1]!==h.source_name) chainNodes.push(h.source_name);
    chainNodes.push(h.destination_name);
  }
  const uniqueChain = chainNodes.filter((n,i) => i===0||n!==chainNodes[i-1]);
  return (
    <div style={{ borderBottom:'1px solid var(--border)' }}>
      <div onClick={onToggle} className="px-3 py-2.5 cursor-pointer hover:bg-surface-3" style={{ background: isExpanded?'var(--surface-3)':undefined }}>
        <div className="flex items-center gap-1.5 mb-1">
          {isExpanded ? <ChevronDown className="w-3 h-3 text-nhi-faint flex-shrink-0"/> : <ChevronRight className="w-3 h-3 text-nhi-faint flex-shrink-0"/>}
          {isEnforce
            ? <Shield className="w-3 h-3 flex-shrink-0" style={{ color:'#10b981' }} />
            : <RouteIcon className="w-3 h-3 flex-shrink-0" style={{ color:chainVc.color }} />
          }
          <div className="flex items-center gap-0.5 min-w-0 flex-1 overflow-hidden">
            {isEnforce ? (
              <>
                <TypeBadge name={firstHop.source_name} />
                <span className="text-[9px] font-semibold text-nhi-text truncate max-w-[70px]">{firstHop.source_name}</span>
                <ArrowRight className="w-2.5 h-2.5 text-nhi-faint flex-shrink-0" />
                <TypeBadge name={firstHop.destination_name} />
                <span className="text-[9px] font-semibold text-nhi-text truncate max-w-[70px]">{firstHop.destination_name}</span>
              </>
            ) : uniqueChain.map((name,i) => (
              <React.Fragment key={`${name}-${i}`}>
                {i > 0 && <ArrowRight className="w-2.5 h-2.5 text-nhi-faint flex-shrink-0" />}
                <div className="flex items-center gap-1 flex-shrink-0"><TypeBadge name={name} /><span className="text-[9px] font-semibold text-nhi-text truncate max-w-[55px]">{name.replace(/^wid-dev-/,'')}</span></div>
              </React.Fragment>
            ))}
          </div>
          {wlCtx?.[firstHop.source_name] && <TrustPill level={wlCtx[firstHop.source_name].trust_level} />}
          <span className="text-[8px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ml-1" style={{ color:chainVc.color, background:chainVc.bg, borderColor:chainVc.border }}>{allAllow?'PASS':'FAIL'}</span>
        </div>
        <div className="flex gap-2 items-center text-[9px] text-nhi-faint ml-5">
          {isEnforce
            ? <span className="flex items-center gap-0.5"><Shield className="w-2.5 h-2.5" style={{ color:'#10b981' }} /> {hops.length} phases · enforce</span>
            : <>
                <span className="flex items-center gap-0.5"><GitBranch className="w-2.5 h-2.5" /> {hops.length} hops</span>
                <span>{hops.filter(h=>h.verdict==='allow'||h.verdict==='granted').length} allowed</span>
                <span>{hops.filter(h=>h.verdict==='deny'||h.verdict==='denied').length} denied</span>
              </>
          }
          {firstHop.policy_name && <span className="text-nhi-faint font-mono truncate max-w-[80px]">{firstHop.policy_name}</span>}
          <span className="ml-auto">{timeAgo(firstHop.created_at)}</span>
        </div>
      </div>
      {isExpanded && hops.map((d,i) => {
        const vc = verdictFor(d.verdict);
        const isSelected = selected===d.decision_id||selected===d.id?.toString();
        const phaseLabels = ['BASELINE', 'AUDIT', 'ENFORCE'];
        const phaseColors = ['#10b981', '#f59e0b', '#ef4444'];
        return (
          <div key={d.id||d.decision_id} onClick={() => onSelect(d.decision_id||d.id?.toString(), i)}
            className={`pl-8 pr-3 py-2 cursor-pointer transition-all ${isSelected?'bg-surface-3':'hover:bg-surface-3'}`}
            style={{ borderTop:'1px solid var(--border)', borderLeft: isSelected?`3px solid ${vc.color}`:'3px solid transparent' }}>
            <div className="flex items-center gap-1.5">
              {isEnforce
                ? <span className="text-[7px] font-bold flex-shrink-0 px-1 py-0.5 rounded" style={{ color: phaseColors[i] || '#64748b', background: (phaseColors[i] || '#64748b') + '15' }}>{phaseLabels[i] || `PHASE ${i}`}</span>
                : <span className="text-[8px] font-mono text-nhi-faint w-5 flex-shrink-0 text-right">{i}</span>
              }
              <TypeBadge name={d.source_name} /><span className="text-[10px] font-semibold text-nhi-text truncate max-w-[70px]">{d.source_name}</span>
              <ArrowRight className="w-2.5 h-2.5 text-nhi-faint flex-shrink-0" />
              <TypeBadge name={d.destination_name} /><span className="text-[10px] font-semibold text-nhi-text truncate max-w-[70px]">{d.destination_name}</span>
              <span className="text-[7px] font-bold px-1 py-0.5 rounded border flex-shrink-0 ml-auto" style={{ color:vc.color, background:vc.bg, borderColor:vc.border }}>{vc.label}</span>
            </div>
            {d.policy_name && <div className="text-[8px] text-nhi-faint font-mono ml-6 mt-0.5 truncate">{d.policy_name}</div>}
          </div>
        );
      })}
    </div>
  );
}

/* ==================== EventRow (enriched) ==================== */
function EventRow({ d, selected, onSelect, wlCtx, onNavigateGraph }) {
  const vc = verdictFor(d.verdict);
  const isSelected = selected===d.decision_id||selected===d.id?.toString();
  const srcCtx = wlCtx?.[d.source_name];
  const dstCtx = wlCtx?.[d.destination_name];
  // Risk tier: red if deny + low trust or shadow, amber if deny, green otherwise
  const isDeny = d.verdict === 'deny' || d.verdict === 'denied';
  const isHighRisk = isDeny && (srcCtx?.trust_level === 'none' || srcCtx?.trust_level === 'low' || srcCtx?.is_shadow);
  const riskColor = isHighRisk ? '#ef4444' : isDeny ? '#f59e0b' : 'transparent';
  return (
    <div onClick={() => onSelect(d.decision_id||d.id?.toString())}
      className={`px-3 py-2.5 cursor-pointer transition-all ${isSelected?'bg-surface-3':'bg-surface-2 hover:bg-surface-3'}`}
      style={{ borderBottom:'1px solid var(--border)', borderLeft: isSelected?`3px solid ${vc.color}`:`3px solid ${riskColor}` }}>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-nhi-text min-w-0">
          <TypeBadge name={d.source_name} />
          <span className="truncate max-w-[75px] cursor-pointer hover:underline" onClick={e => { e.stopPropagation(); onNavigateGraph?.(d.source_name); }}>{d.source_name?.replace(/^wid-dev-/,'')}</span>
          <ArrowRight className="w-3 h-3 text-nhi-faint flex-shrink-0" />
          <TypeBadge name={d.destination_name} />
          <span className="truncate max-w-[75px] cursor-pointer hover:underline" onClick={e => { e.stopPropagation(); onNavigateGraph?.(d.destination_name); }}>{d.destination_name?.replace(/^wid-dev-/,'')}</span>
        </div>
        <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full border flex-shrink-0 ml-1.5" style={{ color:vc.color, background:vc.bg, borderColor:vc.border }}>{vc.label}</span>
      </div>
      <div className="flex gap-1.5 items-center text-[8px] text-nhi-faint">
        <span className="font-semibold" style={{ color: d.method==='POST'?'#f59e0b':'#3b82f6' }}>{d.method}</span>
        <span className="font-mono truncate max-w-[80px]">{d.path_pattern}</span>
        {d.policy_name && <span className="truncate max-w-[80px] text-nhi-faint">{d.policy_name}</span>}
        {d.trace_id && <span className="flex items-center gap-0.5 text-purple-400"><RouteIcon className="w-2.5 h-2.5" /></span>}
        <div className="flex-1" />
        {/* Inline trust + risk context */}
        {srcCtx && <TrustPill level={srcCtx.trust_level} />}
        {srcCtx?.is_shadow && <span className="text-[5px] font-bold px-1 py-0.5 rounded bg-red-500/15 text-red-400">SHADOW</span>}
        {srcCtx?.is_dormant && <span className="text-[5px] font-bold px-1 py-0.5 rounded bg-amber-500/15 text-amber-400">DORMANT</span>}
        <span className="flex-shrink-0">{timeAgo(d.created_at)}</span>
      </div>
    </div>
  );
}

/* ==================== Main Page ==================== */
const AccessEvents = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  // Deep link params from graph inspector: ?workload=X&policy=P&since=Z&trace=T
  const graphWorkload = searchParams.get('workload') || '';
  const graphPolicy   = searchParams.get('policy')   || '';
  const graphSince    = searchParams.get('since')     || '';
  const graphTrace    = searchParams.get('trace')     || '';

  const [decisions, setDecisions] = useState([]);
  const [allDecisions, setAllDecisions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [workloadFilter, setWorkloadFilter] = useState(graphWorkload);
  const [policyFilter, setPolicyFilter] = useState(graphPolicy);
  const [searchText, setSearchText] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [timeRange, setTimeRange] = useState(graphSince ? 'custom' : '24h');
  const [sinceFilter, setSinceFilter] = useState(graphSince || '');
  const [selected, setSelected] = useState(null);
  const [selectedTraceId, setSelectedTraceId] = useState(null);
  const [selectedHopIndex, setSelectedHopIndex] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [viewMode, setViewMode] = useState('traces');
  const [expandedTraces, setExpandedTraces] = useState(new Set());
  const [replayExpanded, setReplayExpanded] = useState(false);
  const [stats, setStats] = useState(null);
  const [aiEvents, setAiEvents] = useState([]);
  const [aiStats, setAiStats] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const refreshTimer = useRef(null);
  const searchTimer = useRef(null);

  // Compute since timestamp from time range preset
  const effectiveSince = useMemo(() => {
    if (sinceFilter) return sinceFilter;
    const tr = TIME_RANGES.find(t => t.key === timeRange);
    if (tr) return new Date(Date.now() - tr.hours * 3600000).toISOString();
    return '';
  }, [timeRange, sinceFilter]);

  // Fetch aggregate stats (for sparklines, top denied, enforcement funnel, workload context)
  const fetchStats = useCallback(async () => {
    try {
      const tr = TIME_RANGES.find(t => t.key === timeRange);
      const hours = tr?.hours || 24;
      const res = await fetch(`/api/v1/access/decisions/stats?hours=${hours}`).then(r => r.ok ? r.json() : null).catch(() => null);
      if (res) setStats(res);
    } catch (e) { /* non-critical */ }
  }, [timeRange]);

  // Fetch AI telemetry events
  const fetchAI = useCallback(async () => {
    if (viewMode !== 'ai') return;
    setAiLoading(true);
    try {
      const params = new URLSearchParams({ limit: '200' });
      if (workloadFilter) params.set('source', workloadFilter);
      const [evRes, stRes] = await Promise.all([
        fetch(`/api/v1/ai/requests?${params}`).then(r => r.ok ? r.json() : { events: [] }).catch(() => ({ events: [] })),
        fetch('/api/v1/ai/requests/stats?hours=24').then(r => r.ok ? r.json() : null).catch(() => null),
      ]);
      setAiEvents(evRes.events || []);
      if (stRes) setAiStats(stRes);
    } catch { /* non-critical */ }
    finally { setAiLoading(false); }
  }, [viewMode, workloadFilter]);

  useEffect(() => { fetchAI(); }, [fetchAI]);

  const fetchData = useCallback(async () => {
    try {
      // Fetch 1: All decisions for global counters (no workload/search filter)
      const allParams = new URLSearchParams({ limit: '500' });
      if (effectiveSince) allParams.set('since', effectiveSince);
      const allRes = await fetch(`/api/v1/access/decisions/live?${allParams}`).then(r=>r.ok?r.json():{decisions:[]}).catch(()=>({decisions:[]}));
      const allDecs = allRes.decisions||[];
      setAllDecisions(allDecs);

      // Fetch 2: Filtered decisions for the list (server-side)
      const listParams = new URLSearchParams({ limit: '200' });
      if (workloadFilter) listParams.set('workload', workloadFilter);
      if (policyFilter) listParams.set('policy', policyFilter);
      if (searchText) listParams.set('search', searchText);
      if (effectiveSince) listParams.set('since', effectiveSince);
      const listRes = await fetch(`/api/v1/access/decisions/live?${listParams}`).then(r=>r.ok?r.json():{decisions:[]}).catch(()=>({decisions:[]}));
      setDecisions(listRes.decisions||[]);
      setError(null);
    } catch(e) { setError(e.message); } finally { setLoading(false); }
  }, [workloadFilter, policyFilter, searchText, effectiveSince]);

  // Initial load + polling
  useEffect(() => {
    fetchData();
    fetchStats();
    if (autoRefresh) refreshTimer.current = setInterval(fetchData, 3000);
    return () => { if (refreshTimer.current) clearInterval(refreshTimer.current); };
  }, [fetchData, fetchStats, autoRefresh]);

  // Refresh stats less frequently (every 30s)
  useEffect(() => {
    const id = setInterval(fetchStats, 30000);
    return () => clearInterval(id);
  }, [fetchStats]);

  // Debounce search input
  const handleSearchInput = (val) => {
    setSearchInput(val);
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => setSearchText(val), 400);
  };

  // Auto-expand trace group when navigating from graph enforce flow
  useEffect(() => {
    if (!graphTrace) return;
    const hasTrace = decisions.some(d => d.trace_id === graphTrace);
    if (hasTrace) {
      setExpandedTraces(new Set([graphTrace]));
      setSelectedTraceId(graphTrace);
      setViewMode('traces');
    }
  }, [graphTrace, decisions]);

  // Verdict filter (client-side)
  const filtered = useMemo(() => {
    if (filter === 'allowed') return decisions.filter(d => d.verdict==='allow' || d.verdict==='granted');
    if (filter === 'denied')  return decisions.filter(d => d.verdict==='deny'  || d.verdict==='denied');
    return decisions;
  }, [decisions, filter]);

  const traceGroups = useMemo(() => {
    const groups = new Map(); const ungrouped = [];
    for (const d of filtered) { if (d.trace_id) { if (!groups.has(d.trace_id)) groups.set(d.trace_id, []); groups.get(d.trace_id).push(d); } else ungrouped.push(d); }
    for (const [,hops] of groups) hops.sort((a,b)=>(a.hop_index||0)-(b.hop_index||0));
    return { groups, ungrouped };
  }, [filtered]);

  const selectedDecision = decisions.find(d=>d.decision_id===selected||d.id?.toString()===selected);
  const selectedTraceHops = useMemo(() => {
    const tid = selectedTraceId || selectedDecision?.trace_id;
    if (!tid) return null;
    return decisions.filter(d=>d.trace_id===tid).sort((a,b)=>(a.hop_index||0)-(b.hop_index||0));
  }, [selectedDecision, selectedTraceId, decisions]);
  const effectiveDecision = selectedDecision || (selectedTraceHops && selectedTraceHops.length > 0 ? selectedTraceHops[0] : null);

  // Computed counters from allDecisions
  const counters = useMemo(() => {
    const c = { total: allDecisions.length, allowed: 0, denied: 0, auditDeny: 0 };
    for (const d of allDecisions) {
      if (d.verdict==='allow'||d.verdict==='granted') c.allowed++;
      else if (d.verdict==='deny'||d.verdict==='denied') c.denied++;
      else if (d.verdict==='audit-deny') c.auditDeny++;
    }
    return c;
  }, [allDecisions]);

  const lats = useMemo(() => {
    const arr = allDecisions.filter(d=>d.latency_ms>0).map(d=>d.latency_ms).sort((a,b)=>a-b);
    return { p50: arr.length ? arr[Math.floor(arr.length*0.5)] : 0, p95: arr.length ? arr[Math.floor(arr.length*0.95)] : 0 };
  }, [allDecisions]);

  // Sparkline data: prefer stats API hourly buckets, fall back to client-side bucketing
  const clientSparklines = useMemo(() => {
    if (!allDecisions.length) return { deny: [], allow: [], total: [] };
    // Bucket decisions into ~12 time slots across the visible range
    const sorted = [...allDecisions].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    const tMin = new Date(sorted[0].created_at).getTime();
    const tMax = new Date(sorted[sorted.length - 1].created_at).getTime();
    const span = Math.max(tMax - tMin, 60000); // min 1 minute
    const bucketCount = Math.min(12, Math.max(3, sorted.length));
    const bucketMs = span / bucketCount;
    const deny = new Array(bucketCount).fill(0);
    const allow = new Array(bucketCount).fill(0);
    const total = new Array(bucketCount).fill(0);
    for (const d of sorted) {
      const bi = Math.min(Math.floor((new Date(d.created_at).getTime() - tMin) / bucketMs), bucketCount - 1);
      total[bi]++;
      if (d.verdict === 'deny' || d.verdict === 'denied') deny[bi]++;
      else if (d.verdict === 'allow' || d.verdict === 'granted') allow[bi]++;
    }
    return { deny, allow, total };
  }, [allDecisions]);

  const denySparkline = useMemo(() => {
    const from_stats = (stats?.hourly || []).map(h => h.deny);
    return from_stats.length >= 2 ? from_stats : clientSparklines.deny;
  }, [stats, clientSparklines]);
  const allowSparkline = useMemo(() => {
    const from_stats = (stats?.hourly || []).map(h => h.allow);
    return from_stats.length >= 2 ? from_stats : clientSparklines.allow;
  }, [stats, clientSparklines]);
  const totalSparkline = useMemo(() => {
    const from_stats = (stats?.hourly || []).map(h => h.total);
    return from_stats.length >= 2 ? from_stats : clientSparklines.total;
  }, [stats, clientSparklines]);

  // Trend arrows: compare last half vs first half of sparkline
  const denyTrend = useMemo(() => {
    if (denySparkline.length < 4) return 0;
    const mid = Math.floor(denySparkline.length / 2);
    const first = denySparkline.slice(0, mid).reduce((a,b) => a+b, 0) / mid;
    const second = denySparkline.slice(mid).reduce((a,b) => a+b, 0) / (denySparkline.length - mid);
    if (first === 0) return second > 0 ? 1 : 0;
    return (second - first) / first;
  }, [denySparkline]);

  // Workload context: merge stats API data + derive from decision token_context
  const wlCtx = useMemo(() => {
    const ctx = { ...(stats?.workloadContext || {}) };
    // Enrich from decisions themselves (token_context has trust_level)
    for (const d of allDecisions) {
      if (d.source_name && !ctx[d.source_name]) {
        const tc = d.token_context && typeof d.token_context === 'object' ? d.token_context : null;
        ctx[d.source_name] = {
          trust_level: tc?.trust_level || 'none',
          type: d.source_type || 'service',
        };
      }
      if (d.destination_name && !ctx[d.destination_name]) {
        ctx[d.destination_name] = { trust_level: 'none', type: d.destination_type || 'service' };
      }
    }
    return ctx;
  }, [stats, allDecisions]);

  const topDenied = stats?.topDenied || [];

  // Enforcement funnel: prefer stats API, fall back to deriving from decisions
  const funnel = useMemo(() => {
    const sf = stats?.enforcementFunnel;
    if (sf && sf.total > 0) return sf;
    // Derive from adapter_mode in decisions
    const modes = { enforce: 0, audit: 0, simulate: 0 };
    const seen = new Set();
    for (const d of allDecisions) {
      const key = `${d.source_name}->${d.destination_name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const m = d.adapter_mode || 'audit';
      if (modes[m] !== undefined) modes[m]++;
    }
    const total = modes.enforce + modes.audit + modes.simulate;
    return { enforce: modes.enforce, audit: modes.audit, disabled: modes.simulate, total };
  }, [stats, allDecisions]);

  // Open violations: prefer stats API, fall back to denied decision count
  const openViolations = useMemo(() => {
    if (stats?.openViolations > 0) return stats.openViolations;
    return counters.denied;
  }, [stats, counters]);

  const toggleTrace = tid => setExpandedTraces(p => { const n=new Set(p); n.has(tid)?n.delete(tid):n.add(tid); return n; });
  const handleSelectDecision = (id) => { setSelected(id); setSelectedTraceId(null); setSelectedHopIndex(null); };
  const handleSelectHopInTrace = (id, traceId, hopIndex) => { setSelected(id); setSelectedTraceId(traceId); setSelectedHopIndex(hopIndex); };
  const navigateToGraph = (workloadName) => navigate(`/graph?focus=${encodeURIComponent(workloadName)}`);

  const clearAllFilters = () => {
    setWorkloadFilter(''); setPolicyFilter(''); setSearchInput(''); setSearchText('');
    setSearchParams({});
  };
  const hasActiveFilters = workloadFilter || policyFilter || searchText;

  return (
    <div className="flex flex-col h-[calc(100vh-7.5rem)] -m-7 -mt-0">

      {/* ═══════ TOP: Morning Triage Dashboard ═══════ */}
      {!replayExpanded && <div className="px-4 pt-3 pb-2" style={{ borderBottom: '1px solid var(--border)' }}>
        {/* Row 1: KPI cards with sparklines */}
        <div className="grid grid-cols-6 gap-2.5 mb-2.5">
          {/* Total Decisions */}
          <button onClick={() => setFilter('all')} className="nhi-card p-2.5 text-left hover:ring-1 hover:ring-accent/30 transition-all" style={{ cursor: 'pointer' }}>
            <div className="flex items-center justify-between mb-1">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              <Sparkline data={totalSparkline} color="#3b82f6" width={48} height={16} />
            </div>
            <div className="text-lg font-bold text-nhi-text font-mono leading-none">{counters.total}</div>
            <div className="text-[8px] text-nhi-faint mt-0.5">Total Decisions</div>
          </button>

          {/* Allowed */}
          <button onClick={() => setFilter('allowed')} className="nhi-card p-2.5 text-left hover:ring-1 hover:ring-emerald-400/30 transition-all" style={{ cursor: 'pointer' }}>
            <div className="flex items-center justify-between mb-1">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <Sparkline data={allowSparkline} color="#10b981" width={48} height={16} />
            </div>
            <div className="text-lg font-bold text-nhi-text font-mono leading-none">{counters.allowed}</div>
            <div className="text-[8px] text-nhi-faint mt-0.5">Allowed</div>
          </button>

          {/* Denied — with trend arrow */}
          <button onClick={() => setFilter('denied')} className="nhi-card p-2.5 text-left hover:ring-1 hover:ring-red-400/30 transition-all" style={{ cursor: 'pointer' }}>
            <div className="flex items-center justify-between mb-1">
              <ShieldOff className="w-3.5 h-3.5 text-red-400" />
              <div className="flex items-center gap-1">
                <Sparkline data={denySparkline} color="#ef4444" width={48} height={16} />
                {denyTrend > 0.15 && <TrendingUp className="w-3 h-3 text-red-400" />}
                {denyTrend < -0.15 && <TrendingDown className="w-3 h-3 text-emerald-400" />}
              </div>
            </div>
            <div className="text-lg font-bold text-nhi-text font-mono leading-none">
              {counters.denied}
              {counters.auditDeny > 0 && <span className="text-[9px] text-amber-400 ml-1">+{counters.auditDeny} audit</span>}
            </div>
            <div className="text-[8px] text-nhi-faint mt-0.5">Denied{denyTrend > 0.15 ? ' \u2191' : denyTrend < -0.15 ? ' \u2193' : ''}</div>
          </button>

          {/* Enforcement Funnel */}
          <div className="nhi-card p-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <Shield className="w-3.5 h-3.5 text-accent" />
              <span className="text-[8px] font-bold text-nhi-dim">ENFORCEMENT</span>
            </div>
            {funnel.total > 0 ? (
              <>
                <div className="flex items-center gap-1 mb-1">
                  <div className="flex-1 h-2 rounded-full overflow-hidden bg-surface-3 flex">
                    <div style={{ width: `${(funnel.enforce / funnel.total) * 100}%`, background: '#10b981' }} title={`${funnel.enforce} enforced`} />
                    <div style={{ width: `${(funnel.audit / funnel.total) * 100}%`, background: '#f59e0b' }} title={`${funnel.audit} audit`} />
                  </div>
                  <span className="text-[10px] font-bold text-emerald-400">{Math.round((funnel.enforce / funnel.total) * 100)}%</span>
                </div>
                <div className="flex gap-2 text-[7px] text-nhi-faint">
                  <span><span className="inline-block w-1.5 h-1.5 rounded-full mr-0.5" style={{ background: '#10b981' }} />{funnel.enforce} enforce</span>
                  <span><span className="inline-block w-1.5 h-1.5 rounded-full mr-0.5" style={{ background: '#f59e0b' }} />{funnel.audit} audit</span>
                </div>
              </>
            ) : (
              <>
                <div className="text-[10px] font-bold text-nhi-faint mb-0.5">{counters.total > 0 ? 'All audit mode' : 'No data'}</div>
                <div className="text-[7px] text-nhi-faint">{counters.total > 0 ? `${counters.total} decisions in audit` : 'No enforcement decisions yet'}</div>
              </>
            )}
          </div>

          {/* Active Denials */}
          <button onClick={() => setFilter('denied')} className="nhi-card p-2.5 text-left hover:ring-1 hover:ring-amber-400/30 transition-all" style={{ cursor: 'pointer' }}>
            <div className="flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3.5 h-3.5" style={{ color: openViolations > 0 ? '#ef4444' : '#64748b' }} />
            </div>
            <div className="text-lg font-bold font-mono leading-none" style={{ color: openViolations > 0 ? '#ef4444' : 'var(--nhi-text)' }}>{openViolations}</div>
            <div className="text-[8px] text-nhi-faint mt-0.5">{openViolations === counters.denied ? 'Denied Requests' : 'Open Violations'}</div>
          </button>

          {/* P95 Latency */}
          <div className="nhi-card p-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <Clock className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-lg font-bold text-nhi-text font-mono leading-none">{lats.p95 ? lats.p95+'ms' : '\u2014'}</div>
            <div className="text-[8px] text-nhi-faint mt-0.5">P95 Latency{lats.p50 > 0 && <span className="text-nhi-ghost ml-1">(P50: {lats.p50}ms)</span>}</div>
          </div>
        </div>

        {/* Row 2: Top denied pairs (scrollable horizontal) — only if denials exist */}
        {topDenied.length > 0 && (
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            <span className="text-[7px] font-bold text-red-400 uppercase tracking-wider flex-shrink-0">Top Denied:</span>
            {topDenied.slice(0, 5).map((td, i) => (
              <button key={i} onClick={() => { setWorkloadFilter(td.source_name); setFilter('denied'); }}
                className="flex items-center gap-1 px-2 py-1 rounded border text-[8px] flex-shrink-0 hover:bg-red-500/5 transition-colors"
                style={{ borderColor: 'rgba(239,68,68,0.15)', background: 'rgba(239,68,68,0.03)' }}>
                <span className="font-semibold text-nhi-text truncate max-w-[60px]">{td.source_name?.replace(/^wid-dev-/,'')}</span>
                <ArrowRight className="w-2 h-2 text-red-400" />
                <span className="font-semibold text-nhi-text truncate max-w-[60px]">{td.destination_name?.replace(/^wid-dev-/,'')}</span>
                <span className="font-bold text-red-400 ml-1">{td.deny_count}x</span>
              </button>
            ))}
          </div>
        )}
      </div>}

      {/* ═══════ MIDDLE: Two-panel layout ═══════ */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — collapses when replay is active */}
        <div className={`${replayExpanded ? 'w-0 overflow-hidden opacity-0' : 'w-[400px]'} flex-shrink-0 flex flex-col bg-surface-2 overflow-hidden transition-all duration-300`} style={{ borderRight: replayExpanded ? 'none' : '1px solid var(--border)' }}>

          {/* Search + Time Range + Controls */}
          <div className="p-2.5 space-y-2" style={{ borderBottom:'1px solid var(--border)' }}>
            {/* Search bar */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-nhi-ghost" />
              <input
                type="text"
                value={searchInput}
                onChange={e => handleSearchInput(e.target.value)}
                placeholder="Search workload, SPIFFE, policy, trace ID..."
                className="w-full pl-8 pr-3 py-1.5 text-[10px] rounded-lg border bg-surface-1 text-nhi-text placeholder:text-nhi-ghost"
                style={{ borderColor: 'var(--border)', outline: 'none' }}
                onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
              {searchInput && (
                <button onClick={() => handleSearchInput('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-nhi-faint hover:text-nhi-text"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 14, lineHeight: 1 }}>
                  {'×'}
                </button>
              )}
            </div>

            {/* Time Range + View Mode + Verdict + Controls Row */}
            <div className="flex items-center gap-2 flex-wrap">
              {/* Time range presets */}
              <div className="flex rounded border overflow-hidden" style={{ borderColor:'var(--border)' }}>
                {TIME_RANGES.map(tr => (
                  <button key={tr.key}
                    onClick={() => { setTimeRange(tr.key); setSinceFilter(''); }}
                    className={`text-[8px] font-bold px-2 py-1 ${timeRange===tr.key ? 'bg-accent/10 text-accent' : 'text-nhi-dim bg-surface-3'}`}
                    style={tr.key !== '1h' ? { borderLeft: '1px solid var(--border)' } : {}}>
                    {tr.label}
                  </button>
                ))}
              </div>

              {/* View mode toggle */}
              <div className="flex rounded border overflow-hidden" style={{ borderColor:'var(--border)' }}>
                {[['traces', RouteIcon, 'Traces'], ['events', ListIcon, 'Events'], ['ai', Zap, 'AI']].map(([k, I, l]) => (
                  <button key={k} onClick={()=>setViewMode(k)}
                    className={`text-[8px] font-semibold px-2 py-1 flex items-center gap-1 ${viewMode===k?'bg-accent/10 text-accent':'text-nhi-dim bg-surface-3'}`}
                    style={k!=='traces'?{borderLeft:'1px solid var(--border)'}:{}}>
                    <I className="w-3 h-3" /> {l}
                  </button>
                ))}
              </div>

              {/* Verdict filter */}
              <div className="flex gap-1">
                {[['all','All'],['allowed','Allow'],['denied','Deny']].map(([k,l])=>(
                  <button key={k} onClick={()=>setFilter(k)} className={`text-[8px] font-semibold px-1.5 py-1 rounded border ${filter===k?'text-accent bg-accent/10 border-accent/30':'text-nhi-dim bg-surface-3 border-[var(--border)]'}`}>{l}</button>
                ))}
              </div>

              <div className="flex-1" />

              {/* Live + Refresh */}
              <button onClick={()=>setAutoRefresh(!autoRefresh)} className={`text-[8px] font-semibold px-1.5 py-1 rounded border ${autoRefresh?'text-emerald-500 bg-emerald-500/10 border-emerald-500/20':'text-nhi-dim bg-surface-3 border-[var(--border)]'}`}>
                {autoRefresh?'\u25CF Live':'\u25CB Off'}
              </button>
              <button onClick={fetchData} className="nhi-btn-ghost text-xs p-1"><RefreshCw className={`w-3 h-3 ${loading?'animate-spin':''}`} /></button>
            </div>
          </div>

          {/* Active filter banners */}
          {hasActiveFilters && (
            <div className="px-3 py-1.5 flex items-center gap-1.5 flex-wrap" style={{ borderBottom: '1px solid var(--border)', background: 'rgba(59,130,246,0.03)' }}>
              <Filter className="w-3 h-3 text-blue-400 flex-shrink-0" />
              {workloadFilter && (
                <span className="text-[8px] font-mono px-2 py-1 rounded-md flex items-center gap-1.5" style={{ background: 'rgba(59,130,246,0.08)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.15)' }}>
                  workload: {workloadFilter}
                  <button onClick={() => setWorkloadFilter('')} className="ml-1 hover:opacity-70" style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#60a5fa', fontSize: 12, lineHeight: 1 }}>{'×'}</button>
                </span>
              )}
              {policyFilter && (
                <span className="text-[8px] font-mono px-2 py-1 rounded-md flex items-center gap-1.5" style={{ background: 'rgba(16,185,129,0.08)', color: '#10b981', border: '1px solid rgba(16,185,129,0.15)' }}>
                  policy: {policyFilter}
                  <button onClick={() => setPolicyFilter('')} className="ml-1 hover:opacity-70" style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#10b981', fontSize: 12, lineHeight: 1 }}>{'×'}</button>
                </span>
              )}
              {searchText && (
                <span className="text-[8px] font-mono px-2 py-1 rounded-md flex items-center gap-1.5" style={{ background: 'rgba(139,92,246,0.08)', color: '#8b5cf6', border: '1px solid rgba(139,92,246,0.15)' }}>
                  search: {searchText}
                  <button onClick={() => { setSearchInput(''); setSearchText(''); }} className="ml-1 hover:opacity-70" style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8b5cf6', fontSize: 12, lineHeight: 1 }}>{'×'}</button>
                </span>
              )}
              <span className="text-[8px] text-nhi-faint">{loading ? '...' : `${decisions.length} matching`}</span>
              <button onClick={clearAllFilters} className="ml-auto text-[8px] text-nhi-faint hover:text-nhi-text" style={{ background: 'none', border: 'none', cursor: 'pointer' }}>Clear all</button>
            </div>
          )}

          {/* Event list */}
          <div className="flex-1 overflow-auto">
            <>
              {error && <div className="p-3 m-2 rounded-lg bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/15 text-xs text-red-600 dark:text-red-400">{error}</div>}
              {!loading && filtered.length===0 && (
                <div className="p-8 text-center">
                  <Zap className="w-8 h-8 mx-auto mb-2 text-nhi-ghost" />
                  <div className="text-sm text-nhi-faint mb-1">
                    {hasActiveFilters && allDecisions.length > 0
                      ? 'No decisions match current filters'
                      : allDecisions.length > 0 ? 'No events match current filter' : 'No decisions yet'}
                  </div>
                  {hasActiveFilters && allDecisions.length > 0 && (
                    <button onClick={clearAllFilters}
                      className="text-[9px] text-accent hover:underline mt-1" style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
                      Clear filters and show all {allDecisions.length} events \u2192
                    </button>
                  )}
                </div>
              )}
              {viewMode==='traces' && (
                <>
                  {[...traceGroups.groups.entries()].map(([tid,hops])=>(
                    <TraceGroup key={tid} traceId={tid} hops={hops} selected={selected}
                      onSelect={(id, hopIdx) => handleSelectHopInTrace(id, tid, hopIdx)}
                      isExpanded={expandedTraces.has(tid)}
                      onToggle={()=>{ toggleTrace(tid); setSelectedTraceId(tid); setSelected(null); setSelectedHopIndex(null); }}
                      wlCtx={wlCtx} onNavigateGraph={navigateToGraph}
                    />
                  ))}
                  {traceGroups.ungrouped.length>0 && (
                    <>
                      {traceGroups.groups.size>0 && <div className="px-3 py-1.5 text-[8px] font-bold text-nhi-ghost uppercase tracking-wider" style={{ background:'var(--surface-3)', borderBottom:'1px solid var(--border)' }}>Single Events ({traceGroups.ungrouped.length})</div>}
                      {traceGroups.ungrouped.map(d=><EventRow key={d.id||d.decision_id} d={d} selected={selected} onSelect={handleSelectDecision} wlCtx={wlCtx} onNavigateGraph={navigateToGraph} />)}
                    </>
                  )}
                </>
              )}
              {viewMode==='events' && filtered.map(d=><EventRow key={d.id||d.decision_id} d={d} selected={selected} onSelect={handleSelectDecision} wlCtx={wlCtx} onNavigateGraph={navigateToGraph} />)}
              {viewMode==='ai' && (
                <>
                  {/* AI Activity Summary Strip */}
                  {aiStats?.totals && (
                    <div className="px-3 py-2 flex items-center gap-3" style={{ borderBottom: '1px solid var(--border)', background: 'rgba(139,92,246,0.03)' }}>
                      <div className="flex items-center gap-1.5">
                        <Zap className="w-3 h-3 text-violet-400" />
                        <span className="text-[8px] font-bold text-violet-400 uppercase tracking-wider">AI Activity</span>
                      </div>
                      <div className="flex gap-3 text-[8px]">
                        <span className="text-nhi-dim"><span className="font-bold text-nhi-text">{aiStats.totals.total_requests}</span> requests</span>
                        <span className="text-nhi-dim"><span className="font-bold text-nhi-text">{aiStats.totals.total_tokens.toLocaleString()}</span> tokens</span>
                        <span className="text-nhi-dim"><span className="font-bold text-nhi-text">{aiStats.totals.unique_providers}</span> providers</span>
                        <span className="text-nhi-dim"><span className="font-bold text-nhi-text">{aiStats.totals.unique_sources}</span> sources</span>
                      </div>
                    </div>
                  )}
                  {/* Provider breakdown */}
                  {aiStats?.byProvider?.length > 0 && (
                    <div className="px-3 py-1.5 flex items-center gap-2 overflow-x-auto" style={{ borderBottom: '1px solid var(--border)' }}>
                      {aiStats.byProvider.map((bp, i) => (
                        <div key={i} className="flex items-center gap-1.5 px-2 py-1 rounded border flex-shrink-0"
                          style={{ borderColor: 'rgba(139,92,246,0.15)', background: 'rgba(139,92,246,0.03)' }}>
                          <span className="text-[7px] font-bold px-1 py-0.5 rounded" style={{
                            background: bp.ai_provider === 'openai' ? '#10a37f18' : bp.ai_provider === 'anthropic' ? '#d97b4618' : '#8b5cf618',
                            color: bp.ai_provider === 'openai' ? '#10a37f' : bp.ai_provider === 'anthropic' ? '#d97b46' : '#8b5cf6',
                          }}>{bp.ai_provider?.toUpperCase()}</span>
                          <span className="text-[8px] font-bold text-nhi-text">{bp.request_count}</span>
                          <span className="text-[7px] text-nhi-ghost">{parseInt(bp.total_tokens || 0).toLocaleString()} tok</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {aiLoading && <div className="p-4 text-center"><Loader className="w-4 h-4 animate-spin mx-auto text-violet-400" /></div>}
                  {!aiLoading && aiEvents.length === 0 && (
                    <div className="p-8 text-center">
                      <Zap className="w-8 h-8 mx-auto mb-2 text-nhi-ghost" />
                      <div className="text-sm text-nhi-faint mb-1">No AI requests detected</div>
                      <div className="text-[9px] text-nhi-ghost">AI API calls through edge gateways will appear here</div>
                    </div>
                  )}
                  {!aiLoading && aiEvents.map(ev => (
                    <div key={ev.id} className="px-3 py-2 hover:bg-surface-3/50 cursor-pointer" style={{ borderBottom: '1px solid var(--border)' }}
                      onClick={() => handleSelectDecision(ev.decision_id || ev.id)}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{
                          background: ev.ai_provider === 'openai' ? '#10a37f18' : ev.ai_provider === 'anthropic' ? '#d97b4618' : '#8b5cf618',
                          color: ev.ai_provider === 'openai' ? '#10a37f' : ev.ai_provider === 'anthropic' ? '#d97b46' : '#8b5cf6',
                        }}>{ev.ai_provider?.toUpperCase()}</span>
                        {ev.ai_model && <span className="text-[8px] font-mono text-nhi-dim truncate max-w-[120px]">{ev.ai_model}</span>}
                        {ev.ai_operation && <span className="text-[7px] text-violet-400 font-semibold">{ev.ai_operation}</span>}
                        <span className="text-[7px] text-nhi-ghost ml-auto flex-shrink-0">{timeAgo(ev.created_at)}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[8px]">
                        <span className="text-nhi-faint truncate max-w-[100px]">{ev.source_name?.replace(/^wid-dev-/, '')}</span>
                        <ArrowRight className="w-2.5 h-2.5 text-nhi-ghost flex-shrink-0" />
                        <span className="text-nhi-faint truncate max-w-[100px]">{ev.destination_host}</span>
                        {ev.tool_count > 0 && (
                          <span className="text-[7px] px-1 py-0.5 rounded bg-violet-500/10 text-violet-400 flex-shrink-0">
                            {ev.tool_count} tool{ev.tool_count !== 1 ? 's' : ''}
                          </span>
                        )}
                        {ev.estimated_input_tokens > 0 && (
                          <span className="text-[7px] text-nhi-ghost flex-shrink-0">{ev.estimated_input_tokens.toLocaleString()} tok</span>
                        )}
                        {ev.stream && <span className="text-[6px] text-amber-400 flex-shrink-0">STREAM</span>}
                      </div>
                    </div>
                  ))}
                </>
              )}
            </>
          </div>
        </div>

        {/* Right panel: enforcement timeline or generic trace detail */}
        <div className="flex-1 flex flex-col overflow-hidden bg-surface-1">
          {effectiveDecision || selectedTraceHops
              ? <TraceDetail traceHops={selectedTraceHops} selectedDecision={effectiveDecision} initialHopIndex={selectedHopIndex} onNavigateGraph={navigateToGraph} onReplayActive={setReplayExpanded} />
              : (
                /* Empty state: show context banner when navigated from graph */
                <div className="flex-1 flex items-center justify-center text-nhi-faint">
                  <div className="text-center max-w-[300px]">
                    <Layers className="w-10 h-10 mx-auto mb-3 opacity-20" />
                    <div className="text-sm mb-2">Select a trace or event to inspect</div>
                    {workloadFilter && (
                      <div className="text-[9px] text-nhi-ghost">
                        Showing decisions for <span className="font-semibold text-accent">{workloadFilter}</span>
                        {wlCtx[workloadFilter] && (
                          <div className="mt-1.5 flex items-center justify-center gap-2">
                            <TrustPill level={wlCtx[workloadFilter].trust_level} />
                            {wlCtx[workloadFilter].security_score != null && (
                              <span className="text-[7px] font-bold px-1.5 py-0.5 rounded" style={{
                                background: wlCtx[workloadFilter].security_score >= 80 ? '#10b98118' : wlCtx[workloadFilter].security_score >= 55 ? '#f59e0b18' : '#ef444418',
                                color: wlCtx[workloadFilter].security_score >= 80 ? '#10b981' : wlCtx[workloadFilter].security_score >= 55 ? '#f59e0b' : '#ef4444',
                              }}>
                                Score: {wlCtx[workloadFilter].security_score}
                              </span>
                            )}
                            <button onClick={() => navigateToGraph(workloadFilter)}
                              className="text-[7px] text-accent flex items-center gap-0.5 hover:underline"
                              style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
                              <ExternalLink className="w-2.5 h-2.5" /> View in Graph
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )
          }
        </div>
      </div>
    </div>
  );
};

export default AccessEvents;
