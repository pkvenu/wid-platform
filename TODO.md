# WID Platform — Todo

## 🔴 Pending

### Graph Page
- [ ] A2A/MCP scanner integration (demo agents deployed, scanner incomplete)
- [ ] Stale relay entries cleanup (GCP hub accumulates entries on spoke restart)

### Infrastructure
- [ ] **Custom domain via Load Balancer (Option B)**
  - Reserve static external IP in GCP (`gcloud compute addresses create`)
  - Create global external Application Load Balancer
  - Attach `wid-dev-web-ui` Cloud Run service as a serverless NEG backend
  - Configure Google-managed SSL certificate for the domain
  - Point domain A record at the static IP
  - Update `ALLOWED_ORIGINS` in `discovery-service/src/index.js` to include the new domain
  - Current IP: `34.111.176.251` (existing LB — check if this can be reused)

## ✅ Done

### GraphPage — Enforce Proof Trail
- [x] Fixed empty Playbook (enrichAttackPath not called on node click)
- [x] Fuzzy finding_type mapper so backend titles resolve to catalog keys
- [x] Synced frontend CONTROL_CATALOG field names with backend (`edge_position`, `edges_severed`, `crown_jewel_proximity`)
- [x] Fixed scoreControl() to use correct backend field names
- [x] Backend ranked_controls enrichment added to GET /graph handler (was bypassed by cache)
- [x] Graph node shield overlay + green ring on enforce
- [x] Attack path fades out after enforce
- [x] Timeline event injected on enforce
- [x] Enforcement Record card with policy ID, timestamp, blast delta
- [x] fetchAll() re-runs after enforce so header counts update

### GraphPage — Usability Improvements (21 items)
- [x] Bumped text sizes across right panel (ndChip, ndLabel, ndRow, CollapsibleSection, KPI Strip, Quick Action Bar, Status Bar)
- [x] Collapsed all sections by default except Threat Brief
- [x] Improved ImpactDelta readability (padding, arrow separator, font sizes)
- [x] Added SIM/AUDIT/ENFORCE stepper indicator with 3-dot progress bar
- [x] Reorganized Threat Brief (risk summary sentence, findings first, credential detail moved to bottom)
- [x] Node selection pulse ring animation on click
- [x] Clickable findings that highlight attack paths on graph
- [x] Zoom-dependent label visibility (labels hide below 0.6x, larger at 1.2x+)
- [x] Graph legend (toggleable, shows node types and edge types)
- [x] Improved node clustering (stronger charge/group forces, type-based collision radius)
- [x] Minimap canvas showing node positions and viewport
- [x] Filter chip category-specific colors (pink=agents, orange=shadow, red=rogue, etc.)
- [x] Risk severity filter (CRITICAL/HIGH/MEDIUM/LOW chips below category filters)
- [x] Resizable right panel (drag handle, min 280px, max 520px)
- [x] Enhanced search (searches type/spiffe_id, keyboard nav, highlight matching)
- [x] Cross-page navigation from findings to audit events (Logs button on each finding)
- [x] Right-click context menu on graph nodes (Inspect, View Audit Logs, Highlight, Copy SPIFFE ID)
- [x] SVG export button in header toolbar
- [x] Enforced nodes turn green on graph re-render (verified working)
- [x] Simulate/Audit/Enforce visual flows end-to-end (stepper + overlay)

### Remediation Decision Framework (ADR-011)
- [x] Replaced 3-value `remediation_type` (policy/direct/notify) with 6-category taxonomy (policy/iac/infra/code_change/vendor/process)
- [x] Fixed wrong `template_id` mappings: orphaned-asset, rogue-workload, account-outside-org, scope-reduction
- [x] Removed `template_id` from controls that can't be enforced by WID policy (set to null)
- [x] Updated all 58 backend CONTROL_CATALOG controls with correct `remediation_type`
- [x] Updated all 24 frontend CONTROL_CATALOG_FALLBACK controls with `remediation_type`
- [x] Updated ControlCard UI to render distinct treatment per remediation category
- [x] Documented decision framework in `shared/ADR-011-remediation-decision-framework.md`

### Infrastructure
- [x] Fixed CORS — production allowlist with Cloud Run URL + load balancer IP
- [x] Fixed API URL in production build — was using relative `/api/v1` which 404'd on Cloud Run
- [x] Fixed `vite.config.js` to bake discovery service URL into build via `__API_BASE__`
- [x] Fixed `graph-routes.js` to enrich `ranked_controls` on cached graph responses
