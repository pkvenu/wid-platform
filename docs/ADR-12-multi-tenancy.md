# ADR-12: Multi-Tenancy via Shared Schema + Row-Level Security

> **Status**: Accepted | **Date**: 2026-03-15

---

## Context

The WID platform was single-tenant. All workloads, policies, decisions, and graph data shared a flat namespace. Enterprise customers require:
- Data isolation between tenants (hard requirement for SOC 2, ISO 27001)
- Per-tenant policy scoping (tenant A's policies must not affect tenant B)
- Data sovereignty (EU tenants' data stays in EU)
- No cross-tenant leakage in caches, JWTs, audit logs, or graph queries

## Decision

**Shared database, shared schema with three defense layers:**

1. **PostgreSQL Row-Level Security (RLS)** — every data table has `tenant_id NOT NULL` with RLS policies. DB connection sets `app.current_tenant` via `SET LOCAL`. Even if application code has a bug, the DB rejects cross-tenant reads/writes.

2. **Application-layer tenant middleware** — extracts `tenantId` from JWT, injects into request context, sets `app.current_tenant` on every DB connection before query execution. Rejects requests with missing/invalid tenant context.

3. **Tenant-scoped caches** — all cache keys prefixed with `tenant:{tenantId}:`. Policy cache, graph cache, relay cache — all tenant-partitioned. Cache invalidation is tenant-scoped (no cross-tenant pollution).

### Data Model

```sql
-- Tenant registry
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  plan TEXT NOT NULL DEFAULT 'trial',         -- trial | team | enterprise
  region TEXT NOT NULL DEFAULT 'us',          -- us | eu | ap
  data_residency_mode TEXT DEFAULT 'relaxed', -- relaxed | strict
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tenant membership
CREATE TABLE tenant_memberships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'viewer',  -- owner | admin | operator | viewer
  invited_by UUID REFERENCES users(id),
  accepted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, user_id)
);
```

All existing data tables gain:
```sql
ALTER TABLE workloads ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
ALTER TABLE policies ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
ALTER TABLE ext_authz_decisions ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
-- ... repeated for all 25+ tables
```

RLS pattern per table:
```sql
ALTER TABLE workloads ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workloads
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

### JWT Changes

```json
{
  "sub": "user-uuid",
  "tenantId": "tenant-uuid",
  "tenantSlug": "acme-corp",
  "role": "admin",
  "iat": 1710500000,
  "exp": 1710586400
}
```

### Registration + Invitation Flow

1. First user registers -> creates tenant (becomes `owner`)
2. Owner invites users via email -> `tenant_memberships` row with `accepted_at = NULL`
3. Invited user accepts -> `accepted_at` set, user added to tenant context
4. Users can belong to multiple tenants, switch via `X-Tenant-Id` header or tenant picker UI

### Tenant Middleware

```
Request -> Extract JWT -> Validate tenantId claim
  -> SET LOCAL app.current_tenant = tenantId (on pg connection)
  -> Attach req.tenantId to request context
  -> Next handler (all queries automatically filtered by RLS)
```

Pool connection: `pg.Client` replaced with `pg.Pool`. Each request checks out a connection, sets tenant context, returns on completion.

## Alternatives Considered

### Schema-per-tenant
- **Rejected**: Complicates migrations (N schemas to migrate). Connection pooling explodes. Doesn't scale past ~50 tenants. No benefit over RLS for our data model.

### Database-per-tenant
- **Rejected**: Highest isolation but over-engineered at current scale. Operational burden (N databases to backup, patch, monitor). Cross-tenant analytics impossible. Reserved for regulated verticals (FedRAMP) as future option.

## Data Sovereignty

- **Region tag**: Each tenant has a `region` field (`us`, `eu`, `ap`)
- **Relaxed mode** (default): Data stored in primary region, replicated globally for performance
- **Strict mode**: Queries rejected if routed to wrong region. Spoke relays tagged by region; strict tenants' audit events only flow through same-region spokes
- **Spoke-local storage**: For sovereign deployments, spoke relay can write to local DB instead of forwarding to central hub. Hub receives metadata only (counts, timestamps — no PII)

## Security — Threat Categories

| # | Threat | Mitigation |
|---|--------|-----------|
| T1 | Cross-tenant data leakage (queries) | RLS on every table. Even raw SQL injection cannot cross tenant boundary |
| T2 | Cross-tenant cache poisoning | Cache keys prefixed `tenant:{id}:`. Separate eviction scopes |
| T3 | JWT tenant spoofing | Token-service validates tenant membership before issuing JWT. tenantId is server-set, not client-set |
| T4 | Relay impersonation (cross-tenant) | Relay registration includes tenant_id. Hub verifies relay-tenant binding via mTLS + API key |
| T5 | IDOR on API endpoints | All DB queries go through RLS. Application middleware double-checks tenant context |
| T6 | Privilege escalation (viewer -> admin) | Role checked in middleware. Role changes require owner/admin. Audit logged |
| T7 | Tenant enumeration | Tenant slugs not exposed in API responses. No tenant listing endpoint for non-owners |
| T8 | Cross-tenant policy interference | Policies scoped by tenant_id. Evaluation loads only current tenant's policies |
| T9 | Audit log cross-contamination | ext_authz_decisions has tenant_id + RLS. Replay endpoint enforces tenant match |
| T10 | Graph data leakage | identity_graph cached per tenant. Graph endpoint filters by tenant_id |
| T11 | Token replay across tenants | Token validation checks tenantId claim matches request tenant context |
| T12 | Shared SA cross-tenant pivoting | Attack path detector scoped to tenant. No cross-tenant SA relationships in graph |
| T13 | Tenant deletion data remnants | Hard delete with cascade. Audit log retained per compliance retention policy |
| T14 | Connection pool exhaustion (noisy neighbor) | Per-tenant connection limits. Pool size configurable per plan tier |
| T15 | Backup/restore cross-contamination | Tenant-scoped restore validated by RLS on import |
| T16 | Admin API abuse | Platform admin (super-admin) is separate from tenant admin. Super-admin actions audit logged with elevated scrutiny |
| T17 | Webhook/SIEM cross-tenant routing | Webhook configs are tenant-scoped. Event payloads include tenant context for routing |
| T18 | MCP fingerprint cross-tenant pollution | mcp_fingerprints table has tenant_id + RLS. Drift detection scoped |
| T19 | Compliance framework cross-tenant leakage | Coverage stats computed per tenant. Framework definitions are global (read-only), deployments are tenant-scoped |
| T20 | Data sovereignty violation | Strict residency mode enforced at middleware layer. Spoke-to-hub routing respects region tags |

## Consequences

- All 25+ tables gain `tenant_id` column with NOT NULL constraint and RLS policy
- JWT payload includes `tenantId` — all token-issuing code updated
- `pg.Client` replaced with `pg.Pool` across all services
- Cache keys across policy-sync, discovery, relay services all prefixed with tenant
- Existing single-tenant data migrated to a default tenant on upgrade
- Relay registration includes tenant binding
- Graph computation, attack path detection, control scoring — all tenant-scoped
- Performance: RLS adds ~0.1ms per query (negligible). Index on `tenant_id` on all tables

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/tenants` | Create tenant (first user becomes owner) |
| GET | `/api/v1/tenants/:id` | Get tenant details |
| PUT | `/api/v1/tenants/:id` | Update tenant settings |
| POST | `/api/v1/tenants/:id/invite` | Invite user to tenant |
| GET | `/api/v1/tenants/:id/members` | List tenant members |
| PUT | `/api/v1/tenants/:id/members/:userId` | Update member role |
| DELETE | `/api/v1/tenants/:id/members/:userId` | Remove member |
| POST | `/api/v1/tenants/switch` | Switch active tenant context |
