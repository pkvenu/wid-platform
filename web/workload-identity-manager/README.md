# Workload Identity Platform — Attestation Architecture

## Overview

This platform discovers, classifies, and attests Non-Human Identities (NHIs) across AWS, Docker, Kubernetes, Vault, GitHub, and other providers. The attestation engine verifies workload identity through a 4-tier trust model, then determines whether auto-attestation is safe or manual review is required.

---

## Attestation Decision: Auto vs Manual

The engine evaluates every workload against 4 sequential gates. **All gates must pass** for auto-attestation. If any gate fails, the workload is flagged for manual review.

### Decision Flow

```
                    ┌──────────────────────┐
                    │  Run all applicable   │
                    │  attestation methods  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
             ┌──NO─┤  GATE 1: Has owner?   │
             │      └──────────┬───────────┘
             │                YES
             │      ┌──────────▼───────────┐
             │ ┌─YES┤  GATE 2: Stale?      │
             │ │    │  (>90 days inactive)  │
             │ │    └──────────┬───────────┘
             │ │              NO
             │ │    ┌──────────▼───────────┐
             │ │ ┌──┤  GATE 3: High-risk?  │
             │ │ │  │  (admin/secret) AND   │
             │ │ │  │  no Tier 1/2?         │
             │ │ │  └──────────┬───────────┘
             │ │ │            NO
             │ │ │  ┌──────────▼───────────┐
             │ │ │  │  GATE 4: Production?  │──YES──┐
             │ │ │  │  AND no Tier 1/2?     │       │
             │ │ │  └──────────┬───────────┘       │
             │ │ │            NO                    │
             │ │ │  ┌──────────▼───────────┐  ┌────▼─────────────┐
             │ │ │  │  Tier 1 or 2 passed? ├─►│ ✅ AUTO-ATTEST    │
             │ │ │  └──────────┬───────────┘  │    (high conf)    │
             │ │ │            NO               └──────────────────┘
             │ │ │  ┌──────────▼───────────┐
             │ │ │  │ ABAC ≥60 + team?     │──YES──► ✅ AUTO (medium)
             │ │ │  │ OR owner+team+SPIFFE? │
             │ │ │  └──────────┬───────────┘
             │ │ │            NO
             ▼ ▼ ▼  ┌──────────▼───────────┐
          ┌──────────┤  ⚠️ MANUAL REVIEW     │
          │          │  required             │
          │          └──────────────────────┘
          │
          │  Production exception:
          │  team + SPIFFE + ABAC ≥70 → ✅ AUTO (medium)
          │
```

### Gate Details

| Gate | Condition | Rationale | Industry Source |
|------|-----------|-----------|-----------------|
| **1. Ownership** | `owner` field must be set | No NHI can be governed without a human accountable for it | Astrix/Oasis: "Without a clear owner, there's no one to verify" |
| **2. Staleness** | `last_seen` must be within 90 days | Dormant identities may be abandoned or compromised | Oasis: stale NHI detection and offboarding |
| **3. High-risk** | Admin/root/secret NHIs need Tier 1 or 2 | Blast radius of wrong auto-attestation is too high | Oasis: risk-weighted confidence scoring |
| **4. Production** | Prod environment needs Tier 1 or 2 | Production workloads require platform-level verification | TrustFour/SPIRE: environment isolation enforcement |

### Auto-Attestation Tiers

| Confidence | Required Evidence | Example |
|------------|-------------------|---------|
| **High** | Tier 1 (crypto) or Tier 2 (token) + owner | Lambda with STS CallerID + assigned owner |
| **Medium** | ABAC ≥60 + team + 2 methods, OR owner + team + SPIFFE | Container with labels, team, SPIFFE ID |
| **Manual** | Everything else | IAM role with no owner, unknown type, stale identity |

---

## Trust Tier Model

### Tier 1 — Cryptographic (Highest)

Proof that the workload possesses a cryptographic secret bound to its identity.

| Method | Description | Trust Level |
|--------|-------------|-------------|
| `spiffe-x509-svid` | X.509 certificate chain verified against SPIRE trust bundle | Cryptographic |
| `spiffe-jwt-svid` | JWT signed by SPIRE with subject = SPIFFE ID | Cryptographic |
| `aws-imdsv2-signed` | PKCS7-signed instance identity document from AWS | Cryptographic |
| `gcp-metadata-jwt` | Google-signed instance identity JWT | Cryptographic |
| `azure-msi-signed` | Azure AD-signed managed identity token | Cryptographic |
| `mtls-verified` | Mutual TLS with verified certificate chain | Cryptographic |

### Tier 2 — Token-Based (High)

Proof via platform-issued tokens that can be validated against the issuer.

| Method | Description | Trust Level |
|--------|-------------|-------------|
| `jwt-oidc-verified` | JWT signature + issuer + claims verified via JWKS | High |
| `github-oidc` | GitHub Actions OIDC token with repo/ref/actor claims | High |
| `vault-token-lookup` | HashiCorp Vault accessor introspection | High |
| `k8s-token-review` | Kubernetes API-validated service account token | High |
| `aws-sts-identity` | AWS STS GetCallerIdentity ARN verification | High |

### Tier 3 — Attribute-Based / ABAC (Medium)

Aggregate confidence from multiple weak signals. No single signal is sufficient.

| Signal | Weight | Description |
|--------|--------|-------------|
| Owner assigned | 15 | Human accountability |
| Team assigned | 10 | Escalation path |
| Known environment | 15 | Not "unknown" |
| SPIFFE ID present | 20 | Identity infrastructure |
| Not shadow | 10 | Previously verified |
| Rich labels (≥3) | 10 | Metadata completeness |
| Cloud metadata | 15 | ARN, instance ID present |
| Recently seen (<24h) | 10 | Active workload |

**Pass threshold:** Score ≥ 50/105. Auto-attest threshold: Score ≥ 60 (with team + 2 methods).

### Tier 4 — Policy / Manual (Low)

Weakest verification — pattern matching and human approval.

| Method | Description | Trust Level |
|--------|-------------|-------------|
| `catalog-match` | Name regex AND category match against known patterns | Low |
| `policy-approved` | OPA policy evaluation | Low |
| `manual-approval` | Human operator approval with audit trail | Low |

---

## Score Correlation

When attestation completes, the engine correlates trust level with security score and shadow status.

### Trust → Score Floor

| Trust Level | Score Floor | Rationale |
|-------------|------------|-----------|
| Cryptographic | 90 | Highest possible verification |
| Very High | 80 | Multi-method or strong platform proof |
| High | 70 | Token-based verification |
| Medium | 55 | Attribute-based |
| Low | 40 | Catalog/policy only |
| None | 0 | Not attested |

### Score Modifiers

| Condition | Modifier | Cap |
|-----------|----------|-----|
| 4+ methods passed | +5 | 100 |
| Multi-signal bonus | +5 | 100 |
| No owner | -10 | Floor |
| No team | -5 | Floor |

### Shadow Resolution

- **Attested → shadow cleared** (we verified it, it's not unknown)
- Residual shadow score: +15 no owner, +10 no team, +10 unknown env, +5 few labels
- Re-flagged as shadow only if: `shadow_score ≥ 50 AND trust_level === 'low'`

---

## Attestation Expiry (TTL)

| Trust Level | TTL | Re-attestation |
|-------------|-----|----------------|
| Cryptographic | 7 days | Weekly — strong proof, low re-check burden |
| Very High | 3 days | Bi-weekly cadence |
| High | 2 days | Token-based, moderate refresh |
| Medium | 1 day | ABAC signals can change, daily re-check |
| Low | 4 hours | Weak verification, frequent re-check |
| None | — | Not attested |

---

## Multi-Signal Trust Bonus

If **3 or more** attestation methods pass, the trust level is automatically boosted by one tier (e.g., High → Very High). This mirrors SPIRE's multi-selector approach where combining node attestation + workload attestation + namespace selectors produces stronger identity confidence.

---

## Catalog Match Strictness

The catalog match method requires **both**:
1. Name matches a known pattern regex (e.g., `/^wip-/`, `/vault/`, `/postgres/`)
2. Category is assigned and not "unknown"

A name match alone is too loose. A category alone is scanner-assigned and may be incorrect. Both together provide reasonable service catalog validation.

---

## Owner/Team Assignment

Owners and teams can be assigned via the UI detail panel or the PATCH API:

```
PATCH /api/v1/workloads/:id
Body: { "owner": "user@company.com", "team": "platform-team" }
```

Setting an owner automatically:
- Clears `is_shadow` flag
- Reduces `shadow_score` by 15 (owner) or 10 (team)
- Recalculates `security_score` with bonus

---

## Auto-Attest on Scan

When the **Scan** button is clicked:
1. Discovery scanners run against all configured providers
2. After scan completes, `POST /api/v1/workloads/auto-attest` fires automatically
3. Each workload is evaluated through the confidence assessment gates
4. Results are split into two buckets:
   - **Auto-attested**: pass all gates → `verified = true`, score/shadow updated in DB
   - **Needs manual review**: fail any gate → `attestation_data` saved but `verified` stays `false`
5. UI toast shows: "24 attested · 12 need manual review"

---

## Audit Log

Every attestation event is written to the `attestation_history` table, providing a complete audit trail for compliance and forensics.

### What Gets Logged

Each entry records the source of the attestation, the confidence assessment result, and a summary of the attestation chain. Sources are tagged as: `single-attest` (UI button), `auto-attest` (scan-triggered, passed gates), `auto-attest-manual-review` (scan-triggered, failed gates), `manual-approval` (human operator), or `bulk-attest` (attest-all).

### Schema

| Column | Type | Description |
|--------|------|-------------|
| `workload_id` | FK → workloads | Which identity was attested |
| `workload_name` | varchar | Name at time of attestation |
| `trust_level` | varchar | Resulting trust level |
| `methods_passed` | integer | How many methods succeeded |
| `methods_failed` | integer | How many methods failed |
| `primary_method` | varchar | Primary verification method used |
| `attestation_data` | JSONB | Full audit payload (see below) |
| `expires_at` | timestamptz | When this attestation expires |
| `created_at` | timestamptz | When this event occurred |

### Audit Payload (attestation_data JSONB)

```json
{
  "source": "auto-attest",
  "attested": true,
  "confidence_level": "high",
  "risk_weight": "low",
  "auto_attestable": true,
  "requires_manual_review": false,
  "reasons": ["Cryptographic verification passed (Tier 1) with owner assigned"],
  "missing": [],
  "methods_attempted": 6,
  "methods_passed": 4,
  "multi_signal_bonus": true,
  "attestation_chain": [
    { "method": "aws-sts-identity", "tier": 2, "trust": "high", "label": "AWS STS CallerID" },
    { "method": "spiffe-x509-svid", "tier": 1, "trust": "high", "label": "SPIFFE X.509-SVID" }
  ]
}
```

### API Queries

Per-workload history: `GET /api/v1/workloads/:id/audit-log` (returns last 50 events)

Global history: `GET /api/v1/attestation/audit-log?limit=100` (returns up to 500 events)

### UI

The detail panel includes a collapsible **Audit Log** section at the bottom. Each event shows the timestamp, source badge (color-coded), trust level, method count, and the primary reason or missing actions.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/workloads/:id/attest` | Attest single workload |
| `POST` | `/api/v1/workloads/:id/attest/manual` | Manual approval (requires `approved_by`, `reason`) |
| `GET` | `/api/v1/workloads/:id/attestation` | Get attestation result |
| `GET` | `/api/v1/attestation/methods` | List all attestation methods by tier |
| `GET` | `/api/v1/attestation/stats` | Attestation statistics |
| `POST` | `/api/v1/workloads/attest-all` | Bulk attest unverified workloads |
| `POST` | `/api/v1/workloads/auto-attest` | Auto-attest all (with confidence gating) |
| `PATCH` | `/api/v1/workloads/:id` | Update owner/team/environment |

---

## OWASP NHI Top 10 Mapping

The dashboard maps discovered workloads against each OWASP NHI risk:

| ID | Risk | Detection Method |
|----|------|-----------------|
| NHI1 | Improper Offboarding | Active NHIs without owners |
| NHI2 | Secret Leakage | Unattested secrets/credentials |
| NHI3 | Vulnerable Third-Party NHI | Third-party integrations not verified |
| NHI4 | Insecure Authentication | Attested but no cryptographic identity |
| NHI5 | Overly Permissive NHI | Admin-level IAM roles |
| NHI6 | Insecure Cloud Deployment | Unknown environment |
| NHI7 | Long-Lived Credentials | Credentials >180 days old |
| NHI8 | Environment Isolation Failure | Production NHIs without high trust |
| NHI9 | NHI Reuse | Duplicate identity names |
| NHI10 | Human Use of NHI | Human-named service accounts |

---

## Testing

Two test suites cover the attestation system end-to-end:

```bash
cd services/discovery-service

# Engine tests — gates, thresholds, ABAC, expiry, catalog strictness
node attestation/attestation-engine.test.js

# Integration tests — routes, audit logging, UI data flow, score correlation
node attestation/attestation-routes.test.js
```

### Engine Tests (43 tests)

| Suite | Tests |
|-------|-------|
| Gate 1: Ownership | Tier 1 crypto but no owner → manual; owner + Tier 2 → auto |
| Gate 2: Staleness | 120 days → manual; 30 days → not stale |
| Gate 3: High-risk | Admin IAM without Tier 1/2 → manual + critical risk weight |
| Gate 4: Production | Prod without platform token → manual; exception with team+SPIFFE+ABAC ≥70 |
| Auto-attest paths | Well-governed identity → medium confidence |
| Multi-signal bonus | 3+ methods → trust bumped one tier |
| Catalog strictness | Name-only fails; name + category passes; category-only fails |
| ABAC scoring | Full signals → ≥80; minimal signals → <50 |
| Expiry TTLs | Crypto 168h, very-high 72h, high 48h, medium 24h, low 4h |
| Score correlation | Trust floor applied; score capped at 100 |
| Risk weight | Admin no owner → critical; normal staging → not critical |
| Confidence structure | All required fields present; manual_review is inverse of auto_attestable |

### Integration Tests (51 tests)

| Suite | Tests |
|-------|-------|
| Single attest route | Audit entry created with correct source, workload name, confidence, chain |
| Auto-attest split | 5 workloads → correct auto vs manual split; orphan/stale/prod flagged |
| Manual approval | Audit entry with source=manual-approval, trust=low |
| UI data parsing | attestation_data as object (fresh) and JSON string (from DB) both work |
| Button state | attested=true → Re-Attest; attested=false → Attest |
| Narrative rendering | Trust level, methods line, SPIFFE/ABAC claims all extractable |
| Manual review display | Risk badge, reasons, missing actions all render |
| Audit log queries | Per-workload history; chronological order; global query with limit |
| Score correlation | Floor applied, bonus added, penalties capped, shadow cleared/preserved |

---

## File Structure

```
attestation/
├── attestation-engine.js         # Core engine: methods, ABAC, confidence gates
├── attestation-engine.test.js    # 43 tests: gates, thresholds, scoring, expiry
├── attestation-routes.js         # Express routes: attest, auto-attest, audit log, PATCH
├── attestation-routes.test.js    # 51 tests: routes, audit, UI data flow, correlation
├── migration-attestation.sql     # DB schema: attestation columns + history table
└── reset-attestation.sql         # Reset script for testing

workload-identity-ui/src/
├── pages/
│   ├── Dashboard.jsx             # Trust distribution, OWASP mapping, posture ring
│   └── Workloads.jsx             # Table, detail panel, attestation narrative, audit log
└── utils/
    └── enrichment.js             # Client-side score/risk/shadow correlation
```