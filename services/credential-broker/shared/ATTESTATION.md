# Workload Attestation — How WID Proves Identity

## Why Attestation Matters

Every workload in a modern enterprise — containers, VMs, Lambda functions, AI agents — needs a verifiable identity before it can be trusted. Static credentials (API keys, service account JSON files) are the #1 attack vector for lateral movement. Attestation replaces "I have the right password" with "I can cryptographically prove who I am."

WID's attestation system ensures that:
- **No workload communicates without proof of identity** — zero-trust default
- **Trust is graduated, not binary** — cryptographic proof earns more privilege than self-declaration
- **Proof has a shelf life** — tokens expire, requiring continuous re-attestation
- **Every attestation event is auditable** — full chain of evidence for compliance

---

## Trust Tier Model

WID enforces a strict 4-tier trust hierarchy. Higher tiers unlock more privilege (longer token TTLs, access to sensitive resources):

| Tier | Trust Level | Methods | TTL |
|------|-------------|---------|-----|
| **1 — Cryptographic** | `cryptographic` | SPIRE X.509 SVID, GCP metadata JWT (JWKS-verified), AWS IMDSv2 signed document, Azure MSI signed JWT, mTLS | 1 hour |
| **2 — Token-Based** | `high` | JWT/OIDC verified, GitHub Actions OIDC, Vault token introspection, K8s TokenReview, AWS STS identity | 30 min |
| **3 — Attribute-Based** | `medium` | Multi-signal ABAC (3+ runtime attributes), container verification (image digest + labels), process attestation (binary hash + cgroup), network verification (source IP range) | 15 min |
| **4 — Policy/Manual** | `low` | Service catalog match, OPA/Rego evaluation, manual operator approval | 5 min |

**Key principle**: The system tries the highest-tier method first and falls back gracefully. If cryptographic proof is unavailable (e.g., no SPIRE agent), it aggregates weaker signals and exposes the confidence level so operators can make informed risk decisions.

---

## How It Works

### Step 1: Evidence Collection

When a workload is discovered (via cloud scanner, container scanner, or registration), the attestation engine collects evidence from multiple sources:

**SPIRE (if available)**
- Attempts to verify the workload via the SPIRE API (`POST /svid/verify`)
- Tries multiple SPIFFE ID patterns: `spiffe://{trust-domain}/workload/{name}`, `spiffe://{trust-domain}/agents/{name}`, `spiffe://{trust-domain}/services/{name}`
- If SPIRE confirms the registration, the workload gets Tier 1 cryptographic trust immediately

**Cloud-Native Metadata**
- **GCP**: Fetches identity token from `http://metadata.google.internal/computeMetadata/v1/` targeted at the workload's service URL. Verifies JWT signature against Google's JWKS endpoint.
- **AWS**: Uses IMDSv2 to fetch the signed instance identity document + PKCS7 signature. Verifies against AWS public certificates. Falls back to STS `GetCallerIdentity` for Tier 2.
- **Azure**: Fetches MSI token and attested instance metadata. Verifies JWT signature against Entra ID JWKS for the tenant.

**Self-Evidence (Cross-Platform)**
- If the discovery service runs on the same platform as the workload (e.g., both on GCP Cloud Run), it uses its own platform credentials to verify the peer workload's identity

### Step 2: Multi-Method Evaluation

The attestation engine runs all applicable methods for the workload's type and cloud provider:

```
AWS EC2:         aws-imdsv2-signed, aws-sts-identity, catalog-match, abac-multi-signal
GCP Cloud Run:   gcp-metadata-jwt, catalog-match, abac-multi-signal
Azure VM:        azure-msi-signed, catalog-match, abac-multi-signal
Kubernetes:      k8s-token-review, spiffe-x509-svid, container-verified
Docker:          container-verified, process-attested, network-verified
```

Each method returns: `{ success, trust_level, claims, timestamp }`

The engine selects the **highest trust level achieved**. If 3+ methods pass, a multi-signal bonus bumps trust by one level (e.g., medium → high).

### Step 3: Trust Correlation

The attestation result is correlated with the workload's security posture:

- **Security score floor**: Cryptographic trust guarantees a minimum score of 90/100. Lower tiers have lower floors (high=70, medium=55, low=40).
- **Bonuses**: Multiple methods passed (+5), no static credentials (+5)
- **Penalties**: No owner assigned (-10), no team (-5), stale credentials (-5), credentials not in Vault (-10)
- **Shadow detection**: Cryptographic trust automatically clears shadow status. Lower trust levels may flag the workload as shadow if it lacks ownership metadata.

### Step 4: WID Token Issuance

If attestation succeeds and no manual review is required, a WID token is issued:

```json
{
  "alg": "HS256",
  "typ": "WID-TOKEN"
}
.
{
  "iss": "wid-platform://wid-platform",
  "sub": "spiffe://wid-platform/workload/servicenow-it-agent",
  "aud": "wid-gateway://wid-platform",
  "exp": 1709603600,
  "jti": "wid-1709600000-abc123",
  "wid": {
    "workload_name": "servicenow-it-agent",
    "trust_level": "cryptographic",
    "attestation_method": "gcp-metadata-jwt",
    "is_ai_agent": true,
    "attestation_chain": [
      { "method": "gcp-metadata-jwt", "trust": "cryptographic", "tier": 1 }
    ]
  }
}
```

The token encodes the attestation method and trust level so downstream policy decisions can gate access based on proof strength.

### Step 5: Continuous Re-Attestation

Tokens and attestations have TTLs based on trust level. A scheduled process (`POST /api/v1/workloads/continuous-attest`) re-attests workloads approaching expiry (within 20% of TTL). This ensures:
- Trust doesn't go stale
- Compromised workloads are detected when re-attestation fails
- Token rotation happens automatically

---

## Manual Review Gating

Not all workloads can be auto-attested. The engine flags workloads for manual review when:
- No attestation method passed
- Only low-trust methods succeeded
- The workload is a shadow service without high-trust verification
- An AI agent lacks platform credentials and has no cryptographic attestation

Manual approval requires an `approved_by` actor and `reason`, both logged to the audit trail.

---

## Integration with the Graph

Attestation results flow directly into the identity graph:

1. `trust_level` determines the node's visual ring color (green=cryptographic, blue=high, amber=medium, orange=low, red=none)
2. `security_score` affects the node's risk assessment and attack path severity
3. `is_shadow` determines whether the node shows the shadow indicator (gray dashed border)
4. The WID token is used by edge gateways during policy evaluation — unattested tokens are rejected

---

## Audit Trail

Every attestation event is logged to three tables:
- **attestation_history**: Full result including methods attempted/passed/failed, trust level, expiry
- **audit_events**: System-wide event log (type: `workload-attested`)
- **wid_tokens**: Token lifecycle (issued, revoked, superseded, expired)

This provides deterministic replay capability — any attestation decision can be reconstructed from the evidence chain.

---

## Example: GCP Cloud Run Agent

```
1. Discovery: GCP scanner finds servicenow-it-agent Cloud Run service
2. Evidence:  Fetch identity token from GCP metadata server
3. Verify:    JWT signature validated against Google JWKS → cryptographic trust
4. Score:     Security score: max(baseline, 90) - penalties = 85
5. Token:     Issue WID-TOKEN with TTL 3600s, sub=spiffe://wid-platform/workload/servicenow-it-agent
6. Graph:     Node rendered with green ring (cryptographic), score 85
7. Gateway:   Agent presents token on each API call → policy evaluation uses trust_level
8. Expiry:    After 50 minutes (80% of TTL), continuous-attest re-runs the flow
```
