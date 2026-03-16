# ADR-011: Remediation Decision Framework

**Status**: Accepted
**Date**: 2026-03-05
**Authors**: WID Platform Team

---

## Context

WID discovers security findings across customer cloud environments (AWS/GCP/Azure/K8s).
Each finding needs a remediation path, but **WID has read-only cloud access** and can only
enforce policy at the edge gateway (allow/deny traffic decisions).

The original implementation used three remediation types (`policy`, `direct`, `notify`),
which collapsed fundamentally different execution contexts into a single axis. This caused:

- Policy templates recommended for findings WID cannot enforce (e.g., "Stale Credential
  Lifecycle" for an orphaned firewall rule)
- CLI/Terraform commands shown without distinguishing who executes them
- No mechanism for risk acceptance, vendor coordination, or progress tracking

In production, customers will connect clouds with thousands of identities. The remediation
framework must handle the full spectrum of real-world scenarios.

---

## Decision

### 1. Six Remediation Execution Modes

Replace the 3-value `remediation_type` with a 6-category taxonomy based on **who executes
the remediation** and **what capability is required**:

| Code | Label | Executor | WID's Role | UI Treatment |
|------|-------|----------|------------|--------------|
| `policy` | Policy Enforcement | WID edge gateway | Enforce allow/deny | SIM → AUDIT → ENFORCE stepper |
| `iac` | IAM / Access Change | Customer cloud admin | Provide CLI/Terraform runbook | CLI commands with copy button |
| `infra` | Infrastructure Change | Customer infra team | Provide Terraform/CLI runbook | Infrastructure change guide |
| `code_change` | Application Change | Customer dev team | Provide migration guide | Code change guide with steps |
| `vendor` | Vendor Action | External vendor (Stripe, GitHub, etc.) | Track completion | Vendor instructions + status |
| `process` | Organizational Process | Customer org (manager, security lead) | Orchestrate workflow | Ticket creation + SLA tracking |

Cross-cutting concerns (apply to any category):
- `suppress` — Risk acceptance or false positive, with mandatory reason and expiry
- `hybrid` — Multiple categories combined (e.g., `policy` + `iac` for full remediation)

### 2. Decision Routing Logic

```
Finding → Determine remediation_type:

1. Can WID gateway gate the traffic for this finding?
   ├── YES: Is the finding about access control (auth, scope, delegation)?
   │   ├── YES → remediation_type = 'policy'
   │   │   Prerequisites: edge-gateway-deployed, policy-engine-reachable
   │   └── NO → Continue to step 2
   └── NO → Continue to step 2

2. Does remediation require changing IAM permissions/roles/trust policies?
   ├── YES → remediation_type = 'iac'
   │   Examples: remove wildcard permissions, add permission boundary,
   │             split shared SA, restrict cross-account trust
   └── NO → Continue to step 3

3. Does remediation require infrastructure changes?
   ├── YES → remediation_type = 'infra'
   │   Examples: delete firewall rule, enable encryption, restrict SG ingress,
   │             move to private subnet, enable backup/PITR
   └── NO → Continue to step 4

4. Does remediation require application code changes?
   ├── YES → remediation_type = 'code_change'
   │   Examples: migrate to OAuth 2.1, implement agent card signing,
   │             add delegation chain, integrate SPIRE attestation
   └── NO → Continue to step 5

5. Does remediation require action by an external vendor?
   ├── YES → remediation_type = 'vendor'
   │   Examples: rotate Stripe API key, revoke GitHub PAT,
   │             request OAuth scope change from SaaS provider
   └── NO → Continue to step 6

6. Does remediation require organizational process?
   └── YES → remediation_type = 'process'
       Examples: assign resource owner, conduct access review,
                 compliance certification, executive risk sign-off
```

### 3. Approval Tiers (blast-radius gated)

| Condition | Approval Required |
|-----------|------------------|
| `policy` type + blast_radius < 5 + reversible | None (auto) |
| `policy` type + blast_radius < 5 + non-reversible | Owner approval |
| Any type + blast_radius 5-50 | Team lead approval |
| Any type + blast_radius > 50 | Security team + change ticket |
| `iac` or `infra` + non-reversible (delete/revoke) | Dual approval always |
| Compliance-mapped (SOX, PCI-DSS) | Dual approval always |

### 4. Urgency Tiers

| Urgency | Trigger | Max Time to Start |
|---------|---------|-------------------|
| `immediate` | Active exploitation, key leak, critical + high blast | 15 minutes |
| `next_window` | Critical/high severity, no active exploit | 24 hours |
| `sprint` | Medium severity, architectural changes | 2 weeks |
| `deferred` | Low severity, unused/stale resources | 90 days |

### 5. Prerequisites

Each control can declare prerequisites that must be met before remediation is possible:

| Prerequisite | Meaning |
|-------------|---------|
| `edge-gateway-deployed` | WID gateway must be deployed for this workload |
| `spire-available` | SPIRE agent must be running in the workload's environment |
| `policy-engine-deployed` | Policy engine must be reachable from the gateway |
| `terraform-managed` | Resource must be in Terraform state for IaC remediation |
| `owner-identified` | Resource must have an assigned owner |
| `vendor-api-available` | Vendor must have API for programmatic credential rotation |

When prerequisites are not met, the UI should show them as blockers with instructions
to resolve, rather than hiding the control or showing a broken "Deploy" button.

---

## Mapping: action_type → remediation_type

The existing `action_type` values map to `remediation_type` as follows:

| action_type | Default remediation_type | Notes |
|-------------|------------------------|-------|
| `policy` | `policy` | WID gateway can enforce |
| `replace` | `policy` or `code_change` | Depends on whether gateway can swap credentials |
| `harden` | `iac` or `infra` | Depends on what's being hardened |
| `remediate` | `iac` or `infra` | Depends on the target resource |
| `architecture` | `code_change` | Requires structural code/infra changes |
| `contain` | `iac` | Emergency IAM changes (disable SA, deny-all) |
| `decommission` | `iac` or `infra` | Delete the resource/identity |
| `notify` | `process` | Human triage, no automated fix |
| `escalate` | `process` | Security incident escalation |
| `investigate` | `process` | Human judgment required |
| `governance` | `process` | Compliance registration/certification |

**Important**: `action_type` describes WHAT to do. `remediation_type` describes HOW/WHO.
A single `action_type` can map to different `remediation_type` values depending on context.

---

## Real Production Scenarios

### Scenario 1: Customer connects GCP with 2000 service accounts
- 80% are stale/unused → `process` (assign owners) → `iac` (delete after grace period)
- Need bulk remediation campaigns, not 2000 individual clicks
- Future: bulk campaign workflow with progress tracking

### Scenario 2: Customer has cross-account AWS trust without ExternalId
- `iac` — customer must update IAM trust policy via CLI/Terraform
- WID provides the exact `aws iam update-assume-role-policy` command
- If gateway is deployed, can also add `policy` to deny cross-account calls without ExternalId

### Scenario 3: Customer's CI/CD uses hardcoded Stripe key
- `vendor` — Stripe key rotation requires Stripe dashboard or API
- `code_change` — app must migrate to environment variable or vault
- `policy` — gateway can deny the old key once new one is active
- This is a `hybrid`: vendor + code_change + policy in sequence

### Scenario 4: Orphaned firewall rule (the original bug)
- `infra` — requires `gcloud compute firewall-rules delete`
- WID has read-only access, cannot delete it
- UI should show CLI commands, NOT "Deploy policy"
- `process` first if owner unknown (assign owner → then infra team deletes)

### Scenario 5: Shadow AI agent calling OpenAI directly
- If gateway deployed: `policy` — deny direct OpenAI calls, require LLM gateway
- If no gateway: `code_change` — developer must route through approved proxy
- `process` — register AI usage in governance inventory

---

## Consequences

### Positive
- UI accurately represents what the user needs to do
- No more "Deploy policy" buttons for findings WID can't enforce
- Clear ownership: who does the work?
- Prerequisite awareness: don't offer actions that can't succeed
- Foundation for future approval workflows and bulk campaigns

### Negative
- More categories means more UI states to test
- `remediation_type` must be set correctly per control (manual review needed)
- Some controls are genuinely hybrid — need to model sequences

### Risks
- Over-categorization could confuse users → mitigate with clear UI badges
- Production findings may not fit neatly into categories → mitigate with `hybrid` and fallback

---

## Implementation

1. Update `CONTROL_CATALOG` in `graph-routes.js` with corrected `remediation_type` values
2. Update frontend `CONTROL_CATALOG_FALLBACK` in `GraphPage.jsx`
3. Update `ControlCard` component to render all 6 categories correctly
4. Fix wrong `template_id` mappings (remove template_id from non-policy controls)
5. Add `remediation_type` badge with distinct colors per category in the UI
