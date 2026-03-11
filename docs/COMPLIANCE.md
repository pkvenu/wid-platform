# WID Platform — Compliance Policy Packs

> Version 1.0 | March 2026
> Maps 125 policy templates to 5 compliance frameworks with 68 controls.

---

## Overview

WID ships pre-built **Compliance Policy Packs** — curated sets of policy templates mapped to industry compliance frameworks. Each template enforces a specific security control for workload identities, AI agents, credentials, and network boundaries.

**Key capabilities:**
- 5 frameworks: SOC 2, PCI DSS, NIST 800-53, ISO 27001, EU AI Act
- 125 of 133 templates mapped to at least one framework
- One-click deploy: deploy all policies for a framework in `audit` mode
- Coverage tracking: real-time % of deployed vs. available policies per control
- Control-level granularity: drill down into which templates satisfy each control

**API endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/compliance/frameworks` | List all frameworks with coverage stats |
| GET | `/api/v1/compliance/frameworks/:id` | Framework detail with all mapped templates |
| POST | `/api/v1/compliance/frameworks/:id/deploy` | Deploy all undeployed templates (audit mode) |
| GET | `/api/v1/compliance/frameworks/:id/coverage` | Coverage breakdown by control |

**Frontend:** `/compliance` page with framework cards, detail view, and deploy workflow.

---

## Frameworks

### SOC 2 Type II

**ID:** `SOC2` | **Standard:** AICPA Trust Services Criteria
**Templates:** 124 | **Controls:** 10

SOC 2 is the most broadly covered framework. Nearly all WID templates map to at least one SOC 2 control, reflecting the standard's comprehensive coverage of access controls, monitoring, and change management.

| Control | Description | Templates |
|---------|-------------|-----------|
| CC6.1 | Logical and Physical Access Controls | 41 |
| CC6.2 | Prior to Issuing System Credentials and Granting System Access | 3 |
| CC6.3 | Access Based on Authorization | 44 |
| CC6.6 | System Boundaries and Threat Protection | 21 |
| CC6.7 | Restricts Transmission, Movement, and Removal of Information | 7 |
| CC6.8 | Controls Against Unauthorized or Malicious Software | 8 |
| CC7.1 | Detect and Monitor Anomalies and Events | 8 |
| CC7.2 | Monitor System Components for Anomalies | 9 |
| CC8.1 | Changes to Infrastructure, Data, Software, and Procedures | 3 |
| CC9.1 | Risk Mitigation Activities | 8 |

<details>
<summary><strong>CC6.1 — Logical and Physical Access Controls (41 templates)</strong></summary>

- A2A Agent Authentication Required
- A2A Agent Card Must Be Signed
- AI Agent Requires Human Delegator
- AI Endpoint Authentication Required
- Admin Roles Require Cryptographic Attestation
- Agent Consent Expiry (24 Hours)
- Agent Session TTL Limit
- Attested Clients Only for Production Resources
- CI/CD Must Use OIDC Federation
- Certificate Expiry Warning (30 Days)
- Credential Expiry Enforcement
- Credential Rotation Overdue
- Cryptographic Attestation Required
- Database IAM Authentication Required
- Improper Offboarding Detection
- Inactivity Timeout (30 Days)
- JIT Credential Request Allowed
- JIT Credential Required for External APIs
- JIT Token Maximum TTL (5 Minutes)
- KMS Key Rotation Required
- Long-Lived API Key Detection
- MCP OAuth 2.1 Required
- MCP OAuth Discovery Endpoint Validation
- MCP Server Static Credential Ban
- MCP Session Integrity Protection
- Maximum Credential Age (365 Days)
- Minimum Trust Level for Production
- No Production Credentials in PR Builds
- OBO Chain Must Originate from Human
- OBO Token TTL Shortening per Hop
- Owner Required for All Identities
- Production Attestation Required
- Runtime Posture Check
- SPIFFE Identity Required in Production
- Secret Engine Audit
- Secret Rotation Required
- Shadow Identity Detection
- Shared Service Account Prohibition
- Stale Credential Lifecycle
- Third-Party NHI Quarterly Review
- User-Managed Key Prohibition

</details>

<details>
<summary><strong>CC6.2 — Prior to Issuing System Credentials (3 templates)</strong></summary>

- Improper Offboarding Detection
- NHI Naming Convention Required
- Owner Required for All Identities

</details>

<details>
<summary><strong>CC6.3 — Access Based on Authorization (44 templates)</strong></summary>

- AI Agents Can Use MCP Servers
- Admin Roles Require Cryptographic Attestation
- Agent Confused Deputy Prevention
- Agent MCP Tool Whitelist
- Agent Scope Ceiling Enforcement
- Agent-to-Agent Delegation
- Attested Clients Only for Production Resources
- Block Cross-Environment Access
- Block Untrusted Agent Invocation
- Business Hours Access Only
- Cross-Account Access Restriction
- Cross-Account Requires External ID
- Cross-Account Trust Policy Review
- Cryptographic Attestation Required
- Detect Human Use of Service Account
- Editor/Writer Role Prohibited in Production
- Environment Credential Isolation
- Excessive Resource Access
- Geo-Restricted Access
- GitHub MCP Token Over-Privilege Prevention
- Human-in-Loop for Sensitive Operations
- JIT Credential Scoped Per Request
- MCP Server Tool Least Privilege
- MCP Token Passthrough Prohibition
- Minimum Trust Level for Production
- Minimum Trust Level for Production Access
- Multi-Tool Operation Requires Approval
- No Wildcard Permissions
- OBO Scope Must Narrow at Each Hop
- PII Data Access Restriction
- Permission Boundary Required
- Privilege Escalation Detection
- Production Attestation Required
- Require Authorized Delegation Chain
- Restrict IAM PassRole
- Restrict Trust Policy Principals
- Runtime Posture Check
- Sensitive Access Requires Approval
- Shared SA External Access Block
- Shared Service Account Prohibition
- Toxic Combo: Code Repository + Infrastructure Admin
- Toxic Combo: Financial + CRM Credential Separation
- Unused Permissions Cleanup
- Users Can Invoke AI Agents

</details>

<details>
<summary><strong>CC6.6 — System Boundaries and Threat Protection (21 templates)</strong></summary>

- AI Endpoints VPC-Only Access
- API Rate Limit Enforcement
- Block AI Agent Direct External API Access
- Block Cross-Environment Access
- Cross-Account Trust Policy Review
- Geo-Restricted Access
- IDE MCP Integration Sandbox Required
- Internal Service Mesh Access
- Internal Service Network Isolation
- LLM Gateway Enforcement
- MCP Localhost Exposure Prevention
- MCP Server Localhost Binding Required
- MCP Server URI/SSRF Validation
- Private Subnet Required
- Public AI Endpoint Lockdown
- Public Bucket Access Denied
- Public Database Access Denied
- Public Endpoint Requires Authentication
- Public Resource Requires Security Approval Tag
- Restrict Security Group Public Ingress
- Restrict Unapproved Public Access

</details>

<details>
<summary><strong>CC6.7 — Restricts Transmission of Information (7 templates)</strong></summary>

- Agent Data Loss Prevention
- Encryption at Rest Required
- PII Data Access Restriction
- Plaintext Secrets in Environment Variables
- Public Bucket Access Denied
- Secret Leakage in Logs Detection

</details>

<details>
<summary><strong>CC6.8 — Controls Against Unauthorized Software (8 templates)</strong></summary>

- Agent Privileged Input Isolation
- Git MCP Prompt Injection Guard
- MCP Command Injection Prevention
- MCP Database Query Parameterization
- MCP Server Registry Verification
- MCP Tool Description Sanitization
- MCP Tool Poisoning Prevention

</details>

<details>
<summary><strong>CC7.1 — Detect and Monitor Anomalies (8 templates)</strong></summary>

- Agent Kill Switch Required
- Anomalous Access Pattern Detection
- Detect Human Use of Service Account
- Low Security Score Quarantine
- Privilege Escalation Detection
- Secret Leakage in Logs Detection
- Shadow AI Detection
- Shadow Identity Detection

</details>

<details>
<summary><strong>CC7.2 — Monitor System Components (9 templates)</strong></summary>

- AI Endpoint Registration Required
- AI Permission Audit
- Agent Action Attribution Required
- Anomalous Access Pattern Detection
- Chain Depth Limit (Max 3 Hops)
- OBO Delegation Chain Max Depth
- Require Authorized Delegation Chain
- Require Known Chain Origin
- Secret Engine Audit

</details>

<details>
<summary><strong>CC8.1 — Changes to Infrastructure and Software (3 templates)</strong></summary>

- CI/CD Must Use OIDC Federation
- No Production Credentials in PR Builds
- Weekday-Only Deployments

</details>

<details>
<summary><strong>CC9.1 — Risk Mitigation Activities (8 templates)</strong></summary>

- AI Daily Cost Limit
- AI Daily Request Limit
- AI Provider Restriction
- Backup and PITR Required
- Low Security Score Quarantine
- Third-Party NHI Quarterly Review
- Toxic Combo: Code Repository + Infrastructure Admin
- Toxic Combo: Financial + CRM Credential Separation

</details>

---

### PCI DSS v4.0

**ID:** `PCI_DSS` | **Standard:** Payment Card Industry Data Security Standard
**Templates:** 45 | **Controls:** 13 (10 with mapped templates)

PCI DSS coverage focuses on access control (Req 7), authentication (Req 8), and audit logging (Req 10). Templates enforce credential rotation, least-privilege access, and encryption for cardholder data environments.

| Control | Description | Templates |
|---------|-------------|-----------|
| 3.5 | Primary Account Number (PAN) Secured Wherever Stored | 5 |
| 7.1 | Access to System Components and Data Restricted | 15 |
| 7.2 | Access Appropriately Defined and Assigned | 5 |
| 8.1 | User Identification and Related Accounts Managed | 4 |
| 8.2 | Authentication Credential Rotation | 1 |
| 8.2.4 | Authentication Credential Rotation | 5 |
| 8.3 | Strong Authentication for Users and Administrators | 4 |
| 8.6 | Use of Application and System Accounts Managed | 5 |
| 10.1 | Audit Trails Established and Active | 2 |
| 10.2 | Audit Logs Record User Activities | 3 |

<details>
<summary><strong>7.1 — Access to System Components and Data Restricted (15 templates)</strong></summary>

- Attested Clients Only for Production Resources
- Block Cross-Environment Access
- Cross-Account Access Restriction
- Cross-Account Trust Policy Review
- Geo-Restricted Access
- Minimum Trust Level for Production
- Minimum Trust Level for Production Access
- PII Data Access Restriction
- Private Subnet Required
- Production Attestation Required
- Public Bucket Access Denied
- Public Database Access Denied
- Public Endpoint Requires Authentication
- Restrict Security Group Public Ingress
- Sensitive Access Requires Approval

</details>

<details>
<summary><strong>8.2.4 — Authentication Credential Rotation (5 templates)</strong></summary>

- Credential Expiry Enforcement
- Credential Rotation Overdue
- KMS Key Rotation Required
- Long-Lived API Key Detection
- Secret Rotation Required

</details>

<details>
<summary><strong>8.6 — Application and System Accounts Managed (5 templates)</strong></summary>

- JIT Credential Required for External APIs
- MCP Server Static Credential Ban
- Shared SA External Access Block
- Shared Service Account Prohibition
- User-Managed Key Prohibition

</details>

---

### NIST 800-53 Rev 5

**ID:** `NIST_800_53` | **Standard:** Security and Privacy Controls for Information Systems
**Templates:** 122 | **Controls:** 19 (16 with mapped templates)

NIST 800-53 is the second most comprehensive mapping. Templates span Access Control (AC), Audit (AU), Identification & Authentication (IA), System Communications (SC), and System Information Integrity (SI) families.

| Control | Description | Templates |
|---------|-------------|-----------|
| AC-2 | Account Management | 15 |
| AC-3 | Access Enforcement | 27 |
| AC-4 | Information Flow Enforcement | 7 |
| AC-6 | Least Privilege | 21 |
| AU-2 | Event Logging | 1 |
| AU-3 | Content of Audit Records | 4 |
| AU-6 | Audit Record Review, Analysis, and Reporting | 1 |
| CA-7 | Continuous Monitoring | 4 |
| CM-3 | Configuration Change Control | 5 |
| IA-2 | Identification and Authentication | 12 |
| IA-4 | Identifier Management | 3 |
| IA-5 | Authenticator Management | 14 |
| IA-8 | Identification and Authentication (Non-Org Users) | 1 |
| IR-4 | Incident Handling | 4 |
| SC-7 | Boundary Protection | 18 |
| SC-8 | Transmission Confidentiality and Integrity | 3 |
| SC-12 | Cryptographic Key Establishment and Management | 8 |
| SI-4 | System Monitoring | 11 |

<details>
<summary><strong>AC-3 — Access Enforcement (27 templates)</strong></summary>

- AI Agents Can Use MCP Servers
- Agent Confused Deputy Prevention
- Agent-to-Agent Delegation
- Attested Clients Only for Production Resources
- Block Cross-Environment Access
- Block Untrusted Agent Invocation
- Business Hours Access Only
- Cross-Account Access Restriction
- Cross-Account Requires External ID
- Cross-Account Trust Policy Review
- Geo-Restricted Access
- Human-in-Loop for Sensitive Operations
- MCP Token Passthrough Prohibition
- Minimum Trust Level for Production
- Minimum Trust Level for Production Access
- Multi-Tool Operation Requires Approval
- No Production Credentials in PR Builds
- PII Data Access Restriction
- Production Attestation Required
- Public Bucket Access Denied
- Public Database Access Denied
- Public Endpoint Requires Authentication
- Require Authorized Delegation Chain
- Restrict Trust Policy Principals
- Runtime Posture Check
- Sensitive Access Requires Approval
- Users Can Invoke AI Agents

</details>

<details>
<summary><strong>AC-6 — Least Privilege (21 templates)</strong></summary>

- Admin Roles Require Cryptographic Attestation
- Agent MCP Tool Whitelist
- Agent Scope Ceiling Enforcement
- Chain Depth Limit (Max 3 Hops)
- Editor/Writer Role Prohibited in Production
- Excessive Resource Access
- GitHub MCP Token Over-Privilege Prevention
- JIT Credential Scoped Per Request
- MCP Server Tool Least Privilege
- No Wildcard Permissions
- OBO Delegation Chain Max Depth
- OBO Scope Must Narrow at Each Hop
- Permission Boundary Required
- Privilege Escalation Detection
- Restrict IAM PassRole
- Revoke Unused AI Permissions
- Shared SA External Access Block
- Shared Service Account Prohibition
- Toxic Combo: Code Repository + Infrastructure Admin
- Toxic Combo: Financial + CRM Credential Separation
- Unused Permissions Cleanup

</details>

<details>
<summary><strong>SC-7 — Boundary Protection (18 templates)</strong></summary>

- AI Endpoints VPC-Only Access
- API Rate Limit Enforcement
- Block AI Agent Direct External API Access
- IDE MCP Integration Sandbox Required
- Internal Service Mesh Access
- Internal Service Network Isolation
- LLM Gateway Enforcement
- MCP Localhost Exposure Prevention
- MCP Server Localhost Binding Required
- MCP Server URI/SSRF Validation
- Private Subnet Required
- Public AI Endpoint Lockdown
- Public Bucket Access Denied
- Public Database Access Denied
- Public Endpoint Requires Authentication
- Public Resource Requires Security Approval Tag
- Restrict Security Group Public Ingress
- Restrict Unapproved Public Access

</details>

<details>
<summary><strong>SI-4 — System Monitoring (11 templates)</strong></summary>

- Agent Privileged Input Isolation
- Anomalous Access Pattern Detection
- Detect Human Use of Service Account
- Git MCP Prompt Injection Guard
- MCP Command Injection Prevention
- MCP Database Query Parameterization
- MCP Tool Description Sanitization
- MCP Tool Poisoning Prevention
- Privilege Escalation Detection
- Shadow AI Detection
- Shadow Identity Detection

</details>

---

### ISO 27001:2022

**ID:** `ISO_27001` | **Standard:** Information Security Management System
**Templates:** 71 | **Controls:** 17 (15 with mapped templates)

ISO 27001 mapping covers Annex A controls across access control (A.5.15-A.5.18), privileged access (A.8.2), cryptography (A.8.24), and monitoring (A.8.16).

| Control | Description | Templates |
|---------|-------------|-----------|
| A.5.15 | Access Control | 17 |
| A.5.16 | Identity Management | 5 |
| A.5.17 | Authentication Information | 5 |
| A.5.23 | Information Security for Cloud Services | 4 |
| A.5.33 | Protection of Records | 2 |
| A.8.2 | Privileged Access Rights | 10 |
| A.8.3 | Information Access Restriction | 9 |
| A.8.5 | Secure Authentication | 11 |
| A.8.9 | Configuration Management | 3 |
| A.8.15 | Logging | 2 |
| A.8.16 | Monitoring Activities | 6 |
| A.8.24 | Use of Cryptography | 9 |
| A.9.2.1 | User Registration and De-registration | 3 |
| A.9.2.6 | Removal or Adjustment of Access Rights | 5 |
| A.9.4.3 | Password Management System | 2 |

<details>
<summary><strong>A.5.15 — Access Control (17 templates)</strong></summary>

- AI Endpoints VPC-Only Access
- API Rate Limit Enforcement
- Attested Clients Only for Production Resources
- Block Cross-Environment Access
- Business Hours Access Only
- Cross-Account Trust Policy Review
- Geo-Restricted Access
- MCP Server Localhost Binding Required
- Minimum Trust Level for Production
- Minimum Trust Level for Production Access
- Private Subnet Required
- Production Attestation Required
- Public Endpoint Requires Authentication
- Public Resource Requires Security Approval Tag
- Restrict Security Group Public Ingress
- Restrict Unapproved Public Access
- Runtime Posture Check

</details>

<details>
<summary><strong>A.8.2 — Privileged Access Rights (10 templates)</strong></summary>

- Admin Roles Require Cryptographic Attestation
- Detect Human Use of Service Account
- Editor/Writer Role Prohibited in Production
- Excessive Resource Access
- No Wildcard Permissions
- Permission Boundary Required
- Privilege Escalation Detection
- Restrict IAM PassRole
- Restrict Trust Policy Principals
- Shared Service Account Prohibition

</details>

<details>
<summary><strong>A.8.5 — Secure Authentication (11 templates)</strong></summary>

- A2A Agent Authentication Required
- AI Endpoint Authentication Required
- Admin Roles Require Cryptographic Attestation
- Attested Clients Only for Production Resources
- CI/CD Must Use OIDC Federation
- Cryptographic Attestation Required
- Database IAM Authentication Required
- MCP OAuth 2.1 Required
- Minimum Trust Level for Production
- Production Attestation Required
- SPIFFE Identity Required in Production

</details>

<details>
<summary><strong>A.8.24 — Use of Cryptography (9 templates)</strong></summary>

- A2A Agent Card Must Be Signed
- Certificate Expiry Warning (30 Days)
- Cryptographic Attestation Required
- Encryption at Rest Required
- KMS Key Rotation Required
- Plaintext Secrets in Environment Variables
- Secret Engine Audit
- Secret Rotation Required
- User-Managed Key Prohibition

</details>

---

### EU AI Act

**ID:** `EU_AI_ACT` | **Standard:** European Union AI Systems Regulation
**Templates:** 37 | **Controls:** 9 (8 with mapped templates)
**Effective:** August 2, 2026

The EU AI Act mapping is uniquely relevant for organizations deploying AI agents. Templates enforce human oversight (Art. 14), traceability (Art. 12), risk management (Art. 9), and cybersecurity (Art. 15). This is the only compliance framework that addresses AI-specific threats like confused deputy attacks, prompt injection, and agent delegation chains.

| Control | Description | Templates |
|---------|-------------|-----------|
| Art.9 | Risk Management System | 12 |
| Art.12 | Record-Keeping and Traceability | 7 |
| Art.13 | Transparency and Information to Deployers | 1 |
| Art.14 | Human Oversight | 10 |
| Art.15 | Accuracy, Robustness, and Cybersecurity | 7 |
| Art.17 | Quality Management System | 5 |
| Art.26 | Obligations of Deployers | 3 |
| Art.72 | Monitoring and Reporting of Serious Incidents | 1 |

<details>
<summary><strong>Art.9 — Risk Management System (12 templates)</strong></summary>

- AI Agents Can Use MCP Servers
- AI Daily Cost Limit
- AI Daily Request Limit
- AI Provider Restriction
- Agent Kill Switch Required
- Agent MCP Tool Whitelist
- Agent Scope Ceiling Enforcement
- Agent Session TTL Limit
- Block AI Agent Direct External API Access
- Block Untrusted Agent Invocation
- LLM Gateway Enforcement
- OBO Scope Must Narrow at Each Hop

</details>

<details>
<summary><strong>Art.12 — Record-Keeping and Traceability (7 templates)</strong></summary>

- AI Permission Audit
- Agent Action Attribution Required
- Chain Depth Limit (Max 3 Hops)
- OBO Delegation Chain Max Depth
- Require Authorized Delegation Chain
- Require Known Chain Origin
- Revoke Unused AI Permissions

</details>

<details>
<summary><strong>Art.14 — Human Oversight (10 templates)</strong></summary>

- AI Agent Requires Human Delegator
- Agent Consent Expiry (24 Hours)
- Agent Kill Switch Required
- Agent Scope Ceiling Enforcement
- Agent-to-Agent Delegation
- Human-in-Loop for Sensitive Operations
- Multi-Tool Operation Requires Approval
- OBO Chain Must Originate from Human
- Require Known Chain Origin
- Users Can Invoke AI Agents

</details>

<details>
<summary><strong>Art.15 — Accuracy, Robustness, and Cybersecurity (7 templates)</strong></summary>

- Agent Confused Deputy Prevention
- Agent Privileged Input Isolation
- Git MCP Prompt Injection Guard
- MCP Token Passthrough Prohibition
- MCP Tool Description Sanitization
- MCP Tool Poisoning Prevention
- Public AI Endpoint Lockdown

</details>

<details>
<summary><strong>Art.17 — Quality Management System (5 templates)</strong></summary>

- AI Endpoint Registration Required
- AI Provider Restriction
- MCP Server Registry Verification
- Shadow AI Detection

</details>

<details>
<summary><strong>Art.26 — Obligations of Deployers (3 templates)</strong></summary>

- AI Agent Requires Human Delegator
- Agent Consent Expiry (24 Hours)
- OBO Chain Must Originate from Human

</details>

---

## Deployment Workflow

### One-Click Framework Deploy

```
POST /api/v1/compliance/frameworks/:id/deploy
```

Deploys all undeployed templates for a framework in **audit** mode (log-only, no blocking). This is the safe default — templates generate `WOULD_BLOCK` decisions visible in the Access Events page without disrupting workloads.

**Response:**
```json
{
  "deployed": 37,
  "skipped": 0,
  "errors": []
}
```

### Graduated Enforcement

After deploying in audit mode:
1. **Review** decisions in Access Events — identify false positives
2. **Tune** individual policies (adjust conditions, add exceptions)
3. **Promote** to `enforce` mode per-policy from the Policies page

This follows the Simulate → Audit → Enforce progression documented in SPEC.md.

### Coverage Tracking

```
GET /api/v1/compliance/frameworks/:id/coverage
```

Returns per-control coverage breakdown:
```json
{
  "total": 37,
  "deployed": 37,
  "coverage_pct": 100,
  "by_control": {
    "Art.9": { "total": 12, "deployed": 12, "templates": [...] },
    "Art.14": { "total": 10, "deployed": 10, "templates": [...] }
  }
}
```

---

## Cross-Framework Coverage Matrix

Templates frequently map to multiple frameworks. The table below shows how key policy categories span frameworks:

| Policy Category | SOC 2 | PCI DSS | NIST | ISO | EU AI Act |
|----------------|-------|---------|------|-----|-----------|
| Identity & Authentication | CC6.1 | 8.3, 8.6 | IA-2, IA-5 | A.8.5 | — |
| Access Control | CC6.3 | 7.1, 7.2 | AC-2, AC-3, AC-6 | A.5.15, A.8.2 | — |
| Network Boundaries | CC6.6 | — | SC-7 | A.5.15 | — |
| Credential Lifecycle | CC6.1 | 8.2.4 | IA-5, SC-12 | A.8.24, A.9.4.3 | — |
| Monitoring & Detection | CC7.1, CC7.2 | 10.1, 10.2 | AU-2, SI-4 | A.8.15, A.8.16 | Art.72 |
| AI Agent Controls | CC6.3, CC7.2 | — | AC-3, AC-6 | — | Art.9, Art.14 |
| Delegation Chains | CC7.2 | — | AU-3 | — | Art.12, Art.14 |
| MCP Security | CC6.8 | — | SI-4, CM-3 | — | Art.15, Art.17 |
| Data Protection | CC6.7 | 3.5 | AC-4 | A.8.3 | — |
| Change Management | CC8.1 | — | CM-3 | A.8.9 | — |

---

## Data Model

### Template compliance_frameworks field

Each policy template in `policy_templates` has a `compliance_frameworks` JSONB column:

```json
[
  { "framework": "SOC2", "controls": ["CC6.1", "CC6.3"] },
  { "framework": "NIST_800_53", "controls": ["AC-2", "AC-3"] },
  { "framework": "ISO_27001", "controls": ["A.9.2.1"] }
]
```

**Schema:**
```sql
ALTER TABLE policy_templates
  ADD COLUMN IF NOT EXISTS compliance_frameworks JSONB DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_policy_templates_compliance
  ON policy_templates USING GIN (compliance_frameworks);
```

The GIN index enables efficient `@>` containment queries for filtering templates by framework.

### Framework definitions

Framework metadata (control IDs, descriptions) is defined in:
`services/policy-sync-service/src/engine/compliance-frameworks.js`

Template-to-framework mappings are defined in:
`services/policy-sync-service/src/engine/templates.js`

---

## Files

| File | Purpose |
|------|---------|
| `services/policy-sync-service/src/engine/compliance-frameworks.js` | Framework definitions (5 frameworks, 68 controls) |
| `services/policy-sync-service/src/engine/templates.js` | 133 templates with `compliance_frameworks` mappings |
| `services/policy-sync-service/src/routes.js` | 4 compliance API endpoints |
| `database/schemas/002-policy-templates.sql` | Schema: `compliance_frameworks` JSONB column + GIN index |
| `web/workload-identity-manager/src/pages/Compliance.jsx` | Compliance dashboard page |
