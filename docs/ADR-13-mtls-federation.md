# ADR-13: mTLS Federation with SPIFFE SVIDs for Spoke Identity

**Status**: Accepted
**Date**: 2026-03-16
**Author**: WID Platform Team

---

## Context

WID uses a hub-and-spoke architecture where spoke relays run in customer environments (AWS, Azure, on-prem) and connect to a central GCP hub for policy sync, audit forwarding, and heartbeats.

**Current state**: Spoke relays authenticate using a static `CENTRAL_API_KEY` passed as a Bearer token. This has critical limitations:
- Shared secret — not unique per relay
- No mutual authentication — hub cannot cryptographically verify which spoke is connecting
- No per-relay revocation — revoking one relay requires rotating the global key
- No certificate-based identity — cannot bind relay identity to SPIFFE trust domain

**Threat**: Relay impersonation. An attacker with the API key can register as any environment and receive policies meant for other environments. Cross-tenant data could be exposed.

---

## Decision

Implement mTLS between spoke relays and the central hub using SPIFFE X.509 SVIDs (or WID-issued client certificates where SPIRE is unavailable).

### Components

1. **TLSManager** (`shared/data-plane-core/src/tls-manager.js`) — Certificate loading, SPIFFE ID extraction, file watching for rotation, mTLS agent creation
2. **Federation Routes** (`services/policy-sync-service/src/federation/federation-routes.js`) — Hub-side relay management: register, heartbeat, revoke, push, bootstrap
3. **Relay mTLS Client** — Updated relay httpRequest with mTLS agent, SPIFFE ID headers, webhook listener for policy push
4. **Spoke Relays Table** (`spoke_relays`) — DB-backed relay registry replacing in-memory Map
5. **Federation Events Table** (`federation_events`) — Audit trail for all federation actions
6. **Cross-Environment Trace Context** (`shared/data-plane-core/src/trace-context.js`) — Headers for propagating relay identity across spoke boundaries

### Certificate Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  Option A: SPIRE-based (recommended for production)              │
│                                                                   │
│  SPIRE Server ──▶ SPIRE Agent ──▶ Relay (SVID on disk/memory)   │
│  Trust bundle shared between hub and spoke SPIRE servers         │
│  Auto-rotation: 1h default TTL                                    │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  Option B: Bootstrap flow (for envs without SPIRE)               │
│                                                                   │
│  1. Admin generates one-time registration token                   │
│  2. Relay calls POST /api/v1/federation/bootstrap-cert            │
│  3. Hub's Federation CA signs a client cert with SPIFFE SAN       │
│  4. Relay saves cert/key, connects via mTLS                       │
│  5. Short-lived cert (24h), re-bootstrap on expiry                │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  Option C: API key fallback (backward compatible)                │
│                                                                   │
│  Relay connects with CENTRAL_API_KEY as before                    │
│  Federation routes accept both mTLS and API key auth              │
│  No SPIFFE ID, no cert fingerprint pinning                        │
└──────────────────────────────────────────────────────────────────┘
```

### Webhook Policy Push

Complements pull-based sync (15s interval) for urgent scenarios:
- Policy revocation (enforce mode)
- Emergency policy deployment
- Tenant suspension

Hub broadcasts to all active relays with webhook URLs. Push is signed with HMAC-SHA256. Receiver validates signature and timestamp (rejects >60s stale). Pull-based sync is the primary mechanism; push is an optimization.

### Cross-Environment Trace Linking

When a request traverses multiple spokes (AWS → GCP), trace headers propagate the origin relay identity:

```
X-WID-Origin-Relay: spiffe://wid-platform/relay/aws-east
X-WID-Origin-Environment: aws-us-east-1
X-WID-Relay-SPIFFE-ID: spiffe://wid-platform/relay/gcp-central
```

Audit events include `relay_spiffe_id` and `origin_relay_spiffe_id` for full cross-environment path reconstruction.

---

## Database Schema

### `spoke_relays` table
Replaces in-memory relay registry. Includes:
- mTLS identity: `spiffe_id`, `cert_fingerprint`, `cert_issuer`, `cert_not_before/after`
- Status lifecycle: `pending → active → stale → revoked`
- Webhook config: `webhook_url`, `webhook_enabled`
- Health snapshot: `policy_version`, `audit_buffer_size`, `adapter_count`, `uptime_seconds`
- Data sovereignty: `data_region`, `data_residency_strict`, `allowed_regions`
- Multi-tenant: `tenant_id` with RLS

### `federation_events` table
Audit trail for: `registered`, `heartbeat`, `cert_rotated`, `revoked`, `policy_pushed`, `auth_failed`, `stale_detected`

### Alterations to `ext_authz_decisions`
New columns: `relay_spiffe_id`, `origin_relay_spiffe_id`, `origin_environment`

---

## Security Considerations

| Threat | Mitigation |
|--------|-----------|
| Relay impersonation | mTLS ensures only relays with certs signed by trusted CA can register |
| Certificate theft from compromised spoke | Short cert TTL (1h SPIRE, 24h bootstrap) + revocation API |
| Man-in-the-middle on spoke-to-hub | mTLS provides mutual verification |
| Webhook replay attack | HMAC signature + nonce + 60s timestamp validation |
| Stale relay entries | 5-minute heartbeat timeout, automatic stale marking |
| Cross-tenant relay pivoting | Relay bound to tenant_id at registration, verified on every request |

---

## Failure Modes

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| Hub CA key compromise | Attacker can issue fake relay certs | Store CA key in KMS. Short cert TTL. Certificate pinning optional. |
| Relay cert expired | Cannot authenticate to hub | File watcher auto-reloads. SPIRE auto-rotates. Health check alerts on cert expiry < 1h. |
| Hub unreachable | No policy sync, no audit flush | LKG policies continue enforcing. Audit buffer holds events. Webhook push is complementary. |
| Webhook push fails | Spoke misses urgent revocation | Pull-based sync catches up within 15s. Circuit breaker prevents repeated failures. |

---

## Alternatives Considered

1. **OAuth 2.0 client credentials** — Doesn't provide mutual authentication. Requires token refresh dance. Doesn't leverage SPIFFE ecosystem.
2. **WireGuard tunnel** — Heavier infrastructure. Requires kernel module on some platforms. Overkill for control plane traffic.
3. **Shared API key per relay** — Still symmetric. Key management at scale is problematic. No automatic rotation.

---

## Consequences

- **Positive**: Cryptographic relay identity, per-relay revocation, audit trail for all federation actions, cross-environment trace linking, backward compatible with API key auth
- **Negative**: Certificate management complexity (mitigated by SPIRE and bootstrap flow), additional DB tables
- **Neutral**: No change to data plane enforcement (gateways still evaluate locally)
