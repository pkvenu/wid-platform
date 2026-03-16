# Workload Identity Defense (WID) Platform — Dual-Mode Data Plane

## Architecture

The platform provides **two deployment modes** for the data plane, both backed by the same shared core:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Management Plane (UI)                        │
│             workload-identity-ui (React dashboard)              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     Control Plane                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│  │ policy-sync  │  │ token-service│  │ credential-broker  │     │
│  │ -service     │  │              │  │                    │     │
│  └──────────────┘  └──────────────┘  └───────────────────┘     │
│                          │                                      │
│              ┌───────────▼────────────┐                         │
│              │  shared/data-plane-core │                        │
│              │  (PolicyCache, Breakers, │                        │
│              │   Sanitization, Metrics) │                        │
│              └─────┬──────────┬────────┘                        │
│                    │          │                                  │
│         ┌─────────▼──┐  ┌───▼───────────┐                      │
│         │  ext-authz  │  │ edge-gateway   │                     │
│         │  adapter    │  │               │                      │
│         │ (gRPC hook) │  │ (HTTP proxy)  │                      │
│         └──────┬──────┘  └──────┬────────┘                      │
└────────────────┼────────────────┼───────────────────────────────┘
                 │                │
    ┌────────────▼──┐    ┌───────▼────────┐
    │    Envoy /     │    │  iptables /    │
    │    Istio       │    │  explicit      │
    │    sidecar     │    │  proxy         │
    └───────────────┘    └────────────────┘
```

## When to Use Which

| Environment | Mode | Why |
|---|---|---|
| Kubernetes + Istio/Linkerd/Consul | **ext-authz-adapter** | Hooks into existing mesh — zero additional sidecars |
| Kubernetes + standalone Envoy | **ext-authz-adapter** | Envoy doesn't need full mesh, just ext_authz filter |
| Kubernetes, no mesh | **edge-gateway** | Sidecar container + init container for iptables |
| Docker Compose (dev) | **Either** | Both have docker-compose stacks |
| VMs / Bare metal | **edge-gateway** | systemd service + iptables redirect |
| Hybrid (mesh + legacy VMs) | **Both** | Adapter for mesh workloads, gateway for VMs |

## Project Structure

```
WORKLOAD-IDENTITY-PLATFORM/
├── shared/
│   └── data-plane-core/          ← SHARED LIBRARY (both modes import this)
│       ├── src/core.js           ← PolicyCache, CircuitBreaker, CredentialBuffer,
│       │                            RateLimiter, MetricsCollector, AuditBuffer,
│       │                            sanitizeHeaders, sanitizePath, buildAuditEntry,
│       │                            createAdminServer, generateIptablesScript
│       ├── test/core.test.js     ← 72 tests (single source of truth)
│       └── package.json
│
├── services/
│   ├── ext-authz-adapter/        ← CLOUD / MESH MODE
│   │   ├── src/adapter.js        ← gRPC ext_authz server (imports @wid/core)
│   │   ├── test/adapter.test.js  ← Adapter-specific tests (gRPC response format)
│   │   ├── deploy/
│   │   │   ├── local/            ← Docker Compose with Envoy sidecars
│   │   │   └── aws/              ← Terraform + EKS manifests
│   │   └── Dockerfile
│   │
│   ├── edge-gateway/             ← ON-PREM / NON-MESH MODE
│   │   ├── src/gateway.js        ← Transparent HTTP proxy (imports @wid/core)
│   │   ├── test/gateway.test.js  ← Gateway-specific tests (proxy, iptables)
│   │   ├── deploy/
│   │   │   ├── local/            ← Docker Compose with explicit proxy demo
│   │   │   └── k8s/             ← Sidecar injection example
│   │   ├── scripts/
│   │   │   └── init-iptables.sh  ← iptables transparent redirect
│   │   └── Dockerfile
│   │
│   ├── policy-sync-service/      ← Policy evaluation + governance engine
│   ├── token-service/            ← JIT token exchange + OBO chains
│   ├── credential-broker/        ← Vault/cloud secret injection
│   ├── discovery-service/        ← NHI scanner + attestation
│   └── opa/                      ← Policy agent (optional)
│
└── workload-identity-ui/         ← React dashboard
```

## Shared Core (`shared/data-plane-core`)

Both `ext-authz-adapter` and `edge-gateway` import from the shared core. This guarantees:

- **Identical policy caching** — same LRU eviction, same TTL, same path normalization
- **Identical data sanitization** — same allowlist, same header stripping, same path masking
- **Identical circuit breaking** — same thresholds, same half-open recovery
- **Identical credential buffering** — same fallback behavior during outages
- **Identical metrics** — same counters, same percentiles, same Prometheus format
- **Identical audit trail** — same entry structure, same batch flush
- **Identical admin API** — same /healthz, /readyz, /metrics, /config, /mode endpoints

### Integration

Both services reference the shared core via a local file dependency:

```json
// services/ext-authz-adapter/package.json
{
  "dependencies": {
    "@wid/core": "file:../../shared/data-plane-core"
  }
}

// services/edge-gateway/package.json
{
  "dependencies": {
    "@wid/core": "file:../../shared/data-plane-core"
  }
}
```

Then in code:

```javascript
const {
  PolicyCache, CredentialBuffer, CircuitBreaker,
  MetricsCollector, AuditBuffer, sanitizeHeaders,
  sanitizePath, buildAuditEntry, createAdminServer,
  httpRequest, log
} = require('@wid/core');
```

## How Each Mode Works

### ext-authz-adapter (Cloud)

```
curl → Envoy sidecar → [ext_authz gRPC call] → adapter
                                                    ↓
                                           Policy evaluation
                                           Token exchange
                                           Credential injection
                                                    ↓
                         Envoy injects x-wid-* headers ← adapter responds OK
                                                    ↓
                         Envoy forwards to app (app sees x-wid-* headers)
```

The adapter is a **gRPC server** that Envoy calls on every request. It never touches the actual HTTP traffic — it only sees metadata (SPIFFE IDs, method, path) and responds with allow/deny + headers to inject.

### edge-gateway (On-Prem)

```
App HTTP call → [iptables REDIRECT] → edge-gateway:15001
                                           ↓
                                  Policy evaluation
                                  Token exchange
                                  Credential injection
                                           ↓
                              gateway proxies request to real destination
                              with x-wid-* headers injected
                                           ↓
                              Response returns to app transparently
```

The gateway is a **transparent HTTP proxy** that intercepts traffic via iptables (or explicit proxy config). It sees and proxies the actual HTTP requests, injecting credentials before forwarding.

## Testing

### Shared core (always run first)
```bash
cd shared/data-plane-core
npm test
# 72 tests — validates all shared logic
```

### ext-authz-adapter
```bash
cd services/ext-authz-adapter
npm install
npm test
# Adapter-specific tests (gRPC responses, Envoy integration)

# Full stack with Envoy
docker compose -f deploy/local/docker-compose.yml up --build
curl http://localhost:10000/data
```

### edge-gateway
```bash
cd services/edge-gateway
npm test
# Gateway-specific tests (proxy behavior, iptables generation)

# Full stack with explicit proxy
docker compose -f deploy/local/docker-compose.yml up --build
curl http://localhost:8081/call
```

## Feature Parity Checklist

| Feature | ext-authz-adapter | edge-gateway |
|---|---|---|
| Policy cache (LRU + TTL) | ✅ shared core | ✅ shared core |
| Circuit breakers | ✅ shared core | ✅ shared core |
| Credential buffer | ✅ shared core | ✅ shared core |
| Rate limiting | ✅ shared core | ✅ shared core |
| Data sanitization | ✅ shared core | ✅ shared core |
| Metrics / Prometheus | ✅ shared core | ✅ shared core |
| Audit buffer | ✅ shared core | ✅ shared core |
| Admin API | ✅ shared core | ✅ shared core |
| Runtime mode switch | ✅ shared core | ✅ shared core |
| JIT token exchange | ✅ | ✅ |
| Chain depth tracking | ✅ | ✅ |
| Per-workload overrides | ✅ | ✅ |
| gRPC ext_authz protocol | ✅ | N/A |
| HTTP transparent proxy | N/A | ✅ |
| iptables interception | N/A | ✅ |
| Envoy header injection | ✅ | N/A |
| Direct header injection | N/A | ✅ |

## mTLS Federation

The hub-and-spoke relay layer uses mTLS with SPIFFE X.509 SVIDs for relay authentication. This is managed by the `TLSManager` class exported from `@wid/core`, which handles certificate loading, rotation, and mTLS context creation.

### New `@wid/core` Exports

| Export | Purpose |
|--------|---------|
| `TLSManager` | Manages relay TLS certificates (load, rotate, create mTLS context for relay connections) |
| `trace-context` | Propagates `trace_id` across hub-spoke boundaries for cross-environment decision replay |

### How It Works

1. Each spoke relay loads its SPIFFE X.509 SVID from `RELAY_CERT_PATH` and `RELAY_KEY_PATH`.
2. On connection to the hub, the relay presents its certificate. The hub verifies the certificate chain against the federation CA.
3. The hub extracts the relay's SPIFFE ID from the SAN field to establish per-relay cryptographic identity.
4. If certificates are not configured, the relay falls back to `CENTRAL_API_KEY` header authentication.
5. Cross-environment trace context is propagated via `trace-context`, enabling full audit trail linking across federated deployments.
