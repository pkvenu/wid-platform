// =============================================================================
// Demo App — Plain HTTP server with ZERO awareness of WID platform
// =============================================================================
// This app makes normal HTTP calls. The Envoy sidecar + ext_authz adapter
// handle all authentication, authorization, and credential injection
// transparently. This proves zero-code-change deployment.
// =============================================================================

const http = require('http');

const APP_NAME = process.env.APP_NAME || 'demo';
const APP_PORT = parseInt(process.env.APP_PORT) || 8081;
const CALL_TARGET = process.env.CALL_TARGET || null;

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  // ── Health ──
  if (req.url === '/health') {
    return res.end(JSON.stringify({ service: APP_NAME, status: 'healthy' }));
  }

  // ── Data endpoint (what backends serve) ──
  if (req.url === '/data') {
    // Log what headers we received — shows WID headers injected by adapter
    const widHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (key.startsWith('x-wid-')) widHeaders[key] = value;
    }
    return res.end(JSON.stringify({
      service: APP_NAME,
      message: `Hello from ${APP_NAME}`,
      timestamp: new Date().toISOString(),
      wid_headers_received: widHeaders,
    }));
  }

  // ── Call another service (for frontend → backend chain) ──
  if (req.url === '/call' && CALL_TARGET) {
    try {
      const data = await fetch(CALL_TARGET).then(r => r.json());
      return res.end(JSON.stringify({
        service: APP_NAME,
        called: CALL_TARGET,
        response: data,
        my_headers: Object.fromEntries(
          Object.entries(req.headers).filter(([k]) => k.startsWith('x-wid-'))
        ),
      }));
    } catch (e) {
      res.statusCode = 502;
      return res.end(JSON.stringify({
        service: APP_NAME,
        error: `Failed to call ${CALL_TARGET}: ${e.message}`,
      }));
    }
  }

  // ── Default ──
  res.end(JSON.stringify({
    service: APP_NAME,
    endpoints: ['/health', '/data', '/call'],
    note: 'This app has ZERO knowledge of the WID platform. All auth is handled by the sidecar.',
  }));
});

server.listen(APP_PORT, '0.0.0.0', () => {
  console.log(`[${APP_NAME}] listening on :${APP_PORT}`);
  if (CALL_TARGET) console.log(`[${APP_NAME}] will call: ${CALL_TARGET}`);
});
