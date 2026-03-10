// =============================================================================
// Target Service — Receives requests through the Edge Gateway
// =============================================================================
// Shows which x-wid-* headers the gateway injected.
// =============================================================================

const http = require('http');
const PORT = parseInt(process.env.PORT) || 9090;

const server = http.createServer((req, res) => {
  // Collect all x-wid-* headers
  const widHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (k.startsWith('x-wid-')) widHeaders[k] = v;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    service: 'target-service',
    message: 'Hello from target service',
    timestamp: new Date().toISOString(),
    request: {
      method: req.method,
      path: req.url,
      host: req.headers.host,
    },
    wid_headers_received: widHeaders,
    wid_headers_count: Object.keys(widHeaders).length,
  }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[target-service] listening on :${PORT}`);
});
