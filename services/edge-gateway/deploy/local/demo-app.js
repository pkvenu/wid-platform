// =============================================================================
// Demo App — Sends requests through the Edge Gateway
// =============================================================================
// In production, iptables transparently redirects traffic.
// For local Docker testing, the app explicitly sends through the gateway.
// =============================================================================

const http = require('http');

const PORT = parseInt(process.env.PORT) || 8081;
const GATEWAY_HOST = process.env.GATEWAY_HOST || 'edge-gateway';
const GATEWAY_PORT = parseInt(process.env.GATEWAY_PORT) || 15001;
const TARGET_SERVICE = process.env.TARGET_SERVICE || 'http://target-service:9090';

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.url === '/data') {
    // Direct response — shows the app is running
    return res.end(JSON.stringify({
      service: 'demo-app',
      message: 'Hello from demo app',
      timestamp: new Date().toISOString(),
    }));
  }

  if (req.url === '/call') {
    // Call target service THROUGH the edge gateway
    try {
      const targetUrl = new URL(TARGET_SERVICE + '/data');
      const result = await new Promise((resolve, reject) => {
        const proxyReq = http.request({
          // Send to gateway, but set Host header to the real target
          hostname: GATEWAY_HOST,
          port: GATEWAY_PORT,
          path: targetUrl.pathname,
          method: 'GET',
          headers: {
            'Host': `${targetUrl.hostname}:${targetUrl.port || 80}`,
            'Accept': 'application/json',
          },
          timeout: 10000,
        }, (proxyRes) => {
          let body = '';
          proxyRes.on('data', c => body += c);
          proxyRes.on('end', () => {
            try {
              resolve({
                status: proxyRes.statusCode,
                headers: {
                  'x-wid-decision-id': proxyRes.headers['x-wid-decision-id'],
                },
                body: JSON.parse(body),
              });
            } catch {
              resolve({ status: proxyRes.statusCode, body });
            }
          });
        });
        proxyReq.on('error', reject);
        proxyReq.end();
      });

      return res.end(JSON.stringify({
        service: 'demo-app',
        called: TARGET_SERVICE + '/data',
        via: `edge-gateway (${GATEWAY_HOST}:${GATEWAY_PORT})`,
        result,
      }));
    } catch (e) {
      res.writeHead(500);
      return res.end(JSON.stringify({ error: e.message }));
    }
  }

  if (req.url === '/health') {
    return res.end(JSON.stringify({ status: 'healthy' }));
  }

  res.writeHead(404);
  res.end(JSON.stringify({
    error: 'Not found',
    endpoints: ['/data', '/call', '/health'],
  }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[demo-app] listening on :${PORT}`);
  console.log(`[demo-app] gateway: ${GATEWAY_HOST}:${GATEWAY_PORT}`);
  console.log(`[demo-app] target: ${TARGET_SERVICE}`);
});
