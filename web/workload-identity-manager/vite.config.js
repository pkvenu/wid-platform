import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  define: {
    __API_BASE__: JSON.stringify(process.env.VITE_API_URL || ''),
  },
  server: {
    host: '0.0.0.0',
    port: 3100,
    proxy: {
      // Discovery service routes (external port 3004)
      '/api/v1/graph':       { target: 'http://localhost:3004', changeOrigin: true },
      '/api/v1/workloads':   { target: 'http://localhost:3004', changeOrigin: true },
      // Policy engine routes (port 3001)
      '/api/v1/policies':    { target: 'http://localhost:3001', changeOrigin: true },
      '/api/v1/violations':  { target: 'http://localhost:3001', changeOrigin: true },
      '/api/v1/access':      { target: 'http://localhost:3001', changeOrigin: true },
      '/api/v1/enforcement': { target: 'http://localhost:3001', changeOrigin: true },
      '/api/v1/governance':  { target: 'http://localhost:3001', changeOrigin: true },
      // Gateway evaluate → policy-sync-service (port 3001)
      '/api/v1/gateway':     { target: 'http://localhost:3001', changeOrigin: true },
      // Token issuance → discovery service (has /api/v1/tokens/issue)
      '/api/v1/tokens':      { target: 'http://localhost:3004', changeOrigin: true },
      // Catch-all /api/v1 → discovery (must be AFTER specific routes)
      '/api/v1':             { target: 'http://localhost:3004', changeOrigin: true },
      // Other service proxies
      '/api/opa': {
        target: 'http://localhost:8181',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/opa/, '')
      },
      '/api/token': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/token/, '')
      },
      '/api/broker': {
        target: 'http://localhost:3002',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/broker/, '')
      },
      '/api/relay': {
        target: 'http://localhost:3005',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/relay/, '')
      },
    }
  }
})
