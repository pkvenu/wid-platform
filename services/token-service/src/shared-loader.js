// =============================================================================
// Shared Module Loader — resolves shared/ in both dev and Docker contexts
// =============================================================================
// Dev:    ../../../shared/  (relative to repo root)
// Docker: ../shared/        (copied into build context)
// =============================================================================

const path = require('path');
const fs = require('fs');

const DEV_SHARED = path.resolve(__dirname, '../../../shared');
const DOCKER_SHARED = path.resolve(__dirname, '../shared');

const SHARED_DIR = fs.existsSync(DEV_SHARED) ? DEV_SHARED : DOCKER_SHARED;

module.exports = {
  tenantDb: require(path.join(SHARED_DIR, 'tenant-db')),
  agentCardSigner: require(path.join(SHARED_DIR, 'agent-card-signer')),
  securityHeaders: require(path.join(SHARED_DIR, 'security-headers')),
  rateLimitMiddleware: require(path.join(SHARED_DIR, 'rate-limit-middleware')),
};
