// =============================================================================
// Target API Configurations — Extracted for testability
// =============================================================================

/**
 * Get target API configuration for credential injection proxy.
 * Each target defines baseUrl, secretPath, authType, and optional headers.
 *
 * @param {string} target - Target name (stripe, github, openai, anthropic)
 * @returns {Object|undefined} Target config or undefined if not found
 */
function getTargetConfig(target) {
  const configs = {
    'stripe': {
      baseUrl: process.env.STRIPE_API_URL || 'https://api.stripe.com',
      secretPath: process.env.STRIPE_SECRET_PATH || 'credentials/stripe/api-key',
      authType: 'bearer',
      headers: { 'Stripe-Version': '2023-10-16' },
    },
    'github': {
      baseUrl: process.env.GITHUB_API_URL || 'https://api.github.com',
      secretPath: process.env.GITHUB_SECRET_PATH || 'credentials/github/token',
      authType: 'token',
      headers: { 'Accept': 'application/vnd.github.v3+json' },
    },
    'openai': {
      baseUrl: process.env.OPENAI_API_URL || 'https://api.openai.com',
      secretPath: process.env.OPENAI_SECRET_PATH || 'credentials/openai/api-key',
      authType: 'bearer',
    },
    'anthropic': {
      baseUrl: process.env.ANTHROPIC_API_URL || 'https://api.anthropic.com',
      secretPath: process.env.ANTHROPIC_SECRET_PATH || 'credentials/anthropic/api-key',
      authType: 'x-api-key',
      headers: { 'anthropic-version': '2023-06-01' },
    },
  };

  return configs[target];
}

/**
 * List all supported target names.
 */
function getTargetNames() {
  return ['stripe', 'github', 'openai', 'anthropic'];
}

module.exports = {
  getTargetConfig,
  getTargetNames,
};
