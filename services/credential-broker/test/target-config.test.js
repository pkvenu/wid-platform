const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { getTargetConfig, getTargetNames } = require('../src/target-config');

// =============================================================================
// getTargetConfig()
// =============================================================================

describe('getTargetConfig', () => {
  it('should return config for stripe', () => {
    const config = getTargetConfig('stripe');
    assert.ok(config, 'stripe config should exist');
    assert.equal(config.authType, 'bearer');
    assert.ok(config.baseUrl.includes('stripe.com'));
    assert.ok(config.secretPath.includes('stripe'));
  });

  it('should return config for github', () => {
    const config = getTargetConfig('github');
    assert.ok(config, 'github config should exist');
    assert.equal(config.authType, 'token');
    assert.ok(config.baseUrl.includes('github.com'));
    assert.ok(config.headers['Accept'], 'github should have Accept header');
  });

  it('should return config for openai', () => {
    const config = getTargetConfig('openai');
    assert.ok(config, 'openai config should exist');
    assert.equal(config.authType, 'bearer');
    assert.ok(config.baseUrl.includes('openai.com'));
  });

  it('should return config for anthropic', () => {
    const config = getTargetConfig('anthropic');
    assert.ok(config, 'anthropic config should exist');
    assert.equal(config.authType, 'x-api-key');
    assert.ok(config.baseUrl.includes('anthropic.com'));
    assert.ok(config.headers['anthropic-version'], 'anthropic should have version header');
  });

  it('should return undefined for unknown target', () => {
    assert.equal(getTargetConfig('unknown-api'), undefined);
  });

  it('should have authType on every known target', () => {
    for (const name of getTargetNames()) {
      const config = getTargetConfig(name);
      assert.ok(config.authType, `${name} missing authType`);
    }
  });

  it('should have secretPath on every known target', () => {
    for (const name of getTargetNames()) {
      const config = getTargetConfig(name);
      assert.ok(config.secretPath, `${name} missing secretPath`);
    }
  });
});

// =============================================================================
// getTargetNames()
// =============================================================================

describe('getTargetNames', () => {
  it('should return array of 4 target names', () => {
    const names = getTargetNames();
    assert.equal(names.length, 4);
    assert.ok(names.includes('stripe'));
    assert.ok(names.includes('github'));
    assert.ok(names.includes('openai'));
    assert.ok(names.includes('anthropic'));
  });
});
