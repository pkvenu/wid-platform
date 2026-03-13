const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const BaseSecretProvider = require('../src/providers/base-provider');

// =============================================================================
// BaseSecretProvider
// =============================================================================

describe('BaseSecretProvider', () => {
  it('should store name and config', () => {
    const provider = new BaseSecretProvider('test-vault', { url: 'http://vault' });
    assert.equal(provider.name, 'test-vault');
    assert.deepEqual(provider.config, { url: 'http://vault' });
  });

  it('should default to disabled', () => {
    const provider = new BaseSecretProvider('test');
    assert.equal(provider.enabled, false);
  });

  it('should throw on unimplemented initialize()', async () => {
    const provider = new BaseSecretProvider('test');
    await assert.rejects(provider.initialize(), /initialize\(\) must be implemented/);
  });

  it('should throw on unimplemented getSecret()', async () => {
    const provider = new BaseSecretProvider('test');
    await assert.rejects(provider.getSecret('path'), /getSecret\(\) must be implemented/);
  });

  it('should throw on unimplemented putSecret()', async () => {
    const provider = new BaseSecretProvider('test');
    await assert.rejects(provider.putSecret('path', 'val'), /putSecret\(\) not implemented/);
  });

  it('should throw on unimplemented rotateSecret()', async () => {
    const provider = new BaseSecretProvider('test');
    await assert.rejects(provider.rotateSecret('path', 'new'), /rotateSecret\(\) not implemented/);
  });

  it('should return false for supportsRotation()', () => {
    const provider = new BaseSecretProvider('test');
    assert.equal(provider.supportsRotation(), false);
  });

  it('should return false for supportsRevocation()', () => {
    const provider = new BaseSecretProvider('test');
    assert.equal(provider.supportsRevocation(), false);
  });

  it('should return false for supportsDynamicSecrets()', () => {
    const provider = new BaseSecretProvider('test');
    assert.equal(provider.supportsDynamicSecrets(), false);
  });

  it('should return enabled state from healthCheck()', async () => {
    const provider = new BaseSecretProvider('test');
    assert.equal(await provider.healthCheck(), false);
    provider.enabled = true;
    assert.equal(await provider.healthCheck(), true);
  });

  it('should return metadata with name and enabled', () => {
    const provider = new BaseSecretProvider('vault-prod', { url: 'https://vault' });
    provider.enabled = true;
    const meta = provider.getMetadata();
    assert.equal(meta.name, 'vault-prod');
    assert.equal(meta.enabled, true);
    assert.deepEqual(meta.config, { configured: true });
  });

  it('should return safe config without secrets', () => {
    const provider = new BaseSecretProvider('test', { token: 'secret123', url: 'http://vault' });
    const safe = provider.getSafeConfig();
    assert.ok(!safe.token, 'Should not expose token');
    assert.ok(!safe.url, 'Should not expose URL');
    assert.ok('configured' in safe, 'Should have configured flag');
  });
});
