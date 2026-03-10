const BaseScanner = require('../base/BaseScanner');

class OpenStackScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'openstack';
    this.version = '1.0.0';
    this.authUrl = config.authUrl || process.env.OPENSTACK_AUTH_URL;
    this.enabled = false;
    this.disabledReason = this.authUrl
      ? 'OpenStack scanner coming soon'
      : 'Requires OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME';
  }

  getRequiredCredentials() {
    return [
      { name: 'OS_AUTH_URL', description: 'Keystone auth endpoint' },
      { name: 'OS_USERNAME', description: 'OpenStack username' },
      { name: 'OS_PASSWORD', description: 'OpenStack password' },
      { name: 'OS_PROJECT_NAME', description: 'OpenStack project' },
    ];
  }

  async validate() {
    return false;
  }

  getCapabilities() {
    return ['discover', 'instances', 'containers'];
  }

  async discover() {
    // TODO: Implement OpenStack discovery
    // - Nova instances
    // - Swift containers
    this.log('OpenStack discovery not yet implemented', 'info');
    return [];
  }
}

module.exports = OpenStackScanner;
