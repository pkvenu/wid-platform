const BaseScanner = require('../base/BaseScanner');

class OracleScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'oracle';
    this.version = '1.0.0';
    this.tenancyId = config.tenancyId || process.env.OCI_TENANCY_ID;
    this.enabled = false;
    this.disabledReason = this.tenancyId
      ? 'Oracle Cloud scanner coming soon'
      : 'Requires OCI_TENANCY_ID, OCI_USER_OCID, OCI_FINGERPRINT, OCI_PRIVATE_KEY';
  }

  getRequiredCredentials() {
    return [
      { name: 'OCI_TENANCY_ID', description: 'Oracle Cloud tenancy OCID' },
      { name: 'OCI_USER_OCID', description: 'OCI user OCID' },
      { name: 'OCI_FINGERPRINT', description: 'API key fingerprint' },
      { name: 'OCI_PRIVATE_KEY', description: 'API signing key (PEM)' },
    ];
  }

  async validate() {
    return false;
  }

  getCapabilities() {
    return ['discover', 'compute', 'oke', 'functions'];
  }

  async discover() {
    // TODO: Implement Oracle Cloud discovery
    // - Compute instances
    // - OKE clusters
    // - Functions
    this.log('Oracle Cloud discovery not yet implemented', 'info');
    return [];
  }
}

module.exports = OracleScanner;
