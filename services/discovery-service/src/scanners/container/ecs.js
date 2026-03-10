const BaseScanner = require('../base/BaseScanner');

class ECSScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'ecs';
    this.version = '1.0.0';
    const hasAWS = !!(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_ROLE_ARN);
    this.enabled = false;
    this.disabledReason = hasAWS
      ? 'ECS deep scanner coming soon (basic ECS discovery available via AWS scanner)'
      : 'Requires AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY or AWS_ROLE_ARN';
  }

  getRequiredCredentials() {
    return [
      { name: 'AWS_ACCESS_KEY_ID', description: 'AWS access key' },
      { name: 'AWS_SECRET_ACCESS_KEY', description: 'AWS secret key' },
      { name: 'AWS_DEFAULT_REGION', description: 'AWS region (e.g. us-east-1)' },
    ];
  }

  async validate() {
    return false;
  }

  getCapabilities() {
    return ['discover', 'ecs-tasks', 'ecs-services'];
  }

  async discover() {
    // TODO: Implement ECS-specific discovery
    // This would be more detailed than the ECS discovery in aws.js
    this.log('ECS scanner not yet implemented', 'info');
    return [];
  }
}

module.exports = ECSScanner;
