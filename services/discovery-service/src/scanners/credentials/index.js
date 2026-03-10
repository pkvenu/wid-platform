module.exports = {
  IAMScanner: require('./iam'),
  VaultScanner: require('./vault'),
  ServiceTokenScanner: require('./service-tokens'),
  CICDScanner: require('./cicd')
};