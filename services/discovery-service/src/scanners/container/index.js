module.exports = {
  KubernetesScanner: require('./kubernetes'),
  DockerScanner: require('./docker'),
  ECSScanner: require('./ecs')
};
