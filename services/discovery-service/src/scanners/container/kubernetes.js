const k8s = require('@kubernetes/client-node');
const { generateSpiffeId } = require('../../utils/spiffe');

class KubernetesScanner {
  constructor() {
    this.name = 'KubernetesScanner';
    this.provider = 'kubernetes';
    this.version = '1.0.0';
    this.kc = new k8s.KubeConfig();

    try {
      // Try cluster config first
      this.kc.loadFromCluster();
    } catch {
      // Fall back to local kubeconfig
      try {
        this.kc.loadFromDefault();
        console.log('  ✓ Loaded kubeconfig');
      } catch (error) {
        console.warn('  ⚠️  No Kubernetes config - K8s scanning disabled');
        this.available = false;
        this.enabled = false;
        this.disabledReason = 'Requires kubeconfig or in-cluster service account';
        return;
      }
    }

    this.appsApi = this.kc.makeApiClient(k8s.AppsV1Api);
    this.batchApi = this.kc.makeApiClient(k8s.BatchV1Api);
    this.available = true;
    this.enabled = true;
  }

  getMetadata() {
    return {
      name: this.name,
      provider: this.provider,
      version: this.version,
      enabled: this.enabled !== false,
      capabilities: this.getCapabilities(),
    };
  }

  getCapabilities() {
    return ['discover', 'deployments', 'statefulsets', 'daemonsets', 'cronjobs'];
  }

  getRequiredCredentials() {
    return [
      { name: 'KUBECONFIG', description: 'Path to kubeconfig file (or in-cluster SA)' },
      { name: 'K8S_CLUSTER_NAME', description: 'Cluster display name (optional)' },
    ];
  }

  async validate() {
    return this.available === true;
  }

  async discover() {
    // ✅ ADD: Get cluster name and trust domain
    const clusterName = process.env.K8S_CLUSTER_NAME || 
                        process.env.CLUSTER_NAME || 
                        'local-cluster';
    
    const trustDomain = process.env.SPIRE_TRUST_DOMAIN || 'company.com';
    
    if (!this.available) return [];

    const workloads = [];

    try {
      // Deployments
      const deployments = await this.appsApi.listDeploymentForAllNamespaces();
      for (const deploy of deployments.body.items) {
        workloads.push(this.createWorkload(deploy, 'kubernetes-deployment', clusterName, trustDomain));
      }

      // StatefulSets
      const statefulsets = await this.appsApi.listStatefulSetForAllNamespaces();
      for (const sts of statefulsets.body.items) {
        workloads.push(this.createWorkload(sts, 'kubernetes-statefulset', clusterName, trustDomain));
      }

      // DaemonSets
      const daemonsets = await this.appsApi.listDaemonSetForAllNamespaces();
      for (const ds of daemonsets.body.items) {
        workloads.push(this.createWorkload(ds, 'kubernetes-daemonset', clusterName, trustDomain));
      }

      // CronJobs
      const cronjobs = await this.batchApi.listCronJobForAllNamespaces();
      for (const cj of cronjobs.body.items) {
        workloads.push(this.createWorkload(cj, 'kubernetes-cronjob', clusterName, trustDomain));
      }

    } catch (error) {
      console.error('  Kubernetes scan error:', error.message);
    }

    return workloads;
  }

  // ✅ UPDATED: Add clusterName and trustDomain parameters
  createWorkload(resource, type, clusterName, trustDomain) {
    const namespace = resource.metadata.namespace;
    const name = resource.metadata.name;
    const labels = resource.metadata.labels || {};
    const serviceAccountName = resource.spec?.template?.spec?.serviceAccountName || 'default';

    // Determine environment
    let environment = 'unknown';
    if (labels.environment) environment = labels.environment;
    else if (labels.env) environment = labels.env;
    else if (namespace.includes('prod')) environment = 'production';
    else if (namespace.includes('stag')) environment = 'staging';
    else if (namespace.includes('dev')) environment = 'development';

    // ✅ ADD: Generate SPIFFE ID
    const spiffeId = generateSpiffeId(
      trustDomain,
      'k8s',
      `${namespace}/${serviceAccountName}/${name}`
    );

    return {
      name,
      type,
      spiffe_id: spiffeId,  // ✅ ADD
      namespace,
      environment,
      
      // ✅ ADD: Trust domain fields
      trust_domain: trustDomain,
      issuer: `k8s://${clusterName}`,
      cluster_id: clusterName,
      
      discovered_by: 'kubernetes',
      labels,
      selectors: {
        'k8s:ns': namespace,
        'k8s:sa': serviceAccountName,
        'k8s:cluster': clusterName,  // ✅ ADD
        [`k8s:${type.split('-')[1]}`]: name
      },
      metadata: {
        uid: resource.metadata.uid,
        created: resource.metadata.creationTimestamp,
        cluster: clusterName  // ✅ ADD
      }
    };
  }
}

module.exports = new KubernetesScanner;