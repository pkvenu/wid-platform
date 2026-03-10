// =============================================================================
// CI/CD Scanner - Discovers GitHub Actions, Jenkins & CI/CD Bot Identities
// =============================================================================
// Scans for:
// 1. GitHub Actions OIDC identities (via GitHub API)
// 2. GitHub App installations
// 3. GitHub deploy keys & PATs (from repository settings)
// 4. Jenkins credentials (if Jenkins API is available)

const BaseScanner = require('../base/BaseScanner');
const https = require('https');
const http = require('http');

class CICDScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'github';
    this.version = '1.0.0';
    this.githubToken = config.githubToken || process.env.GITHUB_TOKEN;
    this.githubOrg = config.githubOrg || process.env.GITHUB_ORG;
    this.jenkinsUrl = config.jenkinsUrl || process.env.JENKINS_URL;
    this.jenkinsUser = config.jenkinsUser || process.env.JENKINS_USER;
    this.jenkinsToken = config.jenkinsToken || process.env.JENKINS_TOKEN;

    // Disable early if no sources configured at all
    if (!this.githubToken && !this.jenkinsUrl) {
      this.enabled = false;
      this.disabledReason = 'Requires GITHUB_TOKEN + GITHUB_ORG or JENKINS_URL';
    }
  }

  getRequiredCredentials() {
    return [
      { name: 'GITHUB_TOKEN', description: 'GitHub personal access token or app token' },
      { name: 'GITHUB_ORG', description: 'GitHub organization name' },
      { name: 'JENKINS_URL', description: 'Jenkins server URL (alternative to GitHub)' },
      { name: 'JENKINS_USER', description: 'Jenkins username (optional)' },
      { name: 'JENKINS_TOKEN', description: 'Jenkins API token (optional)' },
    ];
  }

  async validate() {
    let sources = 0;

    // Check GitHub
    if (this.githubToken && this.githubOrg) {
      try {
        await this.githubRequest(`/orgs/${this.githubOrg}`);
        this.log(`GitHub org connected: ${this.githubOrg}`, 'success');
        this.githubAvailable = true;
        sources++;
      } catch (error) {
        this.log(`GitHub validation failed: ${error.message}`, 'warn');
        this.githubAvailable = false;
      }
    } else {
      this.githubAvailable = false;
    }

    // Check Jenkins
    if (this.jenkinsUrl) {
      try {
        await this.httpGet(`${this.jenkinsUrl}/api/json`);
        this.log('Jenkins connected', 'success');
        this.jenkinsAvailable = true;
        sources++;
      } catch {
        this.jenkinsAvailable = false;
      }
    }

    if (sources === 0) {
      this.log('No CI/CD sources available (need GITHUB_TOKEN+GITHUB_ORG or JENKINS_URL)', 'warn');
      return false;
    }

    return true;
  }

  getCapabilities() {
    return ['discover', 'github-actions', 'github-apps', 'deploy-keys', 'jenkins'];
  }

  async discover() {
    this.log('Starting CI/CD identity discovery', 'info');
    const workloads = [];

    if (this.githubAvailable) {
      // GitHub Actions workflows (OIDC identities)
      const workflows = await this.discoverGitHubWorkflows();
      workloads.push(...workflows);
      this.log(`Found ${workflows.length} GitHub Actions workflows`, 'success');

      // GitHub App installations
      const apps = await this.discoverGitHubApps();
      workloads.push(...apps);
      this.log(`Found ${apps.length} GitHub App installations`, 'success');

      // Deploy keys across repos
      const deployKeys = await this.discoverDeployKeys();
      workloads.push(...deployKeys);
      this.log(`Found ${deployKeys.length} deploy keys`, 'success');
    }

    if (this.jenkinsAvailable) {
      const jenkinsJobs = await this.discoverJenkinsJobs();
      workloads.push(...jenkinsJobs);
      this.log(`Found ${jenkinsJobs.length} Jenkins jobs`, 'success');
    }

    return workloads;
  }

  async discoverGitHubWorkflows() {
    try {
      // List repos in the org
      const repos = await this.githubRequest(`/orgs/${this.githubOrg}/repos?per_page=100&type=all`);
      const workloads = [];

      for (const repo of repos) {
        try {
          // List workflows for each repo
          const wfResponse = await this.githubRequest(`/repos/${this.githubOrg}/${repo.name}/actions/workflows`);
          const workflows = wfResponse.workflows || [];

          for (const wf of workflows) {
            // Get recent runs for this workflow
            let lastRun = null;
            let totalRuns = 0;
            try {
              const runs = await this.githubRequest(`/repos/${this.githubOrg}/${repo.name}/actions/workflows/${wf.id}/runs?per_page=1`);
              totalRuns = runs.total_count || 0;
              lastRun = runs.workflow_runs?.[0] || null;
            } catch { /* no runs */ }

            const daysSinceRun = lastRun?.updated_at
              ? Math.floor((Date.now() - new Date(lastRun.updated_at).getTime()) / 86400000)
              : null;

            const usesOIDC = wf.path?.includes('id-token') || false; // Heuristic

            const workload = {
              name: `gh-action-${repo.name}-${wf.name.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`,
              type: 'github-action',
              namespace: 'github-actions',
              environment: repo.default_branch === 'main' || repo.default_branch === 'master' ? 'production' : 'development',

              category: 'ci-cd',
              subcategory: usesOIDC ? 'oidc-workflow' : 'github-workflow',
              is_ai_agent: false,
              is_mcp_server: false,

              labels: {
                repo: repo.full_name,
                workflow_name: wf.name,
                workflow_state: wf.state,
                default_branch: repo.default_branch,
                visibility: repo.visibility || (repo.private ? 'private' : 'public'),
                total_runs: String(totalRuns),
                uses_oidc: String(usesOIDC)
              },
              metadata: {
                workflow_id: wf.id,
                workflow_path: wf.path,
                workflow_state: wf.state,
                repo_full_name: repo.full_name,
                repo_id: repo.id,
                repo_url: repo.html_url,
                visibility: repo.visibility || (repo.private ? 'private' : 'public'),
                created_at: wf.created_at,
                updated_at: wf.updated_at,
                last_run_at: lastRun?.updated_at || null,
                last_run_status: lastRun?.conclusion || null,
                last_run_actor: lastRun?.actor?.login || null,
                total_runs: totalRuns,
                days_since_run: daysSinceRun
              },

              cloud_provider: 'github',
              region: 'global',
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `https://token.actions.githubusercontent.com`,
              cluster_id: this.githubOrg,

              owner: repo.owner?.login || null,
              team: null,
              is_shadow: wf.state === 'disabled_manually' || (daysSinceRun !== null && daysSinceRun > 180),
              shadow_score: this.calculateWorkflowShadowScore(wf, daysSinceRun, totalRuns),

              discovered_by: 'cicd-scanner'
            };

            workload.security_score = this.calculateWorkflowSecurityScore(workload, usesOIDC, repo.visibility);
            workloads.push(workload);
          }
        } catch (error) {
          // Repo may not have actions enabled
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering GitHub workflows: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverGitHubApps() {
    try {
      const installations = await this.githubRequest(`/orgs/${this.githubOrg}/installations?per_page=100`);
      const workloads = [];

      for (const install of installations.installations || installations || []) {
        const app = install.app || {};
        const permissions = install.permissions || {};
        const hasWritePermissions = Object.values(permissions).some(v => v === 'write');
        const hasAdminPermissions = Object.values(permissions).some(v => v === 'admin');

        const workload = {
          name: `gh-app-${(app.slug || app.name || install.id).toString().replace(/[^a-zA-Z0-9-]/g, '-')}`,
          type: 'github-app',
          namespace: 'github-apps',
          environment: 'production',

          category: 'ci-cd',
          subcategory: 'github-app',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            app_name: app.name || 'unknown',
            app_slug: app.slug || 'unknown',
            installation_id: String(install.id),
            has_write: String(hasWritePermissions),
            has_admin: String(hasAdminPermissions),
            repository_selection: install.repository_selection || 'all'
          },
          metadata: {
            app_id: app.id,
            app_name: app.name,
            app_slug: app.slug,
            app_owner: app.owner?.login || null,
            installation_id: install.id,
            target_type: install.target_type,
            repository_selection: install.repository_selection,
            permissions: permissions,
            events: install.events || [],
            created_at: install.created_at,
            updated_at: install.updated_at,
            has_admin_permissions: hasAdminPermissions
          },

          cloud_provider: 'github',
          region: 'global',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'https://github.com/apps',
          cluster_id: this.githubOrg,

          owner: app.owner?.login || null,
          team: null,
          is_shadow: false,
          shadow_score: hasAdminPermissions ? 40 : 15,

          discovered_by: 'cicd-scanner'
        };

        workload.security_score = this.calculateAppSecurityScore(workload, hasWritePermissions, hasAdminPermissions);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering GitHub apps: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverDeployKeys() {
    try {
      const repos = await this.githubRequest(`/orgs/${this.githubOrg}/repos?per_page=100&type=all`);
      const workloads = [];

      for (const repo of repos) {
        try {
          const keys = await this.githubRequest(`/repos/${this.githubOrg}/${repo.name}/keys`);

          for (const key of keys) {
            const ageDays = key.created_at
              ? Math.floor((Date.now() - new Date(key.created_at).getTime()) / 86400000)
              : null;

            const workload = {
              name: `deploy-key-${repo.name}-${key.id}`,
              type: 'deploy-key',
              namespace: 'github-keys',
              environment: 'production',

              category: 'ci-cd',
              subcategory: key.read_only ? 'read-only-key' : 'read-write-key',
              is_ai_agent: false,
              is_mcp_server: false,

              labels: {
                repo: repo.full_name,
                key_title: key.title || 'untitled',
                read_only: String(key.read_only),
                verified: String(key.verified || false)
              },
              metadata: {
                key_id: key.id,
                title: key.title,
                repo_full_name: repo.full_name,
                read_only: key.read_only,
                created_at: key.created_at,
                age_days: ageDays,
                key_fingerprint: key.key?.slice(0, 50) + '...',
                verified: key.verified || false,
                last_used: key.last_used || null
              },

              cloud_provider: 'github',
              region: 'global',
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `github://${repo.full_name}`,
              cluster_id: this.githubOrg,

              owner: null,
              team: null,
              is_shadow: ageDays > 365,
              shadow_score: this.calculateKeyShadowScore(key, ageDays),

              discovered_by: 'cicd-scanner'
            };

            workload.security_score = this.calculateKeySecurityScore(workload, key.read_only, ageDays);
            workloads.push(workload);
          }
        } catch {
          // No deploy keys or no permission
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering deploy keys: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverJenkinsJobs() {
    try {
      const jenkins = await this.httpGet(`${this.jenkinsUrl}/api/json?tree=jobs[name,url,buildable,lastBuild[number,timestamp,result],healthReport[score]]`);
      const workloads = [];

      for (const job of jenkins.jobs || []) {
        const lastBuildTime = job.lastBuild?.timestamp ? new Date(job.lastBuild.timestamp) : null;
        const daysSinceBuild = lastBuildTime ? Math.floor((Date.now() - lastBuildTime.getTime()) / 86400000) : null;

        const workload = {
          name: `jenkins-${job.name.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase()}`,
          type: 'jenkins-job',
          namespace: 'jenkins',
          environment: 'unknown',

          category: 'ci-cd',
          subcategory: 'jenkins-pipeline',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            job_name: job.name,
            buildable: String(job.buildable || false),
            last_build_result: job.lastBuild?.result || 'unknown',
            health_score: String(job.healthReport?.[0]?.score || 0)
          },
          metadata: {
            job_name: job.name,
            job_url: job.url,
            buildable: job.buildable || false,
            last_build_number: job.lastBuild?.number || null,
            last_build_timestamp: lastBuildTime?.toISOString() || null,
            last_build_result: job.lastBuild?.result || null,
            days_since_build: daysSinceBuild,
            health_score: job.healthReport?.[0]?.score || 0
          },

          cloud_provider: 'jenkins',
          region: 'local',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `jenkins://${this.jenkinsUrl}`,
          cluster_id: 'jenkins-local',

          owner: null,
          team: null,
          is_shadow: daysSinceBuild > 180 || !job.buildable,
          shadow_score: daysSinceBuild > 365 ? 80 : (daysSinceBuild > 180 ? 60 : 20),

          discovered_by: 'cicd-scanner'
        };

        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Jenkins jobs: ${error.message}`, 'error');
      return [];
    }
  }

  // ── Scoring helpers ──

  calculateWorkflowShadowScore(wf, daysSinceRun, totalRuns) {
    let score = 0;
    if (wf.state !== 'active') score += 30;
    if (daysSinceRun > 180) score += 30;
    else if (daysSinceRun > 90) score += 15;
    if (totalRuns < 5) score += 20;
    return Math.min(100, score);
  }

  calculateWorkflowSecurityScore(workload, usesOIDC, visibility) {
    let score = 50;
    if (usesOIDC) score += 20; // OIDC is more secure than PATs
    if (visibility === 'private') score += 10;
    if (workload.metadata.total_runs > 10) score += 10;
    if (workload.is_shadow) score -= 15;
    return Math.max(0, Math.min(100, score));
  }

  calculateAppSecurityScore(workload, hasWrite, hasAdmin) {
    let score = 60;
    if (hasAdmin) score -= 25;
    else if (hasWrite) score -= 10;
    if (workload.metadata.repository_selection === 'selected') score += 15; // Least privilege
    return Math.max(0, Math.min(100, score));
  }

  calculateKeyShadowScore(key, ageDays) {
    let score = 0;
    if (ageDays > 365) score += 40;
    else if (ageDays > 180) score += 20;
    if (!key.read_only) score += 25;
    if (!key.title) score += 15;
    return Math.min(100, score);
  }

  calculateKeySecurityScore(workload, readOnly, ageDays) {
    let score = 50;
    if (readOnly) score += 15;
    if (ageDays < 90) score += 15;
    if (ageDays > 365) score -= 20;
    return Math.max(0, Math.min(100, score));
  }

  // ── HTTP helpers ──

  githubRequest(path) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: 'api.github.com',
        path: path,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.githubToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'workload-identity-platform/1.0',
          'X-GitHub-Api-Version': '2022-11-28'
        }
      };

      const req = https.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode >= 400) reject(new Error(`GitHub ${res.statusCode}: ${data.slice(0, 200)}`));
            else resolve(JSON.parse(data));
          } catch (e) { reject(e); }
        });
      });
      req.on('error', reject);
      req.setTimeout(15000, () => { req.destroy(); reject(new Error('GitHub timeout')); });
      req.end();
    });
  }

  httpGet(url) {
    return new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { timeout: 5000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
  }
}

module.exports = CICDScanner;