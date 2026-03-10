// =============================================================================
// Identity Graph — Relationship Scanner
// =============================================================================
// Discovers relationships between workloads across all cloud providers:
//   - IAM Bindings: identity → roles → resources
//   - Service Identity: which SA/role runs which service
//   - Network Exposure: public ingress, load balancers, IPs
//   - Shared Identities: SAs used by multiple services
//   - Credentials: user-managed keys, access keys
//
// USAGE:
//   const RelationshipScanner = require('./graph/relationship-scanner');
//   const rs = new RelationshipScanner(scannerConfig);
//   const graph = await rs.discover(workloads, 'gcp');
//
// Runs AFTER workload discovery during each scan cycle.
// =============================================================================

class RelationshipScanner {
  constructor(config = {}) {
    this.config = config;
    this.projectId = config.project || process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
    this.nodes = [];
    this.relationships = [];
    this._nids = new Set();
    this._rkeys = new Set();
  }

  // ─── Helpers ───────────────────────────────────────────────────

  addNode(n) {
    if (this._nids.has(n.id)) return;
    this._nids.add(n.id);
    this.nodes.push(n);
  }

  addRel(r) {
    const k = `${r.source}|${r.target}|${r.type}`;
    if (this._rkeys.has(k)) return;
    this._rkeys.add(k);
    this.relationships.push({ ...r, id: k });
  }

  log(msg, lvl = 'info') {
    const p = { info: '  ℹ️', success: '  ✓', error: '  ✗', warn: '  ⚠️' }[lvl] || '  ';
    console.log(`${p} [graph] ${msg}`);
  }

  groupOf(type) {
    const map = {
      // Identity types
      'service-account': 'identity', 'iam-role': 'identity', 'iam-user': 'identity',
      'managed-identity': 'identity', 'user': 'identity', 'iam-group': 'identity',
      'app-registration': 'identity', 'service-principal': 'identity',
      'directory-role': 'permission', 'conditional-access-policy': 'policy',
      'role-assignment': 'permission',
      // Workload types — all variants from DB and cloud providers
      'cloud-run': 'workload', 'cloud-run-service': 'workload',   // GCP Cloud Run
      'gce-instance': 'workload',                                  // GCP Compute
      'cloud-function': 'workload', 'cloud-functions': 'workload', // GCP Functions
      'lambda': 'workload',                                        // AWS Lambda
      'ec2': 'workload', 'ecs-task': 'workload',                  // AWS Compute
      'azure-vm': 'workload', 'azure-app-service': 'workload',    // Azure
      'azure-function': 'workload', 'azure-container-instance': 'workload',
      'container': 'workload', 'pod': 'workload',                 // K8s/Docker
      // Data store types
      's3-bucket': 'data-store', 'rds-instance': 'data-store', 'rds-cluster': 'data-store',
      'dynamodb-table': 'data-store', 'cloud-sql': 'data-store', 'gcs-bucket': 'data-store',
      'storage-account': 'data-store', 'azure-sql': 'data-store',
      // Network types
      'vpc': 'network', 'security-group': 'network-policy', 'load-balancer': 'network',
      'firewall-rule': 'network-policy', 'nsg': 'network-policy',
      // Encryption / secrets
      'kms-key': 'encryption', 'key-vault': 'encryption',
      'managed-secret': 'credential', 'cloudtrail': 'audit',
      // AI Agent types
      'a2a-agent': 'agent-protocol', 'mcp-server': 'agent-protocol',
      // Cloud AI service types
      'vertex-ai-endpoint': 'ai-service', 'vertex-ai-model': 'ai-service',
      'bedrock-model': 'ai-service', 'sagemaker-endpoint': 'ai-service',
      'azure-openai-deployment': 'ai-service', 'ai-api-enabled': 'ai-service',
      // Cluster types
      'gke-cluster': 'cluster', 'aks-cluster': 'cluster', 'eks-cluster': 'cluster',
      // External
      'external-api': 'external', 'external-resource': 'external',
      'external-credential': 'credential', 'credential': 'credential',
    };
    return map[type] || 'workload';
  }

  findByEmail(email) {
    return this.nodes.find(n => n.meta?.sa === email || n.meta?.email === email);
  }

  // ═══════════════════════════════════════════════════════════════
  // Main entry point
  // ═══════════════════════════════════════════════════════════════

  async discover(workloads, provider) {
    this.nodes = []; this.relationships = [];
    this._nids = new Set(); this._rkeys = new Set();

    this.log(`Building identity graph: ${workloads.length} workloads (${provider})`);

    // Phase 1 — workload nodes
    for (const w of workloads) {
      this.addNode({
        id: `w:${w.id || w.name}`,
        wid: w.id, label: w.name, type: w.type,
        group: this.groupOf(w.type),
        trust: w.trust_level || 'none',
        score: w.security_score || 0,
        provider: w.cloud_provider, region: w.region,
        owner: w.owner, team: w.team,
        is_ai_agent: !!w.is_ai_agent,
        is_mcp_server: !!w.is_mcp_server,
        category: w.category || null,
        meta: {
          sa: w.metadata?.service_account || w.metadata?.email,
          email: w.metadata?.email,
          ingress: w.metadata?.ingress,
          extIp: w.metadata?.has_external_ip || w.metadata?.has_public_ip || !!w.metadata?.public_ip,
          image: w.metadata?.image,
          role: w.metadata?.role,
          principalId: w.metadata?.principal_id,
          model_id: w.metadata?.model_id || w.metadata?.ai_asset?.model_id,
          ai_asset: w.metadata?.ai_asset || null,
          userKeys: w.metadata?.user_managed_keys || 0,
          keyAge: w.metadata?.oldest_key_age_days || 0,
          hasMI: w.metadata?.has_managed_identity,
          url: w.metadata?.url || w.metadata?.uri,
          // Network/data store identifiers for relationship matching
          vpc_id: w.metadata?.vpc_id,
          group_id: w.metadata?.group_id,
          is_public: w.metadata?.is_public || w.metadata?.publicly_accessible,
          storage_encrypted: w.metadata?.storage_encrypted ?? w.metadata?.encryption_type !== 'none',
          has_admin_access: w.metadata?.has_admin_access,
          can_escalate: w.metadata?.effective_permissions_summary?.can_escalate,
          cross_account_trusts: w.metadata?.cross_account_trusts,
        },
      });
    }

    // Phase 2 — provider-specific
    try {
      if (provider === 'gcp') await this.gcpRels(workloads);
      else if (provider === 'aws') await this.awsRels(workloads);
      else if (provider === 'azure') await this.azureRels(workloads);
      else this.onPremRels(workloads);
    } catch (e) { this.log(`${provider} scan: ${e.message}`, 'error'); }

    // Phase 3 — cross-cutting
    this.sharedIdentities(workloads);
    this.networkExposure(workloads);
    this.credentialNodes(workloads);

    // Phase 3.4 — AI service relationships
    this.aiServiceRels(workloads);

    // Phase 3.5 — Protocol detection (MCP / A2A)
    let protoResults = { nodes: [], relationships: [], findings: [] };
    try {
      const ProtocolScanner = require('./protocol-scanner');
      const proto = new ProtocolScanner();
      protoResults = await proto.scan(workloads);
      for (const n of protoResults.nodes) this.addNode(n);
      for (const r of protoResults.relationships) this.addRel(r);

      // Merge AI enrichments onto matching graph nodes
      // The aiEnrichments map is keyed by (w.id || w.name) from protocol-scanner.
      // We match against node.id (w:<key>), node.wid, and node.label for robustness.
      if (protoResults.aiEnrichments) {
        let merged = 0;
        for (const [wKey, enrichment] of Object.entries(protoResults.aiEnrichments)) {
          const matchNode = this.nodes.find(n =>
            n.id === `w:${wKey}` || n.wid === wKey || n.label === wKey || n.id === wKey
          );
          if (matchNode) {
            matchNode.ai_enrichment = enrichment;
            matchNode.meta = matchNode.meta || {};
            matchNode.meta.llm_providers = enrichment.llm_providers;
            matchNode.meta.models = enrichment.models;
            matchNode.meta.embeddings_and_vectors = enrichment.embeddings_and_vectors;
            matchNode.meta.frameworks = enrichment.frameworks;
            if (enrichment.fine_tuning) {
              matchNode.meta.fine_tuning = enrichment.fine_tuning;
            }
            if (enrichment.risk_flags && enrichment.risk_flags.length > 0) {
              matchNode.meta.ai_risk_flags = enrichment.risk_flags;
            }
            if (enrichment.credential_count > 0) {
              matchNode.meta.ai_credential_count = enrichment.credential_count;
            }
            if (enrichment.llm_gateways?.length > 0) {
              matchNode.meta.llm_gateways = enrichment.llm_gateways;
            }
            if (enrichment.llm_observability?.length > 0) {
              matchNode.meta.llm_observability = enrichment.llm_observability;
            }
            if (enrichment.cloud_ai_assets?.length > 0) {
              matchNode.meta.cloud_ai_assets = enrichment.cloud_ai_assets;
            }
            if (enrichment.ai_egress?.length > 0) {
              matchNode.meta.ai_egress = enrichment.ai_egress;
            }
            merged++;
          } else {
            this.log(`AI enrichment unmatched for key "${wKey}" — no graph node found`, 'warn');
          }
        }
        this.log(`AI enrichments merged: ${merged}/${Object.keys(protoResults.aiEnrichments).length} workloads`, 'success');
      }

      this.log(`Protocol scan: ${protoResults.nodes.length} nodes, ${protoResults.findings.length} findings`, 'success');
    } catch (e) { this.log('Protocol scan: ' + e.message, 'warn'); }

    // Phase 4 — attack paths
    const ap = this.computeAttackPaths(workloads);

    // Merge protocol scanner findings → attack paths (with finding_type for remediation)
    const protoFindingTypes = ['toxic-combo', 'a2a-no-auth', 'a2a-unsigned-card', 'mcp-static-credentials', 'static-external-credential'];
    for (const f of protoResults.findings.filter(f => protoFindingTypes.includes(f.type))) {
      // Compute blast radius: count workloads connected to the affected credential/resource
      const affectedWorkload = f.workload || 'unknown';
      // Find the workload node by label (not ID string matching which is unreliable)
      const wNode = this.nodes.find(n => (n.label || '') === affectedWorkload || (n.label || '').toLowerCase() === affectedWorkload.toLowerCase());
      const wNodeId = wNode?.id;
      const connectedNodes = new Set();
      if (wNodeId) {
        connectedNodes.add(wNodeId);
        // BFS 1-hop from the workload node
        for (const r of this.relationships) {
          const s = typeof r.source === 'object' ? r.source.id : r.source;
          const t = typeof r.target === 'object' ? r.target.id : r.target;
          if (s === wNodeId) connectedNodes.add(t);
          if (t === wNodeId) connectedNodes.add(s);
        }
      }
      const blastRadius = Math.max(1, connectedNodes.size);
      const entryPoints = [affectedWorkload];

      ap.push({
        id: f.type + ':' + affectedWorkload + (f.api_id ? ':' + f.api_id : ''),
        finding_type: f.type,
        title: f.title || f.type,
        severity: f.severity,
        description: f.message,
        recommendation: f.recommendation,
        workload: affectedWorkload,
        blast_radius: blastRadius,
        entry_points: entryPoints,
        owasp: f.owasp,
        env_keys: f.env_keys,
        api_id: f.api_id,
        credentials: f.env_keys || [],
      });
    }

    // ── Classification-based findings ──
    // Generate attack paths for workloads flagged by classifyWorkload()
    for (const w of workloads) {
      const wName = w.name || 'unknown';

      if (w.is_dormant && (w.dormancy_score || 0) >= 50) {
        ap.push({
          id: `zombie-workload:${wName}`,
          finding_type: 'zombie-workload',
          title: `Zombie Workload — ${wName}`,
          severity: 'high',
          description: `Workload has no recorded activity for an extended period. ${(w.dormancy_reasons || []).join('. ')}`,
          recommendation: 'Verify if workload is still needed. Quarantine credentials and schedule decommission if unused.',
          workload: wName,
          cloud_provider: w.cloud_provider || 'aws',
          blast_radius: 1,
          entry_points: [wName],
          dormancy_score: w.dormancy_score,
        });
      }

      if (w.is_rogue) {
        ap.push({
          id: `rogue-workload:${wName}`,
          finding_type: 'rogue-workload',
          title: `Rogue Workload — ${wName}`,
          severity: 'critical',
          description: `Workload is bypassing governance controls. ${(w.rogue_reasons || []).join('. ')}`,
          recommendation: 'Contain immediately — restrict access, require attestation, and escalate to security team.',
          workload: wName,
          cloud_provider: w.cloud_provider || 'aws',
          blast_radius: 3,
          entry_points: [wName],
          rogue_score: w.rogue_score,
        });
      }

      if (w.is_unused_iam) {
        const isEmptyGroup = w.type === 'iam-group' && (w.metadata?.member_count === 0 || w.metadata?.member_count === '0');
        ap.push({
          id: `unused-iam-role:${wName}`,
          finding_type: 'unused-iam-role',
          title: isEmptyGroup ? `Empty IAM Group — ${wName}` : `Unused IAM Identity — ${wName}`,
          severity: isEmptyGroup ? 'low' : 'medium',
          description: isEmptyGroup
            ? `IAM group has 0 members. Safe to delete — no active identities are affected.`
            : `IAM identity has not been used in over 90 days. Represents latent access risk if credentials are compromised.`,
          recommendation: isEmptyGroup ? 'Delete the empty group.' : 'Tag for review, detach policies, or schedule deletion after review period.',
          workload: wName,
          cloud_provider: w.cloud_provider || 'aws',
          blast_radius: 1,
          entry_points: [wName],
        });
      }

      if (w.is_publicly_exposed) {
        const hasApproval = (w.labels || {})['approved-public'] === 'true' ||
                            (w.labels || {})['approved_public'] === 'true';
        if (!hasApproval) {
          ap.push({
            id: `public-exposure-untagged:${wName}`,
            finding_type: 'public-exposure-untagged',
            title: `Unapproved Public Exposure — ${wName}`,
            severity: 'high',
            description: `Resource is publicly accessible without security approval. ${(w.exposure_reasons || []).join('. ')}`,
            recommendation: 'Require approved-public tag from security team or restrict public access.',
            workload: wName,
            cloud_provider: w.cloud_provider || 'aws',
            blast_radius: 2,
            entry_points: [wName],
          });
        }
      }
    }

    this.log(`Graph: ${this.nodes.length} nodes, ${this.relationships.length} edges, ${ap.length} attack paths`, 'success');

    return {
      nodes: this.nodes,
      relationships: this.relationships,
      attack_paths: ap,
      summary: {
        total_nodes: this.nodes.length,
        total_relationships: this.relationships.length,
        total_attack_paths: ap.length,
        critical_paths: ap.filter(p => p.severity === 'critical').length,
      },
      generated_at: new Date().toISOString(),
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // GCP Relationships
  // ═══════════════════════════════════════════════════════════════

  async gcpRels(workloads) {
    const { google } = require('googleapis');
    const auth = new google.auth.GoogleAuth({ scopes: ['https://www.googleapis.com/auth/cloud-platform'] });

    // Collect known SA emails
    const saEmails = new Set();
    workloads.forEach(w => { if (w.metadata?.email) saEmails.add(w.metadata.email); if (w.metadata?.service_account) saEmails.add(w.metadata.service_account); });

    // ── 1. IAM bindings ──
    let bindings = [];
    try {
      const crm = google.cloudresourcemanager({ version: 'v1', auth });
      const r = await crm.projects.getIamPolicy({ resource: this.projectId, requestBody: {} });
      bindings = r.data.bindings || [];
      this.log(`${bindings.length} IAM bindings`, 'success');
    } catch (e) { this.log(`IAM policy: ${e.message}`, 'warn'); }

    for (const b of bindings) {
      for (const m of b.members || []) {
        if (!m.startsWith('serviceAccount:')) continue;
        const email = m.replace('serviceAccount:', '');
        if (!saEmails.has(email)) continue;

        const rid = `role:gcp:${b.role}`;
        this.addNode({ id: rid, label: b.role.replace('roles/', ''), type: 'iam-role', group: 'permission', risk: this._gcpRisk(b.role) });
        const sn = this.findByEmail(email);
        if (sn) this.addRel({ source: sn.id, target: rid, type: 'has-role', critical: this._gcpHigh(b.role), discovered_by: 'GCP Resource Manager API', evidence: `Called getIamPolicy() on the GCP project. Found IAM binding granting ${b.role} to serviceAccount:${email}.` });
      }
    }

    // ── 2. Role → resource ──
    const RR = {
      'roles/editor': ['Cloud SQL', 'Secret Manager', 'GCS Buckets', 'Artifact Registry'],
      'roles/owner': ['ALL PROJECT RESOURCES'],
      'roles/viewer': ['Cloud SQL (read)', 'GCS Buckets (read)'],
      'roles/cloudsql.admin': ['Cloud SQL'], 'roles/cloudsql.client': ['Cloud SQL'],
      'roles/storage.admin': ['GCS Buckets'], 'roles/storage.objectAdmin': ['GCS Buckets'],
      'roles/secretmanager.admin': ['Secret Manager'], 'roles/secretmanager.secretAccessor': ['Secret Manager'],
      'roles/run.invoker': ['Cloud Run Services'], 'roles/run.admin': ['Cloud Run Services'],
      'roles/iam.serviceAccountUser': ['SA Impersonation'], 'roles/iam.serviceAccountTokenCreator': ['SA Token Creation'],
      'roles/compute.admin': ['Compute Engine'], 'roles/container.admin': ['GKE Clusters'],
    };
    const SENS = new Set(['Cloud SQL', 'Secret Manager', 'SA Impersonation', 'SA Token Creation', 'ALL PROJECT RESOURCES']);
    for (const rn of this.nodes.filter(n => n.id.startsWith('role:gcp:'))) {
      for (const res of RR[`roles/${rn.label}`] || []) {
        const rid = `res:gcp:${res.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
        this.addNode({ id: rid, label: res, type: 'resource', group: 'resource', sensitive: SENS.has(res) });
        this.addRel({ source: rn.id, target: rid, type: 'grants-access', critical: SENS.has(res), discovered_by: 'GCP IAM role definition', evidence: `GCP role ${rn.label} includes permissions that grant access to ${res}. Mapped from Google's role-to-resource permission matrix.` });
      }
    }

    // ── 3. SA → service (runs-as) ──
    for (const w of workloads) {
      if (w.type === 'service-account') continue;
      const sa = w.metadata?.service_account;
      if (!sa) continue;
      const sn = this.findByEmail(sa);
      const wn = this.nodes.find(n => n.wid === w.id && n.group !== 'identity');
      if (sn && wn) this.addRel({ source: sn.id, target: wn.id, type: 'runs-as', discovered_by: 'GCP Cloud Run API', evidence: `Queried Cloud Run service config for ${w.name}. The service_account field is set to ${sa}. All API calls from this service authenticate as this SA.` });
    }

    // ── 4. GCP data/network public exposure ──
    for (const w of workloads) {
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      if (w.type === 'gcs-bucket' && w.metadata?.is_public) {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'GCP Storage API', evidence: `Queried GCS bucket IAM policy for ${w.name}. Found allUsers or allAuthenticatedUsers grant — bucket is publicly readable.` });
      }
      if (w.type === 'cloud-sql' && w.metadata?.publicly_accessible) {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'GCP Cloud SQL Admin API', evidence: `Queried Cloud SQL instance ${w.name}. The ipConfiguration.authorizedNetworks includes 0.0.0.0/0 — instance is accessible from the public internet.` });
      }
      // Firewall rules that allow 0.0.0.0/0 ingress
      if (w.type === 'firewall-rule' && w.metadata?.allows_0_0_0_0 && w.metadata?.direction === 'INGRESS') {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'allows-ingress-from', critical: true, discovered_by: 'GCP Compute API', evidence: `Queried VPC firewall rules. Rule ${w.name} allows INGRESS from 0.0.0.0/0 — any IP can reach workloads behind this rule.` });
      }
    }
  }

  _gcpRisk(r) { return /owner|admin|editor/i.test(r) && !/viewer/i.test(r) ? 'high' : /serviceAccountUser|serviceAccountTokenCreator|secretAccessor/i.test(r) ? 'high' : 'low'; }
  _gcpHigh(r) { return /owner|editor|admin|serviceAccountUser|serviceAccountTokenCreator/i.test(r); }

  // ═══════════════════════════════════════════════════════════════
  // AWS Relationships
  // ═══════════════════════════════════════════════════════════════

  async awsRels(workloads) {
    let IAMClient, ListAttachedRolePoliciesCommand;
    try {
      ({ IAMClient, ListAttachedRolePoliciesCommand } = require('@aws-sdk/client-iam'));
    } catch { this.log('AWS IAM SDK not available', 'warn'); return; }

    const iam = new IAMClient({ region: this.config.region || 'us-east-1' });

    // ── Lambda/ECS → execution role → policies ──
    for (const w of workloads) {
      if (!w.metadata?.role) continue;
      const roleName = w.metadata.role.split('/').pop();
      const roleId = `role:aws:${roleName}`;
      this.addNode({ id: roleId, label: roleName, type: 'iam-role', group: 'permission', risk: 'medium' });
      const wn = this.nodes.find(n => n.wid === w.id);
      if (wn) this.addRel({ source: roleId, target: wn.id, type: 'runs-as', discovered_by: 'AWS IAM API', evidence: `Queried Lambda/ECS task configuration. Workload ${w.name} is configured with execution role ${roleName}. All AWS API calls from this workload authenticate as this role.` });

      try {
        const resp = await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));
        for (const p of resp.AttachedPolicies || []) {
          const pid = `policy:aws:${p.PolicyName}`;
          const isAdmin = /Admin|FullAccess|AdministratorAccess/i.test(p.PolicyName);
          this.addNode({
            id: pid, label: p.PolicyName, type: 'iam-policy', group: 'permission',
            risk: isAdmin ? 'high' : 'low',
            arn: p.PolicyArn || null,
            is_aws_managed: (p.PolicyArn || '').startsWith('arn:aws:iam::aws:policy/'),
            meta: { policy_arn: p.PolicyArn, is_admin: isAdmin },
          });
          this.addRel({ source: roleId, target: pid, type: 'has-policy', critical: isAdmin, discovered_by: 'AWS IAM API', evidence: `Called ListAttachedRolePolicies for role ${roleName}. Found policy ${p.PolicyName} (ARN: ${p.PolicyArn || 'unknown'}).${isAdmin ? ' This is an admin-level policy — high privilege.' : ''}` });

          // Map known policies → discovered storage/data nodes
          const policyResources = {
            S3: ['res:aws:s3', 'S3 Buckets'],
            DynamoDB: ['res:aws:dynamo', 'DynamoDB'],
            SecretsManager: ['res:aws:secrets', 'Secrets Manager'],
            RDS: ['res:aws:rds', 'RDS'],
            Administrator: ['res:aws:all', 'ALL AWS RESOURCES'],
            KMS: ['res:aws:kms', 'KMS Keys'],
          };
          for (const [pattern, [rid, label]] of Object.entries(policyResources)) {
            if (new RegExp(pattern, 'i').test(p.PolicyName)) {
              this.addNode({ id: rid, label, type: 'resource', group: 'resource', sensitive: true });
              this.addRel({ source: pid, target: rid, type: 'grants-access', critical: true, discovered_by: 'AWS IAM policy analysis', evidence: `Analyzed policy ${p.PolicyName}. Policy name pattern matches ${label} resources — grants access to these AWS services.` });
            }
          }

          // Link policy → actual discovered data store nodes via grants-access
          this._linkPolicyToDiscoveredNodes(pid, p.PolicyName);
        }
      } catch (e) { /* permission error */ }
    }

    // ── IAM Group memberships ──
    for (const w of workloads) {
      if (w.type !== 'iam-group') continue;
      const gNode = this.nodes.find(n => n.wid === w.id);
      if (!gNode) continue;
      for (const memberArn of w.metadata?.member_arns || []) {
        const userName = memberArn.split('/').pop();
        const userNode = this.nodes.find(n => n.label === userName && n.type === 'iam-user');
        if (userNode) {
          this.addRel({ source: userNode.id, target: gNode.id, type: 'member-of-group', discovered_by: 'AWS IAM API', evidence: `Called GetGroup for ${w.name}. User ${userName} is listed as a member. The user inherits all policies attached to this group.` });
        }
      }
      // Group → policies
      for (const policyName of w.metadata?.attached_policies || []) {
        const pid = `policy:aws:${policyName}`;
        const isAdmin = /Admin|FullAccess|AdministratorAccess/i.test(policyName);
        const policyArn = w.metadata?.policy_arns?.[policyName] || null;
        this.addNode({
          id: pid, label: policyName, type: 'iam-policy', group: 'permission',
          risk: isAdmin ? 'high' : 'low',
          arn: policyArn,
          is_aws_managed: (policyArn || '').startsWith('arn:aws:iam::aws:policy/'),
          meta: { policy_arn: policyArn, is_admin: isAdmin },
        });
        this.addRel({ source: gNode.id, target: pid, type: 'has-policy', critical: isAdmin, discovered_by: 'AWS IAM API', evidence: `Called ListAttachedGroupPolicies for group ${w.name}. Found policy ${policyName}.${isAdmin ? ' Admin-level policy — all group members inherit high privileges.' : ''}` });
      }
    }

    // ── Cross-account trust chains ──
    for (const w of workloads) {
      if (w.type !== 'iam-role') continue;
      const trusts = w.metadata?.cross_account_trusts || [];
      if (trusts.length === 0) continue;
      const roleNode = this.nodes.find(n => n.wid === w.id);
      if (!roleNode) continue;
      for (const trust of trusts) {
        const extId = `ext-acct:${trust.account_id}`;
        const label = trust.account_id === '*' ? 'ANY AWS Account' : `Account ${trust.account_id}`;
        this.addNode({ id: extId, label, type: 'external-account', group: 'external', risk: trust.account_id === '*' ? 'critical' : 'high' });
        this.addRel({
          source: extId, target: roleNode.id, type: 'can-assume',
          critical: !trust.has_external_id, has_external_id: trust.has_external_id,
          discovered_by: 'AWS IAM trust policy', evidence: `Analyzed AssumeRolePolicyDocument for role ${w.name}. Account ${trust.account_id} is listed as a trusted principal.${trust.has_external_id ? ' External ID condition is present (good).' : ' No external ID condition — any service in that account can assume this role (confused deputy risk).'}`,
        });
      }
    }

    // ── Permission boundaries ──
    for (const w of workloads) {
      if (!w.metadata?.permission_boundary_arn) continue;
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      const boundaryName = w.metadata.permission_boundary_arn.split('/').pop();
      const bid = `boundary:aws:${boundaryName}`;
      this.addNode({ id: bid, label: `Boundary: ${boundaryName}`, type: 'permission-boundary', group: 'policy', risk: 'info' });
      this.addRel({ source: wn.id, target: bid, type: 'has-permission-boundary', discovered_by: 'AWS IAM API', evidence: `Queried IAM role/user metadata. Permission boundary ${boundaryName} is attached — this limits the maximum permissions regardless of attached policies.` });
    }

    // ── Privilege escalation edges ──
    for (const w of workloads) {
      if (!w.metadata?.effective_permissions_summary?.can_escalate) continue;
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      // Find admin roles that could be the escalation target
      const adminRoles = workloads.filter(r => r.type === 'iam-role' && r.metadata?.has_admin_access && r.name !== w.name);
      for (const target of adminRoles.slice(0, 3)) {
        const tn = this.nodes.find(n => n.wid === target.id);
        if (tn) this.addRel({ source: wn.id, target: tn.id, type: 'can-escalate-to', critical: true, discovered_by: 'AWS privilege escalation analysis', evidence: `Analyzed effective permissions for ${w.name}. This identity has iam:PassRole or sts:AssumeRole permissions that allow escalation to the admin role ${target.name}.` });
      }
    }

    // ── Storage/Data nodes: public exposure ──
    for (const w of workloads) {
      if (w.type === 's3-bucket' && w.metadata?.is_public) {
        const wn = this.nodes.find(n => n.wid === w.id);
        if (wn) {
          this._expNode();
          this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'AWS S3 API', evidence: `Queried S3 bucket policy and ACL for ${w.name}. Public access is enabled — bucket contents may be readable from the internet.` });
        }
      }
      if (w.type === 'rds-instance' && w.metadata?.publicly_accessible) {
        const wn = this.nodes.find(n => n.wid === w.id);
        if (wn) {
          this._expNode();
          this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'AWS RDS API', evidence: `Queried RDS instance ${w.name}. PubliclyAccessible is set to true — the database endpoint is reachable from outside the VPC.` });
        }
      }
    }

    // ── Network: SG → workloads, LB → workloads, VPC membership ──
    for (const w of workloads) {
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      // EC2 → security groups
      if (w.type === 'ec2' && w.metadata?.security_groups) {
        for (const sgId of w.metadata.security_groups) {
          const sgNode = this.nodes.find(n => n.type === 'security-group' && n.meta?.group_id === sgId);
          if (sgNode) this.addRel({ source: wn.id, target: sgNode.id, type: 'protected-by', discovered_by: 'AWS EC2 API', evidence: `Queried EC2 instance ${w.name}. Security group ${sgId} is attached — controls inbound/outbound traffic to this instance.` });
        }
      }
      // EC2/RDS → VPC
      if (['ec2', 'rds-instance'].includes(w.type) && w.metadata?.vpc_id) {
        const vpcNode = this.nodes.find(n => n.type === 'vpc' && n.meta?.vpc_id === w.metadata.vpc_id);
        if (vpcNode) this.addRel({ source: wn.id, target: vpcNode.id, type: 'member-of-vpc', discovered_by: 'AWS EC2/RDS API', evidence: `Queried instance metadata for ${w.name}. Deployed in VPC ${w.metadata.vpc_id} — can communicate with other resources in the same VPC.` });
      }
      // SG allows public ingress
      if (w.type === 'security-group' && w.metadata?.allows_public_ingress) {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'allows-ingress-from', critical: true, discovered_by: 'AWS EC2 API', evidence: `Queried security group ${w.name}. Inbound rules include 0.0.0.0/0 — any IP address can reach instances behind this security group.` });
      }
    }
  }

  /**
   * Link a policy node to discovered data store nodes via pattern matching
   */
  _linkPolicyToDiscoveredNodes(policyNodeId, policyName) {
    const dataStoreTypes = ['s3-bucket', 'rds-instance', 'rds-cluster', 'dynamodb-table'];
    const pn = policyName.toLowerCase();
    for (const n of this.nodes) {
      if (!dataStoreTypes.includes(n.type)) continue;
      // Match policy name patterns to node types
      if ((n.type === 's3-bucket' && /s3/i.test(pn)) ||
          (n.type.startsWith('rds') && /rds/i.test(pn)) ||
          (n.type === 'dynamodb-table' && /dynamo/i.test(pn)) ||
          /administrator|fullaccess/i.test(pn)) {
        this.addRel({ source: policyNodeId, target: n.id, type: 'grants-access', critical: true, discovered_by: 'AWS IAM policy analysis', evidence: `Cross-referenced policy ${policyName} with discovered data stores. Policy name matches ${n.label} — this policy likely grants access to this resource.` });
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Azure Relationships
  // ═══════════════════════════════════════════════════════════════

  async azureRels(workloads) {
    let DefaultAzureCredential, AuthorizationManagementClient;
    try {
      ({ DefaultAzureCredential } = require('@azure/identity'));
      ({ AuthorizationManagementClient } = require('@azure/arm-authorization'));
    } catch { this.log('Azure auth SDK not available', 'warn'); return; }

    const subId = this.config.subscriptionId || process.env.AZURE_SUBSCRIPTION_ID;
    if (!subId) return;
    const client = new AuthorizationManagementClient(new DefaultAzureCredential(), subId);

    // Map principal IDs → workloads
    const pMap = {};
    workloads.forEach(w => { if (w.metadata?.principal_id) pMap[w.metadata.principal_id] = w; });

    // ── Role assignments ──
    try {
      const assigns = [];
      for await (const a of client.roleAssignments.listForSubscription()) assigns.push(a);
      this.log(`${assigns.length} Azure role assignments`, 'success');

      for (const a of assigns) {
        const w = pMap[a.principalId];
        if (!w) continue;
        let roleName = a.roleDefinitionId.split('/').pop();
        try { roleName = (await client.roleDefinitions.getById(a.roleDefinitionId)).roleName || roleName; } catch {}

        const rid = `role:az:${roleName.toLowerCase().replace(/\s+/g, '-')}`;
        const hp = ['Owner', 'Contributor', 'User Access Administrator'].includes(roleName);
        this.addNode({ id: rid, label: roleName, type: 'iam-role', group: 'permission', risk: hp ? 'high' : 'low' });
        const wn = this.nodes.find(n => n.wid === w.id);
        if (wn) this.addRel({ source: wn.id, target: rid, type: 'has-role', critical: hp, discovered_by: 'Azure Authorization API', evidence: `Listed role assignments for subscription. Found ${roleName} assigned to ${w.name}.${hp ? ' This is a high-privilege role (Owner/Contributor).' : ''}` });
      }
    } catch (e) { this.log(`Azure roles: ${e.message}`, 'warn'); }

    // ── Managed identities ──
    for (const w of workloads) {
      if (!w.metadata?.has_managed_identity) continue;
      const mid = `mi:az:${w.metadata.principal_id || w.name}`;
      this.addNode({ id: mid, label: `MI: ${w.name}`, type: 'managed-identity', group: 'identity' });
      const wn = this.nodes.find(n => n.wid === w.id);
      if (wn) this.addRel({ source: mid, target: wn.id, type: 'runs-as', discovered_by: 'Azure Resource Manager API', evidence: `Queried resource identity configuration for ${w.name}. System-assigned managed identity is enabled (principal: ${w.metadata.principal_id || 'auto'}). All Azure API calls from this resource authenticate as this identity.` });
    }

    // ── Azure data/network public exposure ──
    for (const w of workloads) {
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      if (w.type === 'storage-account' && w.metadata?.allow_blob_public_access) {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'Azure Storage API', evidence: `Queried storage account ${w.name}. allowBlobPublicAccess is true — blob containers may be readable without authentication.` });
      }
      if (w.type === 'azure-sql' && w.metadata?.public_network_access === 'Enabled') {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'publicly-exposes', critical: true, discovered_by: 'Azure SQL API', evidence: `Queried Azure SQL server ${w.name}. publicNetworkAccess is Enabled — database is reachable from the public internet.` });
      }
      if (w.type === 'nsg' && w.metadata?.allows_public_ingress) {
        this._expNode();
        this.addRel({ source: 'exp:public', target: wn.id, type: 'allows-ingress-from', critical: true, discovered_by: 'Azure Network API', evidence: `Queried NSG ${w.name}. Found inbound rule allowing traffic from 0.0.0.0/0 or Internet service tag.` });
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // On-Prem / Docker / Kubernetes
  // ═══════════════════════════════════════════════════════════════

  onPremRels(workloads) {
    for (const w of workloads) {
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;

      // Container → host
      if (w.metadata?.host) {
        const hid = `host:${w.metadata.host}`;
        this.addNode({ id: hid, label: w.metadata.host, type: 'host', group: 'infrastructure' });
        this.addRel({ source: wn.id, target: hid, type: 'runs-on', discovered_by: 'Docker Engine API', evidence: `Queried container inspect for ${w.name}. Container is running on host ${w.metadata.host}. Host compromise would expose this container.` });
      }

      // K8s service account
      if (w.metadata?.service_account_name) {
        const sid = `k8s-sa:${w.metadata.service_account_name}`;
        this.addNode({ id: sid, label: w.metadata.service_account_name, type: 'service-account', group: 'identity' });
        this.addRel({ source: sid, target: wn.id, type: 'runs-as', discovered_by: 'Kubernetes API', evidence: `Queried pod spec for ${w.name}. serviceAccountName is set to ${w.metadata.service_account_name}. Pod authenticates to the K8s API server using this service account's token.` });
      }

      // Port bindings → exposure
      if (Array.isArray(w.metadata?.ports)) {
        for (const p of w.metadata.ports) {
          if (p.hostIp === '0.0.0.0' || p.public) {
            this._expNode();
            this.addRel({ source: wn.id, target: 'exp:public', type: 'exposed-via', critical: true, discovered_by: 'Docker Engine API', evidence: `Queried container port bindings. Port ${p.containerPort || p.port || '?'} is mapped to host ${p.hostIp}:${p.hostPort || '?'} — accessible from outside the container network.` });
          }
        }
      }

      // SPIFFE ID present → add identity link
      if (w.spiffe_id) {
        const sid = `spiffe:${w.spiffe_id}`;
        this.addNode({ id: sid, label: w.spiffe_id.split('/').pop(), type: 'spiffe-id', group: 'identity' });
        this.addRel({ source: sid, target: wn.id, type: 'identifies', discovered_by: 'Workload registration metadata', evidence: `Workload registered with SPIFFE identity ${w.spiffe_id}. This cryptographic identity is issued by the SPIRE server and uniquely identifies this workload across the mesh.` });
      }
    }

    // Shared Docker network → communicates-with edges
    // Group workloads by network name and link those on the same network
    const networkMap = {}; // networkName → [{ w, wn }]
    for (const w of workloads) {
      const nets = w.metadata?.networks;
      if (!Array.isArray(nets) || nets.length === 0) continue;
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      for (const net of nets) {
        (networkMap[net] = networkMap[net] || []).push({ w, wn });
      }
    }
    for (const [net, members] of Object.entries(networkMap)) {
      if (members.length <= 1) continue;
      // Hub-and-spoke: connect each container to a network hub node (avoids O(n²) pairwise mesh)
      const netId = `net:${net}`;
      this.addNode({ id: netId, label: net, type: 'network', group: 'infrastructure' });
      for (const { w, wn } of members) {
        this.addRel({ source: wn.id, target: netId, type: 'member-of', network: net, discovered_by: 'Docker Engine API', evidence: `Queried Docker network inspect for '${net}'. Container ${w.name} is a member — can communicate with all ${members.length} containers on this network.` });
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Cross-Cutting: Shared Identities, Exposure, Credentials
  // ═══════════════════════════════════════════════════════════════

  sharedIdentities(workloads) {
    const usage = {};
    for (const w of workloads) {
      const sa = w.metadata?.service_account || w.metadata?.email;
      if (!sa || w.type === 'service-account') continue;
      (usage[sa] = usage[sa] || []).push(w);
    }
    for (const [sa, svcs] of Object.entries(usage)) {
      if (svcs.length <= 1) continue;
      // Hub-and-spoke: link each workload to the SA node, not pairwise O(n²)
      const saNode = this.nodes.find(n => n.label === sa || n.wid === sa || n.email === sa);
      if (!saNode) continue;
      for (const svc of svcs) {
        const wNode = this.nodes.find(n => n.wid === svc.id);
        if (!wNode) continue;
        // Check if runs-as edge already exists (runs-as direction: SA→workload)
        const existingEdge = this.relationships.find(r =>
          r.type === 'runs-as' && (
            (r.source === saNode.id && r.target === wNode.id) ||
            (r.source === wNode.id && r.target === saNode.id)
          ));
        if (existingEdge) {
          // Annotate existing edge with shared count
          existingEdge.sharedCount = svcs.length;
          existingEdge.critical = true;
          existingEdge.evidence = `${svcs.length} services share this SA (${sa}). Compromising any one gives the attacker access to all.`;
        } else {
          // Add shares-identity edge to SA node (hub-and-spoke, not pairwise)
          this.addRel({
            source: wNode.id, target: saNode.id,
            type: 'shares-identity', critical: true,
            sharedSA: sa, sharedCount: svcs.length,
            discovered_by: 'GCP Cloud Run API',
            evidence: `${svcs.length} services share SA ${sa}. Compromising any one grants access to all.`,
          });
        }
      }
    }
  }

  networkExposure(workloads) {
    for (const w of workloads) {
      const wn = this.nodes.find(n => n.wid === w.id);
      if (!wn) continue;
      const isPublic = w.metadata?.ingress === 'INGRESS_TRAFFIC_ALL' ||
                       w.metadata?.has_external_ip || w.metadata?.has_public_ip || w.metadata?.public_ip;
      if (isPublic) { this._expNode(); this.addRel({ source: wn.id, target: 'exp:public', type: 'exposed-via', critical: true, discovered_by: 'GCP Cloud Run API', evidence: `Queried ingress settings for ${w.name}. Ingress is set to INGRESS_TRAFFIC_ALL — service accepts requests from the public internet, not just internal VPC.` }); }
      if (w.metadata?.ingress === 'INGRESS_TRAFFIC_INTERNAL_ONLY') {
        this.addNode({ id: 'exp:internal', label: 'Internal VPC', type: 'exposure', group: 'exposure', risk: 'low' });
        this.addRel({ source: wn.id, target: 'exp:internal', type: 'exposed-via', discovered_by: 'GCP Cloud Run API', evidence: `Queried ingress settings for ${w.name}. Ingress is INGRESS_TRAFFIC_INTERNAL_ONLY — only reachable from within the VPC.` });
      }
    }
  }

  credentialNodes(workloads) {
    for (const w of workloads) {
      if (w.type !== 'service-account' || !(w.metadata?.user_managed_keys > 0)) continue;
      const age = w.metadata.oldest_key_age_days || 0;
      const kid = `key:${w.cloud_provider}:${w.name}`;
      this.addNode({ id: kid, label: `User Key (${age}d)`, type: 'credential', group: 'credential', age_days: age, risk: age > 90 ? 'critical' : age > 30 ? 'medium' : 'low' });
      const sn = this.nodes.find(n => n.wid === w.id);
      if (sn) this.addRel({ source: sn.id, target: kid, type: 'has-key', critical: age > 90, discovered_by: 'GCP IAM API', evidence: `Listed service account keys via iam.serviceAccountKeys.list(). Found user-managed key that is ${age} days old.${age > 90 ? ' Exceeds 90-day rotation policy — high risk of credential compromise.' : ''}` });
    }
  }

  _expNode() { this.addNode({ id: 'exp:public', label: 'Public Internet', type: 'exposure', group: 'exposure', risk: 'critical' }); }

  // ═══════════════════════════════════════════════════════════════
  // AI Service Relationships
  // ═══════════════════════════════════════════════════════════════

  aiServiceRels(workloads) {
    const aiEndpoints = workloads.filter(w =>
      ['vertex-ai-endpoint', 'bedrock-model', 'sagemaker-endpoint', 'azure-openai-deployment'].includes(w.type)
    );
    const aiModels = workloads.filter(w => w.type === 'vertex-ai-model');

    if (aiEndpoints.length === 0 && aiModels.length === 0) return;
    this.log(`AI service relationships: ${aiEndpoints.length} endpoints, ${aiModels.length} models`);

    // Link AI endpoints to their service accounts
    for (const ep of aiEndpoints) {
      const epNode = this.nodes.find(n => n.wid === ep.id || n.label === ep.name);
      if (!epNode) continue;

      const sa = ep.metadata?.service_account || ep.metadata?.ai_asset?.service_account;
      if (sa) {
        const saNode = this.findByEmail(sa);
        if (saNode) {
          this.addRel({ source: saNode.id, target: epNode.id, type: 'runs-ai-endpoint', critical: false, discovered_by: 'GCP Vertex AI API', evidence: `Queried AI endpoint ${ep.name}. The endpoint runs under service account ${sa}. API requests to this endpoint authenticate as this SA.` });
        }
      }

      // Link endpoint to its deployed models
      const deployedModels = ep.metadata?.deployed_models || [];
      for (const dm of deployedModels) {
        if (!dm.model_id) continue;
        const modelNode = this.nodes.find(n =>
          n.type === 'vertex-ai-model' && (n.meta?.model_id === dm.model_id || n.label === dm.display_name)
        );
        if (modelNode) {
          this.addRel({ source: epNode.id, target: modelNode.id, type: 'deploys-model', critical: false, discovered_by: 'GCP Vertex AI API', evidence: `Queried endpoint deployedModels. Model ${dm.display_name || dm.model_id} is deployed on this endpoint. Predictions route through this model.` });
        }
      }

      // Flag publicly accessible AI endpoints
      const accessPattern = ep.metadata?.access_pattern || ep.metadata?.ai_asset?.access_pattern;
      if (accessPattern === 'public') {
        this._expNode();
        this.addRel({ source: 'exp:public', target: epNode.id, type: 'public-ai-endpoint', critical: true, discovered_by: 'GCP Vertex AI API', evidence: `Queried endpoint access configuration for ${ep.name}. Access pattern is 'public' — model predictions are callable without VPC restriction.` });
      }
    }

    // Link workloads that use AI APIs to AI service nodes
    for (const w of workloads) {
      if (aiEndpoints.includes(w) || aiModels.includes(w)) continue;
      if (w.type === 'ai-api-enabled') continue;
      const wNode = this.nodes.find(n => n.wid === w.id || n.label === w.name);
      if (!wNode) continue;

      // Check if workload has Vertex AI env vars → link to Vertex endpoints
      const env = w.metadata?.env || {};
      const envKeys = Object.keys(env);
      const usesVertexAI = envKeys.some(k => /VERTEX|GOOGLE_AI|GEMINI/i.test(k));
      if (usesVertexAI) {
        for (const ep of aiEndpoints.filter(e => e.cloud_provider === 'gcp')) {
          const epNode = this.nodes.find(n => n.wid === ep.id || n.label === ep.name);
          if (epNode) {
            this.addRel({ source: wNode.id, target: epNode.id, type: 'calls-ai-endpoint', critical: false, discovered_by: 'Container environment scan', evidence: `Inspected environment variables for ${w.name}. Found VERTEX/GOOGLE_AI/GEMINI env vars indicating this workload calls Vertex AI. Linked to endpoint ${ep.name}.` });
          }
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Attack Path Computation
  // ═══════════════════════════════════════════════════════════════

  computeAttackPaths(workloads) {
    const paths = [];

    // Build adjacency list (bidirectional for identity relationships)
    const adj = {};
    const addEdge = (s, t) => { (adj[s] = adj[s] || []).push(t); };
    for (const r of this.relationships) {
      addEdge(r.source, r.target);
      if (['runs-as', 'shares-identity', 'identifies'].includes(r.type)) addEdge(r.target, r.source);
    }

    // BFS from a set of start nodes
    const bfs = (starts) => {
      const visited = new Set();
      const q = [...starts];
      while (q.length) {
        const c = q.shift();
        if (visited.has(c)) continue;
        visited.add(c);
        for (const t of adj[c] || []) if (!visited.has(t)) q.push(t);
      }
      return visited;
    };

    // ── 1. Shared SA blast radius ──
    const usage = {};
    for (const w of workloads) {
      const sa = w.metadata?.service_account || w.metadata?.email;
      if (!sa || w.type === 'service-account') continue;
      (usage[sa] = usage[sa] || []).push(w);
    }
    for (const [sa, svcs] of Object.entries(usage)) {
      if (svcs.length <= 1) continue;
      const starts = svcs.map(s => `w:${s.id || s.name}`);
      const reached = bfs(starts);
      const pubExposed = svcs.filter(s => s.metadata?.ingress === 'INGRESS_TRAFFIC_ALL' || s.metadata?.has_external_ip);
      const sensitiveHit = [...reached].filter(id => this.nodes.find(n => n.id === id)?.sensitive);
      paths.push({
        id: `shared-sa:${sa.split('@')[0]}`,
        finding_type: 'shared-sa',
        title: `Shared SA: ${sa.split('@')[0]}`,
        severity: pubExposed.length > 0 ? 'critical' : 'high',
        description: `${svcs.length} services share ${sa.split('@')[0]}.${pubExposed.length ? ` ${pubExposed.length} publicly exposed.` : ''} Compromising any gives attacker the SA identity for all.`,
        workload: pubExposed[0]?.name || svcs[0]?.name || sa.split('@')[0],
        nodes: [...reached],
        blast_radius: reached.size,
        entry_points: pubExposed.map(s => s.name),
        sensitive_targets: sensitiveHit,
      });
    }

    // ── 2. Key leak → sensitive resources ──
    for (const key of this.nodes.filter(n => n.type === 'credential')) {
      const reached = bfs([key.id]);
      const sensitive = [...reached].filter(id => { const n = this.nodes.find(x => x.id === id); return n?.sensitive || n?.risk === 'high'; });
      if (sensitive.length > 0) {
        paths.push({
          id: `key-leak:${key.id}`,
          finding_type: 'key-leak',
          title: `Key Leak: ${key.label}`,
          severity: key.risk === 'critical' ? 'critical' : 'high',
          description: `User-managed key (${key.age_days || 0}d old). If leaked → ${sensitive.length} sensitive resources reachable.`,
          workload: key.label,
          nodes: [...reached],
          blast_radius: reached.size,
          entry_points: [key.label],
          sensitive_targets: sensitive,
        });
      }
    }

    // ── 3. Public → internal pivot ──
    const pubNodes = this.nodes.filter(n => this.relationships.some(r => r.source === n.id && r.target === 'exp:public'));
    const intNodes = this.nodes.filter(n => this.relationships.some(r => r.source === n.id && r.target === 'exp:internal'));
    if (pubNodes.length > 0 && intNodes.length > 0) {
      const pubReach = bfs(pubNodes.map(n => n.id));
      const intReached = intNodes.filter(n => pubReach.has(n.id));
      if (intReached.length > 0) {
        paths.push({
          id: 'public-internal-pivot',
          finding_type: 'public-internal-pivot',
          title: 'Public → Internal Pivot',
          severity: 'critical',
          description: `${pubNodes.length} public services can reach ${intReached.length} internal services via shared identity. Public endpoint compromise enables lateral movement.`,
          workload: pubNodes[0]?.label || '',
          nodes: [...pubReach],
          blast_radius: pubReach.size,
          entry_points: pubNodes.map(n => n.label),
          sensitive_targets: intReached.map(n => n.id),
        });
      }
    }

    // ── 4. Over-privileged roles ──
    for (const role of this.nodes.filter(n => n.type === 'iam-role' && n.risk === 'high')) {
      const holders = this.relationships.filter(r => r.target === role.id && r.type === 'has-role').map(r => r.source);
      if (!holders.length) continue;
      const reached = bfs([role.id]);
      const sensitive = [...reached].filter(id => this.nodes.find(n => n.id === id)?.sensitive);
      if (sensitive.length) {
        paths.push({
          id: `over-priv:${role.label}`,
          finding_type: 'over-privileged',
          title: `Over-Privileged: ${role.label}`,
          severity: 'high',
          description: `${holders.length} identity(s) hold ${role.label} → ${sensitive.length} sensitive resources.`,
          workload: this.nodes.find(n => n.id === holders[0])?.label || holders[0] || '',
          nodes: [...reached],
          blast_radius: reached.size,
          entry_points: holders.map(h => this.nodes.find(n => n.id === h)?.label || h),
          sensitive_targets: sensitive,
        });
      }
    }

    // ── 5. Privilege escalation to admin ──
    const escalators = this.nodes.filter(n => n.meta?.can_escalate);
    for (const esc of escalators) {
      const escalationTargets = this.relationships
        .filter(r => r.source === esc.id && r.type === 'can-escalate-to')
        .map(r => r.target);
      if (escalationTargets.length === 0) continue;
      const reached = bfs([esc.id]);
      paths.push({
        id: `priv-escalation:${esc.label}`,
        finding_type: 'privilege-escalation',
        title: `Privilege Escalation: ${esc.label}`,
        severity: 'critical',
        description: `${esc.label} can escalate to ${escalationTargets.length} admin role(s) via iam:PassRole or similar. Full admin access reachable.`,
        workload: esc.label,
        nodes: [...reached],
        blast_radius: reached.size,
        entry_points: [esc.label],
        sensitive_targets: escalationTargets,
      });
    }

    // ── 6. Cross-account trust ──
    const extAccounts = this.nodes.filter(n => n.type === 'external-account');
    for (const ext of extAccounts) {
      const canAssume = this.relationships.filter(r => r.source === ext.id && r.type === 'can-assume');
      if (canAssume.length === 0) continue;
      const targetRoles = canAssume.map(r => r.target);
      const reached = bfs(targetRoles);
      const sensitive = [...reached].filter(id => this.nodes.find(n => n.id === id)?.sensitive);
      paths.push({
        id: `cross-account:${ext.label}`,
        finding_type: 'cross-account-trust',
        title: `Cross-Account Trust: ${ext.label}`,
        severity: ext.label.includes('ANY') ? 'critical' : 'high',
        description: `${ext.label} can assume ${canAssume.length} role(s). ${canAssume.some(r => !r.has_external_id) ? 'No ExternalId required — vulnerable to confused deputy.' : ''}`,
        workload: targetRoles[0] ? (this.nodes.find(n => n.id === targetRoles[0])?.label || '') : '',
        nodes: [...reached],
        blast_radius: reached.size,
        entry_points: [ext.label],
        sensitive_targets: sensitive,
      });
    }

    // ── 7. Unbounded admin (admin without permission boundary) ──
    // Skip IAM groups flagged as unused — empty groups have no active admin risk
    const unusedNames = new Set(workloads.filter(w => w.is_unused_iam).map(w => (w.name || '').toLowerCase()));
    const adminNoBoundary = this.nodes.filter(n =>
      n.meta?.has_admin_access &&
      !(n.type === 'iam-group' && unusedNames.has((n.label || '').toLowerCase())) &&
      !this.relationships.some(r => r.source === n.id && r.type === 'has-permission-boundary')
    );
    if (adminNoBoundary.length > 0) {
      for (const admin of adminNoBoundary.slice(0, 5)) {
        const reached = bfs([admin.id]);
        paths.push({
          id: `unbounded-admin:${admin.label}`,
          finding_type: 'unbounded-admin',
          title: `Unbounded Admin: ${admin.label}`,
          severity: 'high',
          description: `${admin.label} has admin access without a permission boundary. No guardrails on what this identity can do.`,
          workload: admin.label,
          nodes: [...reached],
          blast_radius: reached.size,
          entry_points: [admin.label],
          sensitive_targets: [],
        });
      }
    }

    // ── 8. Public data exposure (S3, RDS, GCS publicly accessible) ──
    const publicDataNodes = this.nodes.filter(n =>
      ['data-store'].includes(this.groupOf(n.type)) && n.meta?.is_public
    );
    for (const pub of publicDataNodes) {
      paths.push({
        id: `public-data:${pub.label}`,
        finding_type: pub.type.includes('rds') || pub.type.includes('sql') ? 'public-database' : 'public-data-exposure',
        title: `Public ${pub.type.includes('rds') || pub.type.includes('sql') ? 'Database' : 'Data Store'}: ${pub.label}`,
        severity: 'critical',
        description: `${pub.label} (${pub.type}) is publicly accessible. Data may be exposed to the internet.`,
        workload: pub.label,
        nodes: [pub.id],
        blast_radius: 1,
        entry_points: ['Public Internet'],
        sensitive_targets: [pub.id],
      });
    }

    // ── 9. Unencrypted data stores ──
    const unencryptedStores = this.nodes.filter(n =>
      ['data-store'].includes(this.groupOf(n.type)) && n.meta?.storage_encrypted === false
    );
    for (const store of unencryptedStores) {
      paths.push({
        id: `unencrypted:${store.label}`,
        finding_type: 'unencrypted-data-store',
        title: `Unencrypted: ${store.label}`,
        severity: 'high',
        description: `${store.label} (${store.type}) does not have encryption at rest enabled.`,
        workload: store.label,
        nodes: [store.id],
        blast_radius: 1,
        entry_points: [store.label],
        sensitive_targets: [store.id],
      });
    }

    // ── 10. Internet-to-data path (Wiz headline) ──
    // Traverse: public exposure → network/LB → compute → identity → data
    if (this._nids.has('exp:public')) {
      const pubReach = bfs(['exp:public']);
      const dataHits = [...pubReach].filter(id => {
        const n = this.nodes.find(x => x.id === id);
        return n && ['data-store'].includes(this.groupOf(n.type));
      });
      if (dataHits.length > 0) {
        paths.push({
          id: 'internet-to-data',
          finding_type: 'internet-to-data',
          title: 'Internet → Data Store Path',
          severity: 'critical',
          description: `${dataHits.length} data store(s) reachable from public internet via identity/network chains. Full path: public exposure → compute → IAM → data.`,
          workload: this.nodes.find(n => n.id === dataHits[0])?.label || '',
          nodes: [...pubReach],
          blast_radius: pubReach.size,
          entry_points: ['Public Internet'],
          sensitive_targets: dataHits,
        });
      }
    }

    // ── 11. Overly permissive security groups ──
    const permissiveSGs = this.nodes.filter(n =>
      n.type === 'security-group' && this.relationships.some(r => r.target === n.id && r.type === 'allows-ingress-from' && r.source === 'exp:public')
    );
    for (const sg of permissiveSGs) {
      const protectedWorkloads = this.relationships.filter(r => r.target === sg.id && r.type === 'protected-by').map(r => r.source);
      if (protectedWorkloads.length > 0) {
        paths.push({
          id: `permissive-sg:${sg.label}`,
          finding_type: 'overly-permissive-sg',
          title: `Overly Permissive SG: ${sg.label}`,
          severity: 'high',
          description: `Security group ${sg.label} allows public ingress and protects ${protectedWorkloads.length} workload(s).`,
          workload: this.nodes.find(n => n.id === protectedWorkloads[0])?.label || sg.label,
          nodes: [sg.id, ...protectedWorkloads],
          blast_radius: protectedWorkloads.length + 1,
          entry_points: ['Public Internet'],
          sensitive_targets: protectedWorkloads,
        });
      }
    }

    paths.sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] || 9) - ({ critical: 0, high: 1, medium: 2, low: 3 }[b.severity] || 9));
    return paths;
  }
}

module.exports = RelationshipScanner;
