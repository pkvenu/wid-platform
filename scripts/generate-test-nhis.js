#!/usr/bin/env node

// =============================================================================
// Comprehensive NHI Test Data Generator
// Creates realistic workload identities with attestation, shadow/dormant detection
// =============================================================================

const { Client } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@localhost:5432/workload_identity';

// =============================================================================
// Utility Functions
// =============================================================================

function generateSpiffeId(trustDomain, type, name) {
  return `spiffe://${trustDomain}/${type}/${name}`;
}

function generateARN(service, region, accountId, resourceType, resourceName) {
  return `arn:aws:${service}:${region}:${accountId}:${resourceType}/${resourceName}`;
}

// =============================================================================
// Test NHI Definitions - 50+ Realistic Workloads
// =============================================================================

const TEST_NHIS = {
  // =========================================================================
  // AI AGENTS (6 workloads)
  // =========================================================================
  aiAgents: [
    {
      name: 'claude-customer-support-agent',
      type: 'lambda',
      namespace: 'ai-services',
      environment: 'production',
      category: 'ai-agent',
      subcategory: 'anthropic-claude',
      is_ai_agent: true,
      
      spiffe_id: 'spiffe://company.com/aws/lambda/us-east-1/claude-customer-support-agent',
      arn: 'arn:aws:lambda:us-east-1:123456789012:function:claude-customer-support-agent',
      
      verified: true,
      verified_by: 'platform-attestation',
      verification_method: 'aws-lambda-context',
      trust_level: 'high',
      attestation_data: {
        method: 'aws-lambda-context',
        function_arn: 'arn:aws:lambda:us-east-1:123456789012:function:claude-customer-support-agent',
        verified_at: Date.now()
      },
      
      labels: {
        'app': 'customer-support',
        'ai-provider': 'anthropic',
        'model': 'claude-3-sonnet',
        'team': 'customer-success'
      },
      
      owner: 'support-team@company.com',
      team: 'customer-success',
      cost_center: 'CS-001',
      security_score: 95,
      api_calls_30d: 125000
    },
    
    {
      name: 'gpt-code-review-bot',
      type: 'ecs-task',
      namespace: 'devtools',
      environment: 'production',
      category: 'ai-agent',
      subcategory: 'openai-gpt',
      is_ai_agent: true,
      
      arn: 'arn:aws:ecs:us-east-1:123456789012:task/devtools-cluster/abc123',
      
      verified: true,
      verification_method: 'aws-ecs-task-role',
      trust_level: 'high',
      
      labels: {
        'app': 'code-review',
        'ai-provider': 'openai',
        'model': 'gpt-4'
      },
      
      owner: 'engineering@company.com',
      security_score: 90,
      api_calls_30d: 8500
    },
    
    {
      name: 'gemini-data-analyst',
      type: 'ec2',
      namespace: 'analytics',
      environment: 'staging',
      category: 'ai-agent',
      subcategory: 'google-gemini',
      is_ai_agent: true,
      
      instance_id: 'i-gemini123abc',
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      labels: {
        'app': 'data-analysis',
        'ai-provider': 'google'
      },
      
      owner: 'data-team@company.com',
      security_score: 75,
      api_calls_30d: 1200
    },
    
    {
      name: 'llama-content-moderator',
      type: 'lambda',
      namespace: 'moderation',
      environment: 'production',
      category: 'ai-agent',
      subcategory: 'meta-llama',
      is_ai_agent: true,
      
      verified: false,
      trust_level: 'none',
      
      labels: {
        'app': 'content-moderation',
        'ai-provider': 'meta'
      },
      
      security_score: 60,
      api_calls_30d: 450
    },
    
    {
      name: 'mistral-translator',
      type: 'lambda',
      namespace: 'i18n',
      environment: 'production',
      category: 'ai-agent',
      subcategory: 'mistral-ai',
      is_ai_agent: true,
      
      verified: true,
      verification_method: 'manual-approval',
      trust_level: 'low',
      verified_by: 'admin@company.com',
      
      owner: 'i18n-team@company.com',
      security_score: 70,
      api_calls_30d: 3400
    },
    
    {
      name: 'unknown-ai-service',
      type: 'ec2',
      namespace: 'unknown',
      environment: 'unknown',
      category: 'ai-agent',
      is_ai_agent: true,
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 75,
      shadow_reasons: ['no_owner', 'unknown_environment', 'no_tags'],
      
      security_score: 40,
      api_calls_30d: 12
    }
  ],

  // =========================================================================
  // MCP SERVERS (6 workloads)
  // =========================================================================
  mcpServers: [
    {
      name: 'mcp-github-integration',
      type: 'ecs-task',
      namespace: 'integrations',
      environment: 'production',
      category: 'mcp-server',
      subcategory: 'github',
      is_mcp_server: true,
      
      spiffe_id: 'spiffe://company.com/aws/ecs/us-east-1/mcp-github-integration',
      arn: 'arn:aws:ecs:us-east-1:123456789012:task/integrations/mcp-github',
      
      verified: true,
      verification_method: 'aws-ecs-task-role',
      trust_level: 'high',
      
      labels: {
        'app': 'github-mcp',
        'mcp-type': 'github',
        'mcp-version': '1.0.0'
      },
      
      owner: 'platform-team@company.com',
      team: 'platform',
      security_score: 92,
      api_calls_30d: 45000
    },
    
    {
      name: 'mcp-filesystem-service',
      type: 'ec2',
      namespace: 'storage',
      environment: 'production',
      category: 'mcp-server',
      subcategory: 'filesystem',
      is_mcp_server: true,
      
      verified: true,
      verification_method: 'aws-imdsv2',
      trust_level: 'high',
      
      labels: {
        'app': 'filesystem-mcp',
        'mcp-type': 'filesystem'
      },
      
      owner: 'infra-team@company.com',
      security_score: 85,
      api_calls_30d: 12000
    },
    
    {
      name: 'mcp-postgres-connector',
      type: 'lambda',
      namespace: 'data',
      environment: 'production',
      category: 'mcp-server',
      subcategory: 'postgres',
      is_mcp_server: true,
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'high',
      
      owner: 'data-team@company.com',
      security_score: 90,
      api_calls_30d: 25000
    },
    
    {
      name: 'mcp-slack-bot',
      type: 'ecs-task',
      namespace: 'communications',
      environment: 'production',
      category: 'mcp-server',
      subcategory: 'slack',
      is_mcp_server: true,
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      owner: 'devops-team@company.com',
      security_score: 87,
      api_calls_30d: 8900
    },
    
    {
      name: 'mcp-puppeteer',
      type: 'lambda',
      namespace: 'automation',
      environment: 'staging',
      category: 'mcp-server',
      subcategory: 'browser',
      is_mcp_server: true,
      
      verified: false,
      trust_level: 'none',
      
      security_score: 65,
      api_calls_30d: 450
    },
    
    {
      name: 'legacy-mcp-server',
      type: 'ec2',
      namespace: 'legacy',
      environment: 'production',
      category: 'mcp-server',
      is_mcp_server: true,
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 85,
      dormancy_reasons: ['no_activity_60d', 'zero_api_calls'],
      
      security_score: 50,
      api_calls_30d: 0,
      unique_callers_30d: 0
    }
  ],

  // =========================================================================
  // MICROSERVICES (10 workloads)
  // =========================================================================
  microservices: [
    {
      name: 'payment-api',
      type: 'ecs-task',
      namespace: 'payments',
      environment: 'production',
      category: 'microservice',
      subcategory: 'api',
      
      spiffe_id: 'spiffe://company.com/aws/ecs/us-east-1/payment-api',
      arn: 'arn:aws:ecs:us-east-1:123456789012:task/prod/payment-api',
      
      verified: true,
      verification_method: 'aws-ecs-task-role',
      trust_level: 'very-high',
      
      labels: {
        'app': 'payment-processing',
        'tier': 'critical',
        'pci-compliant': 'true'
      },
      
      owner: 'payments-team@company.com',
      team: 'payments',
      cost_center: 'PAY-001',
      security_score: 98,
      api_calls_30d: 2500000
    },
    
    {
      name: 'user-service',
      type: 'ec2',
      namespace: 'identity',
      environment: 'production',
      category: 'microservice',
      subcategory: 'api',
      
      verified: true,
      verification_method: 'aws-imdsv2',
      trust_level: 'high',
      
      owner: 'identity-team@company.com',
      security_score: 93,
      api_calls_30d: 1800000
    },
    
    {
      name: 'notification-worker',
      type: 'lambda',
      namespace: 'notifications',
      environment: 'production',
      category: 'worker',
      subcategory: 'background-job',
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'medium',
      
      owner: 'comms-team@company.com',
      security_score: 80,
      api_calls_30d: 450000
    },
    
    {
      name: 'api-gateway',
      type: 'ec2',
      namespace: 'edge',
      environment: 'production',
      category: 'api-gateway',
      subcategory: 'proxy',
      
      verified: true,
      verification_method: 'aws-imdsv2',
      trust_level: 'high',
      
      owner: 'platform-team@company.com',
      security_score: 95,
      api_calls_30d: 5000000
    },
    
    {
      name: 'search-service',
      type: 'ecs-task',
      namespace: 'search',
      environment: 'production',
      category: 'microservice',
      subcategory: 'api',
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      owner: 'product-team@company.com',
      security_score: 82,
      api_calls_30d: 890000
    },
    
    {
      name: 'cache-service',
      type: 'ec2',
      namespace: 'cache',
      environment: 'production',
      category: 'microservice',
      subcategory: 'cache',
      
      verified: true,
      verification_method: 'manual-approval',
      trust_level: 'medium',
      
      owner: 'platform-team@company.com',
      security_score: 78,
      api_calls_30d: 3200000
    },
    
    {
      name: 'legacy-monolith',
      type: 'ec2',
      namespace: 'legacy',
      environment: 'production',
      category: 'microservice',
      subcategory: 'monolith',
      
      verified: false,
      trust_level: 'low',
      
      owner: 'legacy-team@company.com',
      security_score: 55,
      api_calls_30d: 25000
    },
    
    {
      name: 'test-service-123',
      type: 'lambda',
      namespace: 'testing',
      environment: 'development',
      category: 'microservice',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 70,
      shadow_reasons: ['test_naming', 'no_owner'],
      
      security_score: 45,
      api_calls_30d: 50
    },
    
    {
      name: 'app-1',
      type: 'ec2',
      namespace: 'unknown',
      environment: 'unknown',
      category: 'unknown',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 90,
      shadow_reasons: ['generic_naming', 'no_owner', 'no_tags'],
      
      security_score: 30,
      api_calls_30d: 0
    },
    
    {
      name: 'unknown-service',
      type: 'lambda',
      namespace: 'unknown',
      environment: 'unknown',
      category: 'unknown',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      is_dormant: true,
      shadow_score: 85,
      dormancy_score: 92,
      
      security_score: 25,
      api_calls_30d: 0,
      unique_callers_30d: 0
    }
  ],

  // =========================================================================
  // BOTS (5 workloads)
  // =========================================================================
  bots: [
    {
      name: 'deployment-bot',
      type: 'lambda',
      namespace: 'devops',
      environment: 'production',
      category: 'agent',
      subcategory: 'automation-bot',
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'high',
      
      labels: {
        'app': 'deployment-automation',
        'bot-type': 'cicd'
      },
      
      owner: 'devops-team@company.com',
      security_score: 85,
      api_calls_30d: 12000
    },
    
    {
      name: 'oncall-slack-bot',
      type: 'ecs-task',
      namespace: 'operations',
      environment: 'production',
      category: 'agent',
      subcategory: 'slack-bot',
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      owner: 'sre-team@company.com',
      security_score: 82,
      api_calls_30d: 8500
    },
    
    {
      name: 'security-scanner-bot',
      type: 'ec2',
      namespace: 'security',
      environment: 'production',
      category: 'agent',
      subcategory: 'security-bot',
      
      verified: true,
      verification_method: 'aws-imdsv2',
      trust_level: 'high',
      
      owner: 'security-team@company.com',
      security_score: 95,
      api_calls_30d: 25000
    },
    
    {
      name: 'github-pr-bot',
      type: 'lambda',
      namespace: 'devtools',
      environment: 'production',
      category: 'agent',
      subcategory: 'github-bot',
      
      verified: false,
      trust_level: 'low',
      
      security_score: 68,
      api_calls_30d: 3400
    },
    
    {
      name: 'test-automation-bot',
      type: 'lambda',
      namespace: 'testing',
      environment: 'staging',
      category: 'agent',
      
      verified: false,
      trust_level: 'none',
      
      security_score: 55,
      api_calls_30d: 890
    }
  ],

  // =========================================================================
  // INFRASTRUCTURE (8 workloads)
  // =========================================================================
  infrastructure: [
    {
      name: 'prometheus-scraper',
      type: 'ec2',
      namespace: 'monitoring',
      environment: 'production',
      category: 'monitoring',
      subcategory: 'metrics',
      
      verified: true,
      verification_method: 'aws-imdsv2',
      trust_level: 'high',
      
      owner: 'sre-team@company.com',
      security_score: 90,
      api_calls_30d: 0 // Doesn't make API calls, it scrapes
    },
    
    {
      name: 'log-aggregator',
      type: 'ecs-task',
      namespace: 'logging',
      environment: 'production',
      category: 'infrastructure',
      subcategory: 'logging',
      
      verified: true,
      verification_method: 'aws-ecs-task-role',
      trust_level: 'high',
      
      owner: 'platform-team@company.com',
      security_score: 88,
      api_calls_30d: 0
    },
    
    {
      name: 'backup-service',
      type: 'lambda',
      namespace: 'backup',
      environment: 'production',
      category: 'infrastructure',
      subcategory: 'backup',
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'high',
      
      owner: 'infra-team@company.com',
      security_score: 92,
      api_calls_30d: 720 // Runs daily
    },
    
    {
      name: 'grafana-dashboard',
      type: 'ec2',
      namespace: 'monitoring',
      environment: 'production',
      category: 'monitoring',
      subcategory: 'visualization',
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      owner: 'sre-team@company.com',
      security_score: 80,
      api_calls_30d: 0
    },
    
    {
      name: 'ci-runner-1',
      type: 'ec2',
      namespace: 'ci-cd',
      environment: 'production',
      category: 'infrastructure',
      subcategory: 'ci-cd',
      
      verified: true,
      verification_method: 'manual-approval',
      trust_level: 'medium',
      
      owner: 'devops-team@company.com',
      security_score: 75,
      api_calls_30d: 0
    },
    
    {
      name: 'metrics-collector',
      type: 'lambda',
      namespace: 'monitoring',
      environment: 'staging',
      category: 'monitoring',
      
      verified: false,
      trust_level: 'low',
      
      security_score: 65,
      api_calls_30d: 0
    },
    
    {
      name: 'legacy-monitoring',
      type: 'ec2',
      namespace: 'legacy',
      environment: 'production',
      category: 'infrastructure',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 78,
      dormancy_reasons: ['not_deployed_6months', 'minimal_usage'],
      
      security_score: 48,
      api_calls_30d: 0
    },
    
    {
      name: 'old-backup-server',
      type: 'ec2',
      namespace: 'backup',
      environment: 'unknown',
      category: 'infrastructure',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 95,
      dormancy_reasons: ['no_activity_90d', 'zero_usage'],
      
      security_score: 35,
      api_calls_30d: 0
    }
  ],

  // =========================================================================
  // INTEGRATIONS (6 workloads)
  // =========================================================================
  integrations: [
    {
      name: 'stripe-webhook-handler',
      type: 'lambda',
      namespace: 'integrations',
      environment: 'production',
      category: 'integration',
      subcategory: 'payment-provider',
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'high',
      
      labels: {
        'app': 'stripe-integration',
        'provider': 'stripe'
      },
      
      owner: 'payments-team@company.com',
      security_score: 90,
      api_calls_30d: 45000
    },
    
    {
      name: 'salesforce-sync',
      type: 'ecs-task',
      namespace: 'integrations',
      environment: 'production',
      category: 'integration',
      subcategory: 'crm',
      
      verified: true,
      verification_method: 'catalog-match',
      trust_level: 'medium',
      
      owner: 'sales-ops@company.com',
      security_score: 85,
      api_calls_30d: 12000
    },
    
    {
      name: 'datadog-forwarder',
      type: 'lambda',
      namespace: 'monitoring',
      environment: 'production',
      category: 'integration',
      subcategory: 'observability',
      
      verified: true,
      verification_method: 'aws-lambda-context',
      trust_level: 'medium',
      
      owner: 'sre-team@company.com',
      security_score: 87,
      api_calls_30d: 0
    },
    
    {
      name: 'twilio-sms-gateway',
      type: 'lambda',
      namespace: 'communications',
      environment: 'production',
      category: 'integration',
      subcategory: 'messaging',
      
      verified: true,
      verification_method: 'manual-approval',
      trust_level: 'medium',
      
      owner: 'comms-team@company.com',
      security_score: 82,
      api_calls_30d: 8900
    },
    
    {
      name: 'sendgrid-email',
      type: 'lambda',
      namespace: 'email',
      environment: 'production',
      category: 'integration',
      subcategory: 'email-provider',
      
      verified: false,
      trust_level: 'low',
      
      security_score: 72,
      api_calls_30d: 15000
    },
    
    {
      name: 'legacy-integration',
      type: 'ec2',
      namespace: 'legacy',
      environment: 'production',
      category: 'integration',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 82,
      
      security_score: 45,
      api_calls_30d: 0
    }
  ],

  // =========================================================================
  // SHADOW/DORMANT SERVICES (10 additional)
  // =========================================================================
  shadowDormant: [
    {
      name: 'test-john-experiment-2023',
      type: 'ec2',
      namespace: 'testing',
      environment: 'development',
      category: 'unknown',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 85,
      shadow_reasons: ['no_owner', 'test_naming', 'old_unowned'],
      
      created_by: 'john.doe@company.com',
      security_score: 35,
      api_calls_30d: 0
    },
    
    {
      name: 'tmp-migration-service',
      type: 'lambda',
      namespace: 'tmp',
      environment: 'production',
      category: 'worker',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 75,
      shadow_reasons: ['tmp_naming', 'no_owner'],
      
      security_score: 42,
      api_calls_30d: 5
    },
    
    {
      name: 'legacy-reporting-service',
      type: 'ec2',
      namespace: 'reporting',
      environment: 'production',
      category: 'worker',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 90,
      dormancy_reasons: ['no_activity_90d', 'zero_api_calls'],
      
      security_score: 48,
      api_calls_30d: 0,
      unique_callers_30d: 0
    },
    
    {
      name: 'old-analytics-worker',
      type: 'lambda',
      namespace: 'analytics',
      environment: 'production',
      category: 'worker',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 85,
      dormancy_reasons: ['no_activity_60d', 'minimal_usage'],
      
      security_score: 52,
      api_calls_30d: 0
    },
    
    {
      name: 'dev-sandbox-1',
      type: 'ec2',
      namespace: 'sandbox',
      environment: 'development',
      category: 'unknown',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 70,
      shadow_reasons: ['dev_naming', 'no_cost_center'],
      
      security_score: 40,
      api_calls_30d: 15
    },
    
    {
      name: 'experiment-ml-model',
      type: 'ec2',
      namespace: 'experiments',
      environment: 'unknown',
      category: 'ai-agent',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 80,
      shadow_reasons: ['experiment_naming', 'no_owner', 'not_in_catalog'],
      
      security_score: 38,
      api_calls_30d: 8
    },
    
    {
      name: 'unused-cache-service',
      type: 'ec2',
      namespace: 'cache',
      environment: 'production',
      category: 'microservice',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 75,
      dormancy_reasons: ['no_activity_30d', 'low_usage'],
      
      security_score: 55,
      api_calls_30d: 0
    },
    
    {
      name: 'deprecated-api-v1',
      type: 'ecs-task',
      namespace: 'api',
      environment: 'production',
      category: 'microservice',
      
      verified: false,
      trust_level: 'none',
      
      is_dormant: true,
      dormancy_score: 95,
      dormancy_reasons: ['no_activity_90d', 'deprecated'],
      
      security_score: 45,
      api_calls_30d: 0
    },
    
    {
      name: 'zombie-worker',
      type: 'lambda',
      namespace: 'workers',
      environment: 'production',
      category: 'worker',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      is_dormant: true,
      shadow_score: 65,
      dormancy_score: 88,
      
      security_score: 32,
      api_calls_30d: 0
    },
    
    {
      name: 'forgotten-service',
      type: 'ec2',
      namespace: 'unknown',
      environment: 'unknown',
      category: 'unknown',
      
      verified: false,
      trust_level: 'none',
      
      is_shadow: true,
      shadow_score: 92,
      shadow_reasons: ['no_owner', 'unknown_environment', 'no_tags', 'generic_naming'],
      
      security_score: 28,
      api_calls_30d: 0
    }
  ]
};

// =============================================================================
// Database Functions
// =============================================================================

async function insertWorkload(client, workload, trustDomain = 'company.com', cloudProvider = 'aws', region = 'us-east-1') {
  // Generate SPIFFE ID if not provided
  let spiffeId = workload.spiffe_id;
  if (!spiffeId && workload.arn) {
    // Derive from ARN
    spiffeId = `spiffe://${trustDomain}/aws/${workload.type}/${workload.name}`;
  } else if (!spiffeId && workload.instance_id) {
    // Use instance ID
    spiffeId = `spiffe://${trustDomain}/aws/instance/${workload.instance_id}`;
  } else if (!spiffeId) {
    // Fallback - use name
    spiffeId = `spiffe://${trustDomain}/aws/${workload.type}/${workload.name}`;
  }

  const issuer = `${cloudProvider}://${region}`;
  const clusterId = region;

  // Set defaults
  const verifiedAt = workload.verified ? (workload.verified_at || new Date()) : null;
  const lastAttestation = workload.last_attestation || (workload.verified ? new Date() : null);
  const attestationExpires = workload.attestation_expires || (workload.verified ? new Date(Date.now() + 24 * 60 * 60 * 1000) : null);
  const lastApiCall = workload.last_api_call || (workload.api_calls_30d > 0 ? new Date() : null);
  const lastDeployed = workload.last_deployed || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago

  await client.query(`
    INSERT INTO workloads (
      spiffe_id, name, type, namespace, environment,
      trust_domain, issuer, cluster_id,
      cloud_provider, region, account_id,
      category, subcategory, is_ai_agent, is_mcp_server,
      discovered_by, labels, selectors, metadata,
      security_score, status, verified,
      verified_at, verified_by, verification_method, trust_level,
      attestation_data, last_attestation, attestation_expires,
      owner, team, cost_center, created_by,
      is_shadow, is_dormant, shadow_score, dormancy_score,
      shadow_reasons, dormancy_reasons,
      api_calls_30d, unique_callers_30d, last_api_call, last_deployed
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
      $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29,
      $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43
    )
    ON CONFLICT (spiffe_id) DO UPDATE SET
      name = EXCLUDED.name,
      category = EXCLUDED.category,
      verified = EXCLUDED.verified,
      trust_level = EXCLUDED.trust_level,
      security_score = EXCLUDED.security_score,
      updated_at = NOW()
  `, [
    spiffeId,
    workload.name,
    workload.type,
    workload.namespace,
    workload.environment,
    trustDomain,
    issuer,
    clusterId,
    cloudProvider,
    region,
    '123456789012', // account_id
    workload.category,
    workload.subcategory || null,
    workload.is_ai_agent || false,
    workload.is_mcp_server || false,
    'test-generator',
    JSON.stringify(workload.labels || {}),
    JSON.stringify(workload.selectors || {}),
    JSON.stringify(workload.metadata || {}),
    workload.security_score || 70,
    'pending',
    workload.verified || false,
    verifiedAt,
    workload.verified_by || null,
    workload.verification_method || null,
    workload.trust_level || 'none',
    JSON.stringify(workload.attestation_data || {}),
    lastAttestation,
    attestationExpires,
    workload.owner || null,
    workload.team || null,
    workload.cost_center || null,
    workload.created_by || null,
    workload.is_shadow || false,
    workload.is_dormant || false,
    workload.shadow_score || 0,
    workload.dormancy_score || 0,
    JSON.stringify(workload.shadow_reasons || []),
    JSON.stringify(workload.dormancy_reasons || []),
    workload.api_calls_30d || 0,
    workload.unique_callers_30d || 0,
    lastApiCall,
    lastDeployed
  ]);

  return spiffeId;
}

// =============================================================================
// Main Generator Function
// =============================================================================

async function generateTestNHIs() {
  const client = new Client({ connectionString: DATABASE_URL });
  
  try {
    await client.connect();
    console.log('✅ Connected to database\n');

    let totalCreated = 0;
    const categories = {
      'AI Agents': 0,
      'MCP Servers': 0,
      'Microservices': 0,
      'Bots': 0,
      'Infrastructure': 0,
      'Integrations': 0,
      'Shadow/Dormant': 0
    };

    // Generate AI Agents
    console.log('🤖 Creating AI Agents...');
    for (const agent of TEST_NHIS.aiAgents) {
      const spiffeId = await insertWorkload(client, agent);
      console.log(`  ✓ ${agent.name} (${agent.subcategory})`);
      console.log(`    → ${spiffeId}`);
      console.log(`    Trust: ${agent.trust_level || 'none'} | Score: ${agent.security_score}`);
      totalCreated++;
      categories['AI Agents']++;
    }

    // Generate MCP Servers
    console.log('\n🔌 Creating MCP Servers...');
    for (const mcp of TEST_NHIS.mcpServers) {
      const spiffeId = await insertWorkload(client, mcp);
      console.log(`  ✓ ${mcp.name} (${mcp.subcategory})`);
      console.log(`    → ${spiffeId}`);
      console.log(`    Trust: ${mcp.trust_level || 'none'} | Score: ${mcp.security_score}`);
      totalCreated++;
      categories['MCP Servers']++;
    }

    // Generate Microservices
    console.log('\n⚙️  Creating Microservices...');
    for (const service of TEST_NHIS.microservices) {
      const spiffeId = await insertWorkload(client, service);
      console.log(`  ✓ ${service.name}`);
      console.log(`    → ${spiffeId}`);
      console.log(`    Trust: ${service.trust_level || 'none'} | Score: ${service.security_score}`);
      totalCreated++;
      categories['Microservices']++;
    }

    // Generate Bots
    console.log('\n🤖 Creating Bots...');
    for (const bot of TEST_NHIS.bots) {
      const spiffeId = await insertWorkload(client, bot);
      console.log(`  ✓ ${bot.name}`);
      console.log(`    Trust: ${bot.trust_level || 'none'} | Score: ${bot.security_score}`);
      totalCreated++;
      categories['Bots']++;
    }

    // Generate Infrastructure
    console.log('\n🏗️  Creating Infrastructure...');
    for (const infra of TEST_NHIS.infrastructure) {
      const spiffeId = await insertWorkload(client, infra);
      console.log(`  ✓ ${infra.name}`);
      console.log(`    Trust: ${infra.trust_level || 'none'} | Score: ${infra.security_score}`);
      totalCreated++;
      categories['Infrastructure']++;
    }

    // Generate Integrations
    console.log('\n🔗 Creating Integrations...');
    for (const integration of TEST_NHIS.integrations) {
      const spiffeId = await insertWorkload(client, integration);
      console.log(`  ✓ ${integration.name}`);
      console.log(`    Trust: ${integration.trust_level || 'none'} | Score: ${integration.security_score}`);
      totalCreated++;
      categories['Integrations']++;
    }

    // Generate Shadow/Dormant
    console.log('\n👻 Creating Shadow/Dormant Services...');
    for (const shadow of TEST_NHIS.shadowDormant) {
      const spiffeId = await insertWorkload(client, shadow);
      const flags = [];
      if (shadow.is_shadow) flags.push(`Shadow:${shadow.shadow_score}`);
      if (shadow.is_dormant) flags.push(`Dormant:${shadow.dormancy_score}`);
      console.log(`  ✓ ${shadow.name} [${flags.join(', ')}]`);
      console.log(`    Score: ${shadow.security_score}`);
      totalCreated++;
      categories['Shadow/Dormant']++;
    }

    console.log(`\n${'='.repeat(60)}`);
    console.log(`✅ Test NHI generation complete!`);
    console.log(`📊 Created ${totalCreated} workload identities`);
    console.log(`${'='.repeat(60)}\n`);

    // Print detailed summary
    console.log('📋 Breakdown by Category:');
    for (const [category, count] of Object.entries(categories)) {
      console.log(`  ${category.padEnd(20)} : ${count.toString().padStart(3)}`);
    }

    console.log('\n📊 Breakdown by Trust Level:');
    const trustLevels = await client.query(`
      SELECT trust_level, COUNT(*) as count
      FROM workloads
      WHERE discovered_by = 'test-generator'
      GROUP BY trust_level
      ORDER BY 
        CASE trust_level
          WHEN 'very-high' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          WHEN 'none' THEN 5
        END
    `);

    for (const row of trustLevels.rows) {
      console.log(`  ${(row.trust_level || 'none').padEnd(20)} : ${row.count.toString().padStart(3)}`);
    }

    console.log('\n🚨 Shadow/Dormant Summary:');
    const shadowDormant = await client.query(`
      SELECT 
        SUM(CASE WHEN is_shadow = true THEN 1 ELSE 0 END) as shadow_count,
        SUM(CASE WHEN is_dormant = true THEN 1 ELSE 0 END) as dormant_count,
        SUM(CASE WHEN is_shadow = true AND is_dormant = true THEN 1 ELSE 0 END) as both_count
      FROM workloads
      WHERE discovered_by = 'test-generator'
    `);

    const sd = shadowDormant.rows[0];
    console.log(`  Shadow Services      : ${sd.shadow_count}`);
    console.log(`  Dormant Services     : ${sd.dormant_count}`);
    console.log(`  Both Shadow+Dormant  : ${sd.both_count}`);

    console.log('\n✅ Done! Test data ready for discovery and policy testing.\n');

  } catch (error) {
    console.error('❌ Error generating test NHIs:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

// =============================================================================
// Run Generator
// =============================================================================

generateTestNHIs();
