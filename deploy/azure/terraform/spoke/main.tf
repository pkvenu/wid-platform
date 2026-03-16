# =============================================================================
# WID Spoke — Azure Container Apps
# =============================================================================
# Deploys: 1 relay (spoke mode) + N edge-gateways (one per workload)
# No database — all state flows through relay to GCP central control plane.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

provider "azurerm" {
  features {}
}

# ─── Resource Group ──────────────────────────────────────────────────────────

resource "azurerm_resource_group" "spoke" {
  name     = "${local.name_prefix}-rg"
  location = var.azure_region
  tags     = local.common_tags
}

# ─── User-Assigned Managed Identity ────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "spoke" {
  name                = "${local.name_prefix}-identity"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location

  tags = local.common_tags
}

# ─── Container Registry ─────────────────────────────────────────────────────

resource "azurerm_container_registry" "spoke" {
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  sku                 = "Basic"
  admin_enabled       = false

  tags = local.common_tags
}

# Grant AcrPull to the Managed Identity
resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.spoke.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.spoke.principal_id
}

# ─── VNET + Subnet (optional) ─────────────────────────────────────────────────

resource "azurerm_virtual_network" "spoke" {
  count               = var.enable_vnet ? 1 : 0
  name                = "${local.name_prefix}-vnet"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  address_space       = [var.vnet_cidr]

  tags = local.common_tags
}

resource "azurerm_subnet" "container_apps" {
  count                = var.enable_vnet ? 1 : 0
  name                 = "${local.name_prefix}-cae-subnet"
  resource_group_name  = azurerm_resource_group.spoke.name
  virtual_network_name = azurerm_virtual_network.spoke[0].name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 5, 0)]

  delegation {
    name = "container-apps-delegation"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ─── Azure Key Vault (optional) ───────────────────────────────────────────────

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "spoke" {
  count                      = var.enable_keyvault ? 1 : 0
  name                       = "${var.project_name}-${var.environment}-spk-kv"
  resource_group_name        = azurerm_resource_group.spoke.name
  location                   = azurerm_resource_group.spoke.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  enable_rbac_authorization = true

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  tags = local.common_tags
}

# Grant deployer (current principal) Key Vault Administrator
resource "azurerm_role_assignment" "kv_admin" {
  count                = var.enable_keyvault ? 1 : 0
  scope                = azurerm_key_vault.spoke[0].id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Grant Managed Identity "Key Vault Secrets User"
resource "azurerm_role_assignment" "kv_secrets_user" {
  count                = var.enable_keyvault ? 1 : 0
  scope                = azurerm_key_vault.spoke[0].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.spoke.principal_id
}

# Store central API key in Key Vault
resource "azurerm_key_vault_secret" "central_api_key" {
  count        = var.enable_keyvault && var.central_api_key != "" ? 1 : 0
  name         = "central-api-key"
  value        = var.central_api_key
  key_vault_id = azurerm_key_vault.spoke[0].id

  depends_on = [azurerm_role_assignment.kv_admin]
}

# Store federation push secret in Key Vault
resource "azurerm_key_vault_secret" "federation_push" {
  count        = var.enable_keyvault && var.federation_push_secret != "" ? 1 : 0
  name         = "federation-push-secret"
  value        = var.federation_push_secret
  key_vault_id = azurerm_key_vault.spoke[0].id

  depends_on = [azurerm_role_assignment.kv_admin]
}

# ─── Log Analytics Workspace ────────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "spoke" {
  name                = "${local.name_prefix}-logs"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = local.common_tags
}

# ─── Container Apps Environment ──────────────────────────────────────────────

resource "azurerm_container_app_environment" "spoke" {
  name                       = "${local.name_prefix}-env"
  resource_group_name        = azurerm_resource_group.spoke.name
  location                   = azurerm_resource_group.spoke.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.spoke.id
  infrastructure_subnet_id   = var.enable_vnet ? azurerm_subnet.container_apps[0].id : null

  tags = local.common_tags
}

# ─── Container App: Relay (spoke mode) ───────────────────────────────────────

resource "azurerm_container_app" "relay" {
  name                         = "${local.name_prefix}-relay"
  resource_group_name          = azurerm_resource_group.spoke.name
  container_app_environment_id = azurerm_container_app_environment.spoke.id
  revision_mode                = "Single"

  tags = local.common_tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.spoke.id]
  }

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "relay"
      image  = "${azurerm_container_registry.spoke.login_server}/relay-service:latest"
      cpu    = var.relay_cpu
      memory = var.relay_memory

      env {
        name  = "PORT"
        value = "3005"
      }
      env {
        name  = "CENTRAL_CONTROL_PLANE_URL"
        value = var.central_url
      }
      env {
        name  = "ENVIRONMENT_NAME"
        value = var.environment_name
      }
      env {
        name  = "ENVIRONMENT_TYPE"
        value = "container-apps"
      }
      env {
        name  = "REGION"
        value = var.azure_region
      }
      env {
        name  = "CLUSTER_ID"
        value = "${local.name_prefix}-env"
      }
      env {
        name  = "POLICY_SYNC_INTERVAL_MS"
        value = "15000"
      }
      env {
        name  = "AUDIT_FLUSH_INTERVAL_MS"
        value = "5000"
      }
      env {
        name  = "HEALTH_REPORT_INTERVAL_MS"
        value = "60000"
      }

      # ── mTLS + webhook env vars ──────────────────────────────────────
      dynamic "env" {
        for_each = var.enable_mtls ? [1] : []
        content {
          name  = "RELAY_CERT_PATH"
          value = "/certs/relay.crt"
        }
      }
      dynamic "env" {
        for_each = var.enable_mtls ? [1] : []
        content {
          name  = "RELAY_KEY_PATH"
          value = "/certs/relay.key"
        }
      }
      dynamic "env" {
        for_each = var.enable_mtls ? [1] : []
        content {
          name  = "RELAY_CA_BUNDLE_PATH"
          value = "/certs/ca-bundle.crt"
        }
      }
      env {
        name  = "WEBHOOK_ENABLED"
        value = "true"
      }
      env {
        name  = "WEBHOOK_PORT"
        value = "3006"
      }

      # ── Multi-tenancy ────────────────────────────────────────────────
      dynamic "env" {
        for_each = var.tenant_id != "" ? [1] : []
        content {
          name  = "TENANT_ID"
          value = var.tenant_id
        }
      }
      dynamic "env" {
        for_each = var.data_region != "" ? [1] : []
        content {
          name  = "DATA_REGION"
          value = var.data_region
        }
      }

      # ── Secrets (Key Vault references when enabled) ──────────────────
      dynamic "env" {
        for_each = var.central_api_key != "" ? [1] : []
        content {
          name        = "CENTRAL_API_KEY"
          secret_name = "central-api-key"
        }
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 3005
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 3005
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 3005
    transport        = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  registry {
    server   = azurerm_container_registry.spoke.login_server
    identity = azurerm_user_assigned_identity.spoke.id
  }

  dynamic "secret" {
    for_each = var.central_api_key != "" ? [1] : []
    content {
      name  = "central-api-key"
      value = var.central_api_key
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# ─── Container Apps: Edge Gateways (one per workload) ────────────────────────

resource "azurerm_container_app" "gateway" {
  for_each = var.gateway_configs

  name                         = "${local.name_prefix}-gw-${each.key}"
  resource_group_name          = azurerm_resource_group.spoke.name
  container_app_environment_id = azurerm_container_app_environment.spoke.id
  revision_mode                = "Single"

  tags = local.common_tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.spoke.id]
  }

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "gateway"
      image  = "${azurerm_container_registry.spoke.login_server}/edge-gateway:latest"
      cpu    = var.gateway_cpu
      memory = var.gateway_memory

      # Port config
      env {
        name  = "OUTBOUND_PORT"
        value = "15001"
      }
      env {
        name  = "INBOUND_PORT"
        value = "15006"
      }
      env {
        name  = "ADMIN_PORT"
        value = "15000"
      }

      # Target workload
      env {
        name  = "APP_HOST"
        value = each.value.app_host
      }
      env {
        name  = "APP_PORT"
        value = tostring(each.value.app_port)
      }
      env {
        name  = "WORKLOAD_NAME"
        value = each.value.workload_name
      }
      env {
        name  = "WORKLOAD_NS"
        value = "demo-blended"
      }
      env {
        name  = "TRUST_DOMAIN"
        value = "company.com"
      }

      # Point to local spoke relay (internal FQDN in Container Apps env)
      env {
        name  = "POLICY_SERVICE_URL"
        value = "http://${local.name_prefix}-relay.internal.${var.azure_region}.azurecontainerapps.io:3005"
      }
      env {
        name  = "TOKEN_SERVICE_URL"
        value = "http://${local.name_prefix}-relay.internal.${var.azure_region}.azurecontainerapps.io:3005"
      }
      env {
        name  = "BROKER_URL"
        value = "http://${local.name_prefix}-relay.internal.${var.azure_region}.azurecontainerapps.io:3005"
      }

      # Behavioral defaults
      env {
        name  = "DEFAULT_MODE"
        value = "audit"
      }
      env {
        name  = "FAIL_BEHAVIOR"
        value = "open"
      }
      env {
        name  = "LOG_LEVEL"
        value = "info"
      }
      env {
        name  = "STRUCTURED_LOGS"
        value = "true"
      }

      # ── Multi-tenancy ────────────────────────────────────────────────
      dynamic "env" {
        for_each = var.tenant_id != "" ? [1] : []
        content {
          name  = "TENANT_ID"
          value = var.tenant_id
        }
      }
      dynamic "env" {
        for_each = var.data_region != "" ? [1] : []
        content {
          name  = "DATA_REGION"
          value = var.data_region
        }
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 15000
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 15000
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 15001
    transport        = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  registry {
    server   = azurerm_container_registry.spoke.login_server
    identity = azurerm_user_assigned_identity.spoke.id
  }

  depends_on = [azurerm_container_app.relay, azurerm_role_assignment.acr_pull]
}

# =============================================================================
# Azure Monitor — Alert Rules
# =============================================================================

# ─── Action Group for alerts ──────────────────────────────────────────────────

resource "azurerm_monitor_action_group" "spoke" {
  name                = "${local.name_prefix}-alerts-ag"
  resource_group_name = azurerm_resource_group.spoke.name
  short_name          = "widspoke"

  tags = local.common_tags
}

# ─── Alert: Relay unhealthy for >5 minutes ────────────────────────────────────

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "relay_unhealthy" {
  name                = "${local.name_prefix}-relay-unhealthy"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  description         = "Relay container app has been unhealthy for more than 5 minutes"
  severity            = 1
  enabled             = true

  scopes                = [azurerm_log_analytics_workspace.spoke.id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"

  criteria {
    query = <<-KQL
      ContainerAppSystemLogs_CL
      | where ContainerAppName_s == "${local.name_prefix}-relay"
      | where Log_s contains "Unhealthy" or Log_s contains "unhealthy"
      | summarize UnhealthyCount = count() by bin(TimeGenerated, 5m)
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.spoke.id]
  }

  tags = local.common_tags
}

# ─── Alert: Container restarts > 3 ────────────────────────────────────────────

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "container_restarts" {
  name                = "${local.name_prefix}-container-restarts"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  description         = "Container restart count exceeded threshold (>3 in 15 minutes)"
  severity            = 2
  enabled             = true

  scopes                = [azurerm_log_analytics_workspace.spoke.id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT15M"

  criteria {
    query = <<-KQL
      ContainerAppSystemLogs_CL
      | where Log_s contains "Started" or Log_s contains "Restarting"
      | summarize RestartCount = count() by ContainerAppName_s, bin(TimeGenerated, 15m)
      | where RestartCount > 3
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.spoke.id]
  }

  tags = local.common_tags
}

# ─── Alert: Memory usage > 80% ────────────────────────────────────────────────

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "memory_high" {
  name                = "${local.name_prefix}-memory-high"
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  description         = "Container memory usage exceeds 80%"
  severity            = 2
  enabled             = true

  scopes                = [azurerm_log_analytics_workspace.spoke.id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"

  criteria {
    query = <<-KQL
      ContainerAppConsoleLogs_CL
      | where Log_s contains "memory"
      | union (
        Perf
        | where ObjectName == "Container" and CounterName == "memoryWorkingSetBytes"
        | extend MemoryMB = CounterValue / 1048576
        | where MemoryMB > 400
      )
      | summarize HighMemCount = count() by bin(TimeGenerated, 5m)
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.spoke.id]
  }

  tags = local.common_tags
}
