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

# ─── Container Registry ─────────────────────────────────────────────────────

resource "azurerm_container_registry" "spoke" {
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.spoke.name
  location            = azurerm_resource_group.spoke.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = local.common_tags
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

  tags = local.common_tags
}

# ─── Container App: Relay (spoke mode) ───────────────────────────────────────

resource "azurerm_container_app" "relay" {
  name                         = "${local.name_prefix}-relay"
  resource_group_name          = azurerm_resource_group.spoke.name
  container_app_environment_id = azurerm_container_app_environment.spoke.id
  revision_mode                = "Single"

  tags = local.common_tags

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
    server               = azurerm_container_registry.spoke.login_server
    username             = azurerm_container_registry.spoke.admin_username
    password_secret_name = "acr-password"
  }

  dynamic "secret" {
    for_each = var.central_api_key != "" ? [1] : []
    content {
      name  = "central-api-key"
      value = var.central_api_key
    }
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.spoke.admin_password
  }
}

# ─── Container Apps: Edge Gateways (one per workload) ────────────────────────

resource "azurerm_container_app" "gateway" {
  for_each = var.gateway_configs

  name                         = "${local.name_prefix}-gw-${each.key}"
  resource_group_name          = azurerm_resource_group.spoke.name
  container_app_environment_id = azurerm_container_app_environment.spoke.id
  revision_mode                = "Single"

  tags = local.common_tags

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
    server               = azurerm_container_registry.spoke.login_server
    username             = azurerm_container_registry.spoke.admin_username
    password_secret_name = "acr-password"
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.spoke.admin_password
  }

  depends_on = [azurerm_container_app.relay]
}
