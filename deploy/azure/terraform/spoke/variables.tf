# =============================================================================
# Variables — Azure Container Apps Spoke
# =============================================================================

variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "wid"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "dev"
}

variable "azure_region" {
  description = "Azure region to deploy into"
  type        = string
  default     = "eastus"
}

variable "central_url" {
  description = "URL of the central control plane (GCP hub relay)"
  type        = string
  default     = "http://34.120.74.81"
}

variable "central_api_key" {
  description = "API key for authenticating with the central control plane"
  type        = string
  default     = ""
  sensitive   = true
}

variable "environment_name" {
  description = "Name for this spoke environment (shown in hub dashboard)"
  type        = string
  default     = "azure-spoke"
}

variable "acr_name" {
  description = "Azure Container Registry name (must be globally unique)"
  type        = string
  default     = "widspoke"
}

variable "gateway_configs" {
  description = "Map of edge gateway configurations. Key = gateway name, value = config object."
  type = map(object({
    app_host      = string
    app_port      = number
    workload_name = string
    external_port = number
  }))
  default = {
    "servicenow" = {
      app_host      = "servicenow-it-agent"
      app_port      = 6001
      workload_name = "servicenow-it-agent"
      external_port = 8001
    }
    "github-actions" = {
      app_host      = "github-actions-agent"
      app_port      = 6010
      workload_name = "github-actions-agent"
      external_port = 8010
    }
    "code-review" = {
      app_host      = "code-review-agent"
      app_port      = 6011
      workload_name = "code-review-agent"
      external_port = 8011
    }
    "security-scanner" = {
      app_host      = "security-scanner-agent"
      app_port      = 6012
      workload_name = "security-scanner-agent"
      external_port = 8012
    }
    "billing" = {
      app_host      = "billing-agent"
      app_port      = 6021
      workload_name = "billing-agent"
      external_port = 8021
    }
    "crm" = {
      app_host      = "crm-agent"
      app_port      = 6022
      workload_name = "crm-agent"
      external_port = 8022
    }
  }
}

variable "relay_cpu" {
  description = "CPU cores for relay container (0.25, 0.5, 1.0, 2.0)"
  type        = number
  default     = 0.25
}

variable "relay_memory" {
  description = "Memory in Gi for relay container (0.5, 1.0, 2.0, 4.0)"
  type        = string
  default     = "0.5Gi"
}

variable "gateway_cpu" {
  description = "CPU cores for each gateway container"
  type        = number
  default     = 0.25
}

variable "gateway_memory" {
  description = "Memory in Gi for each gateway container"
  type        = string
  default     = "0.5Gi"
}

# ─── VNET ──────────────────────────────────────────────────────────────────────

variable "enable_vnet" {
  description = "Enable VNET integration for Container Apps Environment"
  type        = bool
  default     = true
}

variable "vnet_cidr" {
  description = "CIDR block for the spoke VNET"
  type        = string
  default     = "10.2.0.0/16"
}

# ─── Key Vault ─────────────────────────────────────────────────────────────────

variable "enable_keyvault" {
  description = "Enable Azure Key Vault for secret management"
  type        = bool
  default     = true
}

variable "federation_push_secret" {
  description = "Federation push secret stored in Key Vault"
  type        = string
  default     = ""
  sensitive   = true
}

# ─── Multi-tenancy ─────────────────────────────────────────────────────────────

variable "tenant_id" {
  description = "WID tenant ID for multi-tenancy isolation"
  type        = string
  default     = ""
}

variable "data_region" {
  description = "Data sovereignty region tag for this spoke"
  type        = string
  default     = ""
}

# ─── mTLS ──────────────────────────────────────────────────────────────────────

variable "enable_mtls" {
  description = "Enable mTLS configuration for relay-to-hub communication"
  type        = bool
  default     = false
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Role        = "spoke"
  }
  name_prefix = "${var.project_name}-${var.environment}-spoke"
}
