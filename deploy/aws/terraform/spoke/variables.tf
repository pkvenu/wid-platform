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

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
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
  default     = "aws-spoke"
}

variable "vpc_cidr" {
  description = "CIDR block for the spoke VPC"
  type        = string
  default     = "10.1.0.0/16"
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
  description = "CPU units for relay task (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "relay_memory" {
  description = "Memory in MiB for relay task"
  type        = number
  default     = 512
}

variable "gateway_cpu" {
  description = "CPU units for each gateway task"
  type        = number
  default     = 256
}

variable "gateway_memory" {
  description = "Memory in MiB for each gateway task"
  type        = number
  default     = 256
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
