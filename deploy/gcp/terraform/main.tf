# =============================================================================
# WID Platform — GCP Infrastructure (Cloud Run + Cloud SQL)
# =============================================================================
#
# Creates:
#   - VPC with private services access (for Cloud SQL)
#   - Cloud SQL PostgreSQL 16
#   - Artifact Registry for container images
#   - Secret Manager for DB credentials & JWT key
#   - Cloud Run services for all WID components
#   - Global HTTP(S) Load Balancer with URL map routing
#   - Cloud DNS (optional, for custom domain)
#
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  services = {
    "policy-engine" = {
      port   = 3001
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 5
      env = [
        { name = "OPA_COMPILER", value = "node" },
      ]
      public = true  # exposed via LB
    }
    "token-service" = {
      port   = 3000
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 3
      env    = []
      public = false  # internal only
    }
    "credential-broker" = {
      port   = 3002
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 3
      env    = []
      public = false
    }
    "discovery-service" = {
      port   = 3003
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 3
      env = [
        { name = "SPIRE_TRUST_DOMAIN", value = "company.com" },
        { name = "GCP_PROJECT_ID", value = var.project_id },
        { name = "TOKEN_SERVICE_URL", value = "https://wid-dev-token-service" },
      ]
      public = true
    }
    "relay-service" = {
      port   = 3005
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 5
      env = [
        { name = "ENVIRONMENT_NAME", value = "gcp-production" },
        { name = "ENVIRONMENT_TYPE", value = "cloudrun" },
        { name = "REGION", value = var.region },
        { name = "CLUSTER_ID", value = "wid-gcp-cloudrun" },
        { name = "CENTRAL_CONTROL_PLANE_URL", value = "" },
        { name = "LOCAL_POLICY_ENGINE_URL", value = "https://wid-dev-policy-engine" },
      ]
      public = true  # exposed via LB
    }
    "web-ui" = {
      port   = 3100
      cpu    = "1"
      memory = "512Mi"
      min    = 1
      max    = 3
      env    = []
      public = true  # exposed via LB (default route)
    }
  }

  # Services that get exposed via the load balancer
  public_services  = { for k, v in local.services : k => v if v.public }
  private_services = { for k, v in local.services : k => v if !v.public }
}


# ═══════════════════════════════════════════════════════════════
# 1. VPC & NETWORKING
# ═══════════════════════════════════════════════════════════════

resource "google_compute_network" "main" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "${local.name_prefix}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id

  private_ip_google_access = true
}

# Private services access for Cloud SQL
resource "google_compute_global_address" "private_ip" {
  name          = "${local.name_prefix}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip.name]
}

# VPC connector for Cloud Run → Cloud SQL private access
resource "google_vpc_access_connector" "main" {
  name          = "${local.name_prefix}-vpc-cx"
  region        = var.region
  network       = google_compute_network.main.name
  ip_cidr_range = "10.8.0.0/28"

  min_instances = 2
  max_instances = 3
}


# ═══════════════════════════════════════════════════════════════
# 2. CLOUD SQL (PostgreSQL 16)
# ═══════════════════════════════════════════════════════════════

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "main" {
  name             = "${local.name_prefix}-postgres"
  database_version = "POSTGRES_16"
  region           = var.region

  depends_on = [google_service_networking_connection.private_vpc]

  settings {
    tier              = var.db_tier
    availability_type = var.environment == "dev" ? "ZONAL" : "REGIONAL"
    disk_size         = 20
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.main.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = var.environment != "dev"
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }
  }

  deletion_protection = var.environment != "dev"
}

resource "google_sql_database" "main" {
  name     = var.db_name
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "main" {
  name     = "wid_admin"
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
}


# ═══════════════════════════════════════════════════════════════
# 3. ARTIFACT REGISTRY
# ═══════════════════════════════════════════════════════════════

resource "google_artifact_registry_repository" "main" {
  location      = var.region
  repository_id = "${var.project_name}-services"
  format        = "DOCKER"
  description   = "WID platform container images"
}


# ═══════════════════════════════════════════════════════════════
# 4. SECRET MANAGER
# ═══════════════════════════════════════════════════════════════

resource "google_secret_manager_secret" "db_url" {
  secret_id = "${local.name_prefix}-database-url"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_url" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = "postgresql://wid_admin:${random_password.db_password.result}@${google_sql_database_instance.main.private_ip_address}:5432/${var.db_name}"
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "jwt_key" {
  secret_id = "${local.name_prefix}-jwt-signing-key"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "jwt_key" {
  secret      = google_secret_manager_secret.jwt_key.id
  secret_data = random_password.jwt_secret.result
}


# ═══════════════════════════════════════════════════════════════
# 5. IAM — Cloud Run service account
# ═══════════════════════════════════════════════════════════════

resource "google_service_account" "cloudrun" {
  account_id   = "${local.name_prefix}-run"
  display_name = "WID Cloud Run Service Account"
}

# Access secrets
resource "google_secret_manager_secret_iam_member" "db_url_access" {
  secret_id = google_secret_manager_secret.db_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloudrun.email}"
}

resource "google_secret_manager_secret_iam_member" "jwt_key_access" {
  secret_id = google_secret_manager_secret.jwt_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloudrun.email}"
}

# Access Cloud SQL
resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloudrun.email}"
}


# ═══════════════════════════════════════════════════════════════
# 6. CLOUD RUN SERVICES
# ═══════════════════════════════════════════════════════════════

resource "google_cloud_run_v2_service" "services" {
  for_each = local.services

  name     = "${local.name_prefix}-${each.key}"
  location = var.region

  template {
    service_account = google_service_account.cloudrun.email

    scaling {
      min_instance_count = each.value.min
      max_instance_count = each.value.max
    }

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/${each.key}:latest"

      ports {
        container_port = each.value.port
      }

      resources {
        limits = {
          cpu    = each.value.cpu
          memory = each.value.memory
        }
      }

      # Static env vars
      dynamic "env" {
        for_each = each.value.env
        content {
          name  = env.value.name
          value = env.value.value
        }
      }

      # DATABASE_URL from Secret Manager
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_url.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/health"
          port = each.value.port
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 3
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = each.value.port
        }
        period_seconds = 30
      }
    }
  }

  # Allow unauthenticated access for public services (behind LB)
  # Private services require IAM auth
  depends_on = [
    google_secret_manager_secret_version.db_url,
    google_secret_manager_secret_version.jwt_key,
  ]
}

# Allow unauthenticated access to public services
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  for_each = local.public_services

  location = var.region
  name     = google_cloud_run_v2_service.services[each.key].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Internal services: allow Cloud Run service account to invoke
resource "google_cloud_run_v2_service_iam_member" "internal_access" {
  for_each = local.private_services

  location = var.region
  name     = google_cloud_run_v2_service.services[each.key].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.cloudrun.email}"
}


# ═══════════════════════════════════════════════════════════════
# 7. POST-DEPLOY: Update inter-service URLs
#    (Avoids circular dependency in for_each)
# ═══════════════════════════════════════════════════════════════

resource "terraform_data" "update_relay_url" {
  depends_on = [google_cloud_run_v2_service.services]

  triggers_replace = [
    google_cloud_run_v2_service.services["policy-engine"].uri,
  ]

  provisioner "local-exec" {
    command = <<-EOT
      gcloud run services update ${google_cloud_run_v2_service.services["relay-service"].name} \
        --region=${var.region} \
        --update-env-vars="LOCAL_POLICY_ENGINE_URL=${google_cloud_run_v2_service.services["policy-engine"].uri}" \
        --project=${var.project_id} \
        --quiet
    EOT
  }
}

resource "terraform_data" "update_discovery_url" {
  depends_on = [google_cloud_run_v2_service.services]

  triggers_replace = [
    google_cloud_run_v2_service.services["token-service"].uri,
  ]

  provisioner "local-exec" {
    command = <<-EOT
      gcloud run services update ${google_cloud_run_v2_service.services["discovery-service"].name} \
        --region=${var.region} \
        --update-env-vars="TOKEN_SERVICE_URL=${google_cloud_run_v2_service.services["token-service"].uri}" \
        --project=${var.project_id} \
        --quiet
    EOT
  }
}


# ═══════════════════════════════════════════════════════════════
# 8. GLOBAL HTTP(S) LOAD BALANCER
# ═══════════════════════════════════════════════════════════════

# Serverless NEGs for each public Cloud Run service
resource "google_compute_region_network_endpoint_group" "public_services" {
  for_each = local.public_services

  name                  = "${local.name_prefix}-${each.key}-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region

  cloud_run {
    service = google_cloud_run_v2_service.services[each.key].name
  }
}

# Backend services
resource "google_compute_backend_service" "public_services" {
  for_each = local.public_services

  name        = "${local.name_prefix}-${each.key}-backend"
  protocol    = "HTTP"
  port_name   = "http"
  timeout_sec = 30

  backend {
    group = google_compute_region_network_endpoint_group.public_services[each.key].id
  }
}

# URL map — path-based routing
resource "google_compute_url_map" "main" {
  name            = "${local.name_prefix}-url-map"
  default_service = google_compute_backend_service.public_services["web-ui"].id

  host_rule {
    hosts        = ["*"]
    path_matcher = "wid-paths"
  }

  path_matcher {
    name            = "wid-paths"
    default_service = google_compute_backend_service.public_services["web-ui"].id

    path_rule {
      paths   = ["/api/v1/relay/*", "/api/v1/relay"]
      service = google_compute_backend_service.public_services["relay-service"].id
    }

    path_rule {
      paths   = ["/api/v1/policies", "/api/v1/policies/*", "/api/v1/access/*", "/api/v1/decisions/*", "/api/v1/enforcement/*", "/api/v1/governance/*", "/api/v1/ai", "/api/v1/ai/*", "/api/v1/gateway", "/api/v1/gateway/*"]
      service = google_compute_backend_service.public_services["policy-engine"].id
    }

    path_rule {
      paths   = ["/api/v1/workloads", "/api/v1/workloads/*", "/api/v1/graph", "/api/v1/graph/*", "/api/v1/scanners", "/api/v1/scanners/*", "/api/v1/stats", "/api/v1/stats/*"]
      service = google_compute_backend_service.public_services["discovery-service"].id
    }

    path_rule {
      paths   = ["/health"]
      service = google_compute_backend_service.public_services["relay-service"].id
    }
  }
}

# HTTP proxy
resource "google_compute_target_http_proxy" "main" {
  name    = "${local.name_prefix}-http-proxy"
  url_map = google_compute_url_map.main.id
}

# Global forwarding rule (public IP)
resource "google_compute_global_forwarding_rule" "http" {
  name       = "${local.name_prefix}-http-rule"
  target     = google_compute_target_http_proxy.main.id
  port_range = "80"
}
