output "load_balancer_ip" {
  value       = google_compute_global_forwarding_rule.http.ip_address
  description = "Global HTTP LB IP — access web-ui, relay, policy-engine"
}

output "web_ui_url" {
  value = "http://${google_compute_global_forwarding_rule.http.ip_address}"
}

output "relay_url" {
  value = "http://${google_compute_global_forwarding_rule.http.ip_address}/api/v1/relay/environments"
}

output "cloud_sql_ip" {
  value     = google_sql_database_instance.main.private_ip_address
  sensitive = true
}

output "artifact_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

output "cloud_run_urls" {
  value = { for k, v in google_cloud_run_v2_service.services : k => v.uri }
}

output "docker_push_commands" {
  value = <<-EOT
    # Authenticate Docker to Artifact Registry
    gcloud auth configure-docker ${var.region}-docker.pkg.dev

    # Build and push (run from project root):
    REGISTRY="${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"

    docker build -t $REGISTRY/policy-engine:latest services/policy-sync-service
    docker build -t $REGISTRY/token-service:latest services/token-service
    docker build -t $REGISTRY/credential-broker:latest services/credential-broker
    docker build -t $REGISTRY/discovery-service:latest services/discovery-service
    docker build -t $REGISTRY/relay-service:latest services/relay-service
    docker build -t $REGISTRY/web-ui:latest web/workload-identity-manager

    docker push $REGISTRY/policy-engine:latest
    docker push $REGISTRY/token-service:latest
    docker push $REGISTRY/credential-broker:latest
    docker push $REGISTRY/discovery-service:latest
    docker push $REGISTRY/relay-service:latest
    docker push $REGISTRY/web-ui:latest
  EOT
}
