# =============================================================================
# Outputs — AWS Spoke
# =============================================================================

output "vpc_id" {
  description = "VPC ID for the spoke"
  value       = aws_vpc.spoke.id
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.spoke.name
}

output "ecs_cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.spoke.arn
}

output "alb_dns_name" {
  description = "ALB DNS name (spoke entry point)"
  value       = aws_lb.spoke.dns_name
}

output "alb_url" {
  description = "ALB URL for spoke health check"
  value       = "http://${aws_lb.spoke.dns_name}"
}

output "relay_service_name" {
  description = "ECS service name for relay"
  value       = aws_ecs_service.relay.name
}

output "gateway_service_names" {
  description = "Map of gateway names to ECS service names"
  value       = { for k, v in aws_ecs_service.gateway : k => v.name }
}

output "ecr_relay_url" {
  description = "ECR repository URL for relay image"
  value       = aws_ecr_repository.relay.repository_url
}

output "ecr_gateway_url" {
  description = "ECR repository URL for edge-gateway image"
  value       = aws_ecr_repository.gateway.repository_url
}

output "relay_discovery_dns" {
  description = "Service discovery DNS for relay (used by gateways)"
  value       = "relay.spoke.local"
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for all spoke containers"
  value       = aws_cloudwatch_log_group.spoke.name
}

output "spoke_summary" {
  description = "Quick summary of the spoke deployment"
  value = {
    environment  = var.environment_name
    central_url  = var.central_url
    relay_url    = "http://${aws_lb.spoke.dns_name}/health"
    gateway_urls = { for k, v in var.gateway_configs : k => "http://${aws_lb.spoke.dns_name}/gw/${k}" }
    region       = var.aws_region
  }
}
