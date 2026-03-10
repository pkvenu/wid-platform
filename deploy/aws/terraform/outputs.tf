output "alb_dns" {
  value = aws_lb.main.dns_name
}

output "ecs_cluster" {
  value = aws_ecs_cluster.main.name
}

output "rds_endpoint" {
  value = aws_db_instance.main.address
}

output "ecr_registry" {
  value = "${local.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "web_ui_url" {
  value = "http://${aws_lb.main.dns_name}"
}

output "relay_url" {
  value = "http://${aws_lb.main.dns_name}/api/v1/relay/environments"
}

output "central_url" {
  value = "http://${aws_lb.main.dns_name}"
}
