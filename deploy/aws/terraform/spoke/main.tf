# =============================================================================
# WID Spoke — AWS ECS Fargate
# =============================================================================
# Deploys: 1 relay (spoke mode) + N edge-gateways (one per workload)
# No database — all state flows through relay to GCP central control plane.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

# ─── Data Sources ────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

# ─── VPC ─────────────────────────────────────────────────────────────────────

resource "aws_vpc" "spoke" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "spoke" {
  vpc_id = aws_vpc.spoke.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

# Public subnets (ALB)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.spoke.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

# Private subnets (ECS tasks)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.spoke.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

# NAT Gateway (ECS tasks need outbound internet for image pull + central comms)
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.name_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "spoke" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "${local.name_prefix}-nat" }
  depends_on = [aws_internet_gateway.spoke]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.spoke.id
  tags   = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.spoke.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.spoke.id
  tags   = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.spoke.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ─── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name_prefix = "${local.name_prefix}-alb-"
  vpc_id      = aws_vpc.spoke.id
  description = "ALB: allow inbound HTTP"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = { Name = "${local.name_prefix}-alb-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "ecs_tasks" {
  name_prefix = "${local.name_prefix}-ecs-"
  vpc_id      = aws_vpc.spoke.id
  description = "ECS tasks: allow ALB + inter-task traffic"

  # ALB → relay (3005)
  ingress {
    from_port       = 3005
    to_port         = 3005
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "ALB to relay"
  }

  # ALB → gateway external ports
  dynamic "ingress" {
    for_each = var.gateway_configs
    content {
      from_port       = ingress.value.external_port
      to_port         = ingress.value.external_port
      protocol        = "tcp"
      security_groups = [aws_security_group.alb.id]
      description     = "ALB to gw-${ingress.key}"
    }
  }

  # Inter-task: gateways → relay (3005)
  ingress {
    from_port   = 3005
    to_port     = 3005
    protocol    = "tcp"
    self        = true
    description = "Inter-task: gateways to relay"
  }

  # All outbound (image pull, central comms, agent traffic)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = { Name = "${local.name_prefix}-ecs-sg" }

  lifecycle { create_before_destroy = true }
}

# ─── ECR Repositories ───────────────────────────────────────────────────────

resource "aws_ecr_repository" "relay" {
  name                 = "${var.project_name}/relay-service"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration { scan_on_push = true }
  tags = { Name = "${local.name_prefix}-ecr-relay" }
}

resource "aws_ecr_repository" "gateway" {
  name                 = "${var.project_name}/edge-gateway"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration { scan_on_push = true }
  tags = { Name = "${local.name_prefix}-ecr-gateway" }
}

# ─── CloudWatch Logs ─────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "spoke" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 30

  tags = { Name = "${local.name_prefix}-logs" }
}

# ─── ECS Cluster ─────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "spoke" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${local.name_prefix}-cluster" }
}

# ─── IAM Roles ───────────────────────────────────────────────────────────────

# ECS execution role (pull images, write logs)
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name_prefix}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name_prefix}-ecs-execution" }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS task role (runtime permissions — minimal for spoke)
resource "aws_iam_role" "ecs_task" {
  name = "${local.name_prefix}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${local.name_prefix}-ecs-task" }
}

# Allow task to read central API key from Secrets Manager
resource "aws_iam_role_policy" "ecs_task_secrets" {
  count = var.central_api_key != "" ? 1 : 0
  name  = "read-central-api-key"
  role  = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.central_api_key[0].arn]
    }]
  })
}

# ─── Secrets Manager (optional central API key) ─────────────────────────────

resource "aws_secretsmanager_secret" "central_api_key" {
  count       = var.central_api_key != "" ? 1 : 0
  name        = "${local.name_prefix}-central-api-key"
  description = "API key for authenticating spoke relay with GCP central hub"

  tags = { Name = "${local.name_prefix}-central-api-key" }
}

resource "aws_secretsmanager_secret_version" "central_api_key" {
  count         = var.central_api_key != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.central_api_key[0].id
  secret_string = var.central_api_key
}

# ─── Service Discovery (relay.spoke.local) ───────────────────────────────────

resource "aws_service_discovery_private_dns_namespace" "spoke" {
  name = "spoke.local"
  vpc  = aws_vpc.spoke.id

  tags = { Name = "${local.name_prefix}-dns" }
}

resource "aws_service_discovery_service" "relay" {
  name = "relay"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.spoke.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# ─── ECS Task Definition: Relay (spoke mode) ────────────────────────────────

resource "aws_ecs_task_definition" "relay" {
  family                   = "${local.name_prefix}-relay"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.relay_cpu
  memory                   = var.relay_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "relay"
    image     = "${aws_ecr_repository.relay.repository_url}:latest"
    essential = true

    portMappings = [{
      containerPort = 3005
      protocol      = "tcp"
    }]

    environment = [
      { name = "PORT", value = "3005" },
      { name = "CENTRAL_CONTROL_PLANE_URL", value = var.central_url },
      { name = "ENVIRONMENT_NAME", value = var.environment_name },
      { name = "ENVIRONMENT_TYPE", value = "ecs" },
      { name = "REGION", value = var.aws_region },
      { name = "CLUSTER_ID", value = "${local.name_prefix}-cluster" },
      { name = "POLICY_SYNC_INTERVAL_MS", value = "15000" },
      { name = "AUDIT_FLUSH_INTERVAL_MS", value = "5000" },
      { name = "HEALTH_REPORT_INTERVAL_MS", value = "60000" },
    ]

    secrets = var.central_api_key != "" ? [{
      name      = "CENTRAL_API_KEY"
      valueFrom = aws_secretsmanager_secret.central_api_key[0].arn
    }] : []

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.spoke.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "relay"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:3005/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])

  tags = { Name = "${local.name_prefix}-relay-task" }
}

# ─── ECS Service: Relay ─────────────────────────────────────────────────────

resource "aws_ecs_service" "relay" {
  name            = "${local.name_prefix}-relay"
  cluster         = aws_ecs_cluster.spoke.id
  task_definition = aws_ecs_task_definition.relay.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.relay.arn
    container_name   = "relay"
    container_port   = 3005
  }

  service_registries {
    registry_arn = aws_service_discovery_service.relay.arn
  }

  depends_on = [aws_lb_listener.spoke]
}

# ─── ECS Task Definitions: Edge Gateways (one per workload) ─────────────────

resource "aws_ecs_task_definition" "gateway" {
  for_each = var.gateway_configs

  family                   = "${local.name_prefix}-gw-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.gateway_cpu
  memory                   = var.gateway_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "gateway"
    image     = "${aws_ecr_repository.gateway.repository_url}:latest"
    essential = true

    portMappings = [
      { containerPort = 15001, protocol = "tcp" },
      { containerPort = 15000, protocol = "tcp" },
    ]

    environment = [
      # Port config
      { name = "OUTBOUND_PORT", value = "15001" },
      { name = "INBOUND_PORT", value = "15006" },
      { name = "ADMIN_PORT", value = "15000" },
      # Target workload
      { name = "APP_HOST", value = each.value.app_host },
      { name = "APP_PORT", value = tostring(each.value.app_port) },
      { name = "WORKLOAD_NAME", value = each.value.workload_name },
      { name = "WORKLOAD_NS", value = "demo-blended" },
      { name = "TRUST_DOMAIN", value = "company.com" },
      # Point to local spoke relay (via service discovery)
      { name = "POLICY_SERVICE_URL", value = "http://relay.spoke.local:3005" },
      { name = "TOKEN_SERVICE_URL", value = "http://relay.spoke.local:3005" },
      { name = "BROKER_URL", value = "http://relay.spoke.local:3005" },
      # Behavioral defaults
      { name = "DEFAULT_MODE", value = "audit" },
      { name = "FAIL_BEHAVIOR", value = "open" },
      { name = "LOG_LEVEL", value = "info" },
      { name = "STRUCTURED_LOGS", value = "true" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.spoke.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "gw-${each.key}"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:15000/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 20
    }
  }])

  tags = { Name = "${local.name_prefix}-gw-${each.key}-task" }
}

# ─── ECS Services: Edge Gateways ────────────────────────────────────────────

resource "aws_ecs_service" "gateway" {
  for_each = var.gateway_configs

  name            = "${local.name_prefix}-gw-${each.key}"
  cluster         = aws_ecs_cluster.spoke.id
  task_definition = aws_ecs_task_definition.gateway[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gateway[each.key].arn
    container_name   = "gateway"
    container_port   = 15001
  }

  depends_on = [aws_lb_listener.spoke, aws_ecs_service.relay]
}

# ─── ALB ─────────────────────────────────────────────────────────────────────

resource "aws_lb" "spoke" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${local.name_prefix}-alb" }
}

# Default listener (returns 404 for unmatched paths)
resource "aws_lb_listener" "spoke" {
  load_balancer_arn = aws_lb.spoke.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\":\"not found\"}"
      status_code  = "404"
    }
  }

  tags = { Name = "${local.name_prefix}-listener" }
}

# ── Target group: relay ──────────────────────────────────────────────────────

resource "aws_lb_target_group" "relay" {
  name        = "${local.name_prefix}-relay"
  port        = 3005
  protocol    = "HTTP"
  vpc_id      = aws_vpc.spoke.id
  target_type = "ip"

  health_check {
    path                = "/health"
    port                = "3005"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = { Name = "${local.name_prefix}-relay-tg" }
}

# Relay listener rules: /health, /api/v1/relay/*
resource "aws_lb_listener_rule" "relay_health" {
  listener_arn = aws_lb_listener.spoke.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }

  condition {
    path_pattern { values = ["/health"] }
  }
}

resource "aws_lb_listener_rule" "relay_api" {
  listener_arn = aws_lb_listener.spoke.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }

  condition {
    path_pattern { values = ["/api/v1/relay/*"] }
  }
}

# ── Target groups + listener rules: each gateway on its external_port ────────

resource "aws_lb_target_group" "gateway" {
  for_each = var.gateway_configs

  name        = "${local.name_prefix}-gw-${substr(each.key, 0, 10)}"
  port        = 15001
  protocol    = "HTTP"
  vpc_id      = aws_vpc.spoke.id
  target_type = "ip"

  health_check {
    path                = "/health"
    port                = "15000"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = { Name = "${local.name_prefix}-gw-${each.key}-tg" }
}

# Host-header routing: gw-{name}.{alb-dns} → gateway target group
# Alternative: port-based routing via NLB, or path-based with /gw/{name}/*
resource "aws_lb_listener_rule" "gateway" {
  for_each = var.gateway_configs

  listener_arn = aws_lb_listener.spoke.arn
  priority     = 100 + index(keys(var.gateway_configs), each.key)

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway[each.key].arn
  }

  condition {
    path_pattern {
      values = ["/gw/${each.key}", "/gw/${each.key}/*"]
    }
  }
}
