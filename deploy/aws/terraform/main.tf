# =============================================================================
# WID Platform — Production AWS Infrastructure (ECS Fargate)
# =============================================================================
#
# Creates:
#   - VPC with public/private/database subnets across 2 AZs
#   - ECS Fargate cluster (no EC2 instances needed)
#   - RDS PostgreSQL 16 (encrypted)
#   - ECR repositories for all services
#   - ALB for external access
#   - Secrets Manager for sensitive config
#   - CloudWatch log groups
#   - ECS services for all WID components
#
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags { tags = local.common_tags }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

locals {
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)
  account_id = data.aws_caller_identity.current.account_id
}


# ═══════════════════════════════════════════════════════════════
# 1. VPC
# ═══════════════════════════════════════════════════════════════

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name_prefix}-public-${local.azs[count.index]}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.name_prefix}-private-${local.azs[count.index]}" }
}

resource "aws_subnet" "database" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.name_prefix}-db-${local.azs[count.index]}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.name_prefix}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.name_prefix}-nat" }
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "database" {
  count          = 2
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.private.id
}


# ═══════════════════════════════════════════════════════════════
# 2. ECS FARGATE CLUSTER
# ═══════════════════════════════════════════════════════════════

resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-ecs"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ECS task execution role (pull images, write logs)
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name_prefix}-ecs-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  role       = aws_iam_role.ecs_execution.name
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.ecs_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.db_credentials.arn, aws_secretsmanager_secret.jwt_secret.arn]
    }]
  })
}

# ECS task role (what the containers can do at runtime)
resource "aws_iam_role" "ecs_task" {
  name = "${local.name_prefix}-ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}


# ═══════════════════════════════════════════════════════════════
# 3. RDS PostgreSQL
# ═══════════════════════════════════════════════════════════════

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = aws_subnet.database[*].id
  tags       = { Name = "${local.name_prefix}-db-subnets" }
}

resource "aws_security_group" "rds" {
  name_prefix = "${local.name_prefix}-rds-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
    description     = "Allow ECS tasks"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-rds-sg" }
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "${local.name_prefix}-db-credentials-v2"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "wid_admin"
    password = random_password.db_password.result
    host     = aws_db_instance.main.address
    port     = 5432
    dbname   = var.db_name
    url      = "postgresql://wid_admin:${random_password.db_password.result}@${aws_db_instance.main.address}:5432/${var.db_name}"
  })
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-postgres"
  engine         = "postgres"
  engine_version = "16.11"
  instance_class = var.rds_instance_classes[var.deployment_size]

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = "wid_admin"
  password = random_password.db_password.result

  multi_az               = var.rds_multi_az[var.deployment_size]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = var.deployment_size == "dev" ? 1 : 7
  skip_final_snapshot     = var.deployment_size == "dev"
  deletion_protection     = var.deployment_size != "dev"

  tags = { Name = "${local.name_prefix}-postgres" }
}


# ═══════════════════════════════════════════════════════════════
# 4. ECR Repositories
# ═══════════════════════════════════════════════════════════════

locals {
  ecr_repos = [
    "policy-engine", "token-service", "credential-broker",
    "discovery-service", "relay-service", "web-ui", "edge-gateway",
  ]
}

resource "aws_ecr_repository" "services" {
  for_each             = toset(local.ecr_repos)
  name                 = "${var.project_name}/${each.value}"
  image_tag_mutability = "MUTABLE"
  force_delete         = var.deployment_size == "dev"

  image_scanning_configuration { scan_on_push = true }
  tags = { Service = each.value }
}


# ═══════════════════════════════════════════════════════════════
# 5. Security Groups
# ═══════════════════════════════════════════════════════════════

resource "aws_security_group" "alb" {
  name_prefix = "${local.name_prefix}-alb-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-alb-sg" }
}

resource "aws_security_group" "ecs_tasks" {
  name_prefix = "${local.name_prefix}-ecs-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "From ALB"
  }

  # Allow inter-service communication
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
    description = "Inter-service"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-ecs-sg" }
}


# ═══════════════════════════════════════════════════════════════
# 6. ALB
# ═══════════════════════════════════════════════════════════════

resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${local.name_prefix}-alb" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_ui.arn
  }
}

# Target groups
resource "aws_lb_target_group" "web_ui" {
  name        = "${local.name_prefix}-web-ui"
  port        = 3100
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_target_group" "relay" {
  name        = "${local.name_prefix}-relay"
  port        = 3005
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_target_group" "policy_engine" {
  name        = "${local.name_prefix}-policy"
  port        = 3001
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

# Listener rules — route by path
resource "aws_lb_listener_rule" "relay" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }

  condition {
    path_pattern { values = ["/api/v1/relay/*", "/health"] }
  }
}

resource "aws_lb_listener_rule" "policy" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.policy_engine.arn
  }

  condition {
    path_pattern { values = ["/api/v1/policies/*", "/api/v1/access/*"] }
  }
}


# ═══════════════════════════════════════════════════════════════
# 7. CloudWatch Log Groups
# ═══════════════════════════════════════════════════════════════

resource "aws_cloudwatch_log_group" "wid" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = var.deployment_size == "dev" ? 7 : 90
}


# ═══════════════════════════════════════════════════════════════
# 8. ECS Service Discovery (so services find each other)
# ═══════════════════════════════════════════════════════════════

resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "wid.local"
  description = "WID internal service discovery"
  vpc         = aws_vpc.main.id
}

resource "aws_service_discovery_service" "services" {
  for_each = toset(["policy-engine", "token-service", "credential-broker", "discovery-service", "relay-service", "web-ui"])

  name = each.value

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id
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


# ═══════════════════════════════════════════════════════════════
# 9. Secrets (JWT signing key)
# ═══════════════════════════════════════════════════════════════

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "${local.name_prefix}-jwt-signing-key-v2"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = random_password.jwt_secret.result
}


# ═══════════════════════════════════════════════════════════════
# 10. ECS TASK DEFINITIONS & SERVICES
# ═══════════════════════════════════════════════════════════════

locals {
  ecr_registry = "${local.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"

  services = {
    policy-engine = {
      port    = 3001
      cpu     = 256
      memory  = 512
      desired = 2
      env = [
        { name = "PORT", value = "3001" },
        { name = "OPA_COMPILER", value = "node" },
      ]
    }
    token-service = {
      port    = 3000
      cpu     = 256
      memory  = 512
      desired = 1
      env = [
        { name = "PORT", value = "3000" },
      ]
    }
    credential-broker = {
      port    = 3002
      cpu     = 256
      memory  = 512
      desired = 1
      env = [
        { name = "PORT", value = "3002" },
      ]
    }
    discovery-service = {
      port    = 3003
      cpu     = 256
      memory  = 512
      desired = 1
      env = [
        { name = "PORT", value = "3003" },
        { name = "SPIRE_TRUST_DOMAIN", value = "company.com" },
        { name = "AWS_REGION", value = var.aws_region },
      ]
    }
    relay-service = {
      port    = 3005
      cpu     = 256
      memory  = 512
      desired = 2
      env = [
        { name = "PORT", value = "3005" },
        { name = "ENVIRONMENT_NAME", value = "aws-production" },
        { name = "ENVIRONMENT_TYPE", value = "ecs" },
        { name = "REGION", value = var.aws_region },
        { name = "CLUSTER_ID", value = "wid-dev-ecs" },
        { name = "CENTRAL_CONTROL_PLANE_URL", value = "" },
        { name = "LOCAL_POLICY_ENGINE_URL", value = "http://policy-engine.wid.local:3001" },
      ]
    }
    web-ui = {
      port    = 3100
      cpu     = 256
      memory  = 512
      desired = 1
      env = [
        { name = "PORT", value = "3100" },
      ]
    }
  }
}

resource "aws_ecs_task_definition" "services" {
  for_each = local.services

  family                   = "${local.name_prefix}-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name  = each.key
    image = "${local.ecr_registry}/wid/${each.key}:latest"
    portMappings = [{ containerPort = each.value.port, protocol = "tcp" }]

    environment = concat(each.value.env, [
      { name = "DATABASE_URL", value = "PLACEHOLDER" }
    ])

    secrets = [
      {
        name      = "DATABASE_URL"
        valueFrom = "${aws_secretsmanager_secret.db_credentials.arn}:url::"
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.wid.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = each.key
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "wget -qO- http://localhost:${each.value.port}/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_ecs_service" "services" {
  for_each = local.services

  name            = each.key
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.services[each.key].arn
  desired_count   = each.value.desired
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.services[each.key].arn
  }

  # ALB target group attachment for services that need it
  dynamic "load_balancer" {
    for_each = each.key == "web-ui" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.web_ui.arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  dynamic "load_balancer" {
    for_each = each.key == "relay-service" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.relay.arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  dynamic "load_balancer" {
    for_each = each.key == "policy-engine" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.policy_engine.arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  depends_on = [aws_lb_listener.http]
}
