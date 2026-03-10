# =============================================================================
# AWS EKS Deployment — Terraform Module
# =============================================================================
#
# Creates:
#   - wid-system namespace
#   - IRSA roles (no static credentials)
#   - RDS PostgreSQL (IAM auth, no passwords)
#   - ECR repositories
#   - Security groups
#   - CloudWatch log groups
#
# Usage:
#   terraform init
#   terraform plan -var="cluster_name=my-eks-cluster" -var="account_id=123456789012"
#   terraform apply
#
# Then deploy Kubernetes manifests:
#   kubectl apply -f ../k8s/
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.0" }
  }
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name"
}

variable "account_id" {
  type        = string
  description = "AWS account ID"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where EKS runs"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for RDS"
}

variable "eks_oidc_provider_arn" {
  type        = string
  description = "EKS OIDC provider ARN for IRSA"
}

variable "eks_oidc_provider_url" {
  type        = string
  description = "EKS OIDC provider URL (without https://)"
}

provider "aws" {
  region = var.region
}

# ── Namespace ──
resource "kubernetes_namespace" "wid_system" {
  metadata {
    name = "wid-system"
    labels = {
      "istio-injection"           = "enabled"
      "app.kubernetes.io/part-of" = "wid-platform"
    }
  }
}

# ── ECR Repositories ──
locals {
  images = ["ext-authz-adapter", "policy-engine", "token-service", "credential-broker"]
}

resource "aws_ecr_repository" "wid" {
  for_each             = toset(local.images)
  name                 = "wid/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
}

# ── IRSA: ext-authz-adapter role ──
# Permissions: CloudWatch Logs (write), no access to customer data
resource "aws_iam_role" "ext_authz_adapter" {
  name = "wid-ext-authz-adapter-${var.cluster_name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider_url}:sub" = "system:serviceaccount:wid-system:ext-authz-adapter"
          "${var.eks_oidc_provider_url}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ext_authz_logs" {
  name = "cloudwatch-logs"
  role = aws_iam_role.ext_authz_adapter.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.ext_authz.arn}:*"
    }]
  })
}

# ── IRSA: control-plane role ──
# Permissions: RDS IAM auth, Secrets Manager (read), CloudWatch Logs
resource "aws_iam_role" "control_plane" {
  name = "wid-control-plane-${var.cluster_name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider_url}:sub" = "system:serviceaccount:wid-system:wid-control-plane"
          "${var.eks_oidc_provider_url}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "control_plane_policy" {
  name = "control-plane-access"
  role = aws_iam_role.control_plane.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["rds-db:connect"]
        Resource = "arn:aws:rds-db:${var.region}:${var.account_id}:dbuser:${aws_db_instance.wid.resource_id}/wid_app"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:wid/*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.control_plane.arn}:*"
      },
    ]
  })
}

# ── RDS PostgreSQL (IAM auth, encrypted, no public access) ──
resource "aws_db_subnet_group" "wid" {
  name       = "wid-${var.cluster_name}"
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "rds" {
  name_prefix = "wid-rds-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    description = "PostgreSQL from EKS pods"
    cidr_blocks = ["10.0.0.0/8"] # Adjust to your VPC CIDR
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "wid" {
  identifier     = "wid-${var.cluster_name}"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.medium"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true

  db_name  = "workload_identity"
  username = "wid_admin"
  # Use IAM auth — no static password needed by apps
  iam_database_authentication_enabled = true
  manage_master_user_password         = true

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.wid.name
  publicly_accessible    = false
  multi_az               = true

  backup_retention_period = 7
  deletion_protection     = true

  tags = { Service = "wid-platform", ManagedBy = "terraform" }
}

# ── CloudWatch Log Groups ──
resource "aws_cloudwatch_log_group" "ext_authz" {
  name              = "/wid/ext-authz"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/wid/control-plane"
  retention_in_days = 90
}

# ── Outputs ──
output "ext_authz_role_arn" {
  value = aws_iam_role.ext_authz_adapter.arn
}

output "control_plane_role_arn" {
  value = aws_iam_role.control_plane.arn
}

output "rds_endpoint" {
  value = aws_db_instance.wid.endpoint
}

output "ecr_repositories" {
  value = { for k, v in aws_ecr_repository.wid : k => v.repository_url }
}
