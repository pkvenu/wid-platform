variable "project_name" {
  type    = string
  default = "wid"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "deployment_size" {
  type    = string
  default = "dev"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "db_name" {
  type    = string
  default = "workload_identity"
}

variable "rds_instance_classes" {
  type = map(string)
  default = {
    dev        = "db.t3.micro"
    production = "db.r6g.large"
    enterprise = "db.r6g.xlarge"
  }
}

variable "rds_multi_az" {
  type = map(bool)
  default = {
    dev        = false
    production = true
    enterprise = true
  }
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
  name_prefix = "${var.project_name}-${var.environment}"
}
