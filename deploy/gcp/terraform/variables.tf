variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "project_name" {
  type    = string
  default = "wid"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "subnet_cidr" {
  type    = string
  default = "10.0.0.0/24"
}

variable "db_name" {
  type    = string
  default = "workload_identity"
}

variable "db_tier" {
  type        = string
  default     = "db-f1-micro"
  description = "Cloud SQL machine type (db-f1-micro for dev, db-custom-2-7680 for prod)"
}
