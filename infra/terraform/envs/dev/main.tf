terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = local.tags }
}

locals {
  name = "clearpath-dev"
  tags = { project = "clearpath", env = "dev", owner = var.owner, ttl = "teardown-same-day" }
}

module "vpc" {
  source       = "../../modules/vpc"
  name         = local.name
  cluster_name = local.name
  tags         = local.tags
}

module "eks" {
  source              = "../../modules/eks"
  name                = local.name
  private_subnet_ids  = module.vpc.private_subnet_ids
  public_access_cidrs = var.my_ip_cidrs
  tags                = local.tags
}

module "audit_bucket" {
  source      = "../../modules/s3"
  name        = "${local.name}-audit-${var.account_suffix}"
  object_lock = true
  tags        = local.tags
}

module "ecr" {
  source = "../../modules/ecr"
  repos  = ["clearpath-correlator", "clearpath-agent"]
  tags   = local.tags
}

resource "aws_secretsmanager_secret" "agent" {
  name                    = "${local.name}/agent"
  recovery_window_in_days = 0
}

data "aws_eks_cluster" "this" { name = module.eks.cluster_name }

module "iam" {
  source            = "../../modules/iam"
  name              = local.name
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_issuer       = module.eks.oidc_issuer
  audit_bucket_arn  = module.audit_bucket.arn
  agent_secret_arn  = aws_secretsmanager_secret.agent.arn
  ecr_repo_arns     = module.ecr.repo_arns
  cluster_arn       = data.aws_eks_cluster.this.arn
  github_repo       = var.github_repo
  tags              = local.tags
}

output "cluster_name" { value = module.eks.cluster_name }
output "agent_role_arn" { value = module.iam.agent_role_arn }
output "github_actions_role_arn" { value = module.iam.github_actions_role_arn }
output "ecr" { value = module.ecr.repo_urls }
