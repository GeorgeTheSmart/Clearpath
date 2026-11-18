variable "name" { type = string }
variable "oidc_provider_arn" { type = string }
variable "oidc_issuer" { type = string }
variable "agent_namespace" {
  type    = string
  default = "clearpath"
}
variable "audit_bucket_arn" { type = string }
variable "agent_secret_arn" { type = string }
variable "ecr_repo_arns" { type = list(string) }
variable "cluster_arn" { type = string }
variable "github_repo" {
  type        = string
  description = "owner/name"
}
variable "create_github_oidc" {
  type    = bool
  default = true
}
variable "github_oidc_provider_arn" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}
