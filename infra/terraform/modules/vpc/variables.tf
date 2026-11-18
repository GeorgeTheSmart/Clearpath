variable "name" { type = string }
variable "cluster_name" { type = string }
variable "cidr" {
  type    = string
  default = "10.40.0.0/16"
}
variable "az_count" {
  type    = number
  default = 2
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "EKS needs subnets in at least two AZs."
  }
}
variable "nat_per_az" {
  type    = bool
  default = false
}
variable "flow_log_bucket_arn" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}
