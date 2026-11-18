variable "region" {
  type    = string
  default = "ap-south-1"
}
variable "owner" { type = string }
variable "my_ip_cidrs" {
  type        = list(string)
  description = "Your public IP as x.x.x.x/32 for the EKS API endpoint."
}
variable "account_suffix" {
  type        = string
  description = "Short unique suffix for globally unique bucket names."
}
variable "github_repo" {
  type    = string
  default = "GeorgeTheSmart/clearpath"
}
