variable "name" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "kubernetes_version" {
  type    = string
  default = "1.31"
}
variable "public_endpoint" {
  type    = bool
  default = true
}
variable "public_access_cidrs" {
  type        = list(string)
  description = "Restrict the public API endpoint to your IP (x.x.x.x/32)."
}
variable "instance_types" {
  type    = list(string)
  default = ["t3.large"]
}
variable "spot" {
  type    = bool
  default = true
}
variable "desired_size" {
  type    = number
  default = 2
}
variable "min_size" {
  type    = number
  default = 2
}
variable "max_size" {
  type    = number
  default = 3
}
variable "tags" {
  type    = map(string)
  default = {}
}
