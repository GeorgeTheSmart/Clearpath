variable "repos" { type = list(string) }
variable "force_delete" {
  type    = bool
  default = true
}
variable "tags" {
  type    = map(string)
  default = {}
}
