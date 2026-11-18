variable "name" { type = string }
variable "object_lock" {
  type    = bool
  default = false
}
variable "retention_days" {
  type    = number
  default = 30
}
variable "kms_key_arn" {
  type    = string
  default = ""
}
variable "force_destroy" {
  type        = bool
  default     = true
  description = "Demo default so make aws-down can delete the bucket. Set false for real use."
}
variable "tags" {
  type    = map(string)
  default = {}
}
