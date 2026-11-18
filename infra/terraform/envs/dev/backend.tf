# Remote state with locking. Create the bucket + table once with
# `make tf-bootstrap` (scripts/tf_bootstrap.sh), then `terraform init`.
terraform {
  backend "s3" {
    bucket         = "clearpath-tfstate-CHANGE-ME"
    key            = "envs/dev/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "clearpath-tflock"
    encrypt        = true
  }
}
