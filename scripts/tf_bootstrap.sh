#!/usr/bin/env bash
# One-time: create the Terraform state bucket and lock table (asks before creating).
set -euo pipefail
B=${1:?state bucket name}; R=${2:-ap-south-1}
read -r -p "Create s3://$B and DynamoDB table clearpath-tflock in $R (small ongoing cost)? [y/N] " ok
[[ "$ok" == "y" ]] || exit 1
aws s3api create-bucket --bucket "$B" --region "$R" --create-bucket-configuration LocationConstraint="$R"
aws s3api put-bucket-versioning --bucket "$B" --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket "$B" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws dynamodb create-table --table-name clearpath-tflock --attribute-definitions AttributeName=LockID,AttributeType=S --key-schema AttributeName=LockID,KeyType=HASH --billing-mode PAY_PER_REQUEST --region "$R"
