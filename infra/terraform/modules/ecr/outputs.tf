output "repo_arns" { value = [for r in aws_ecr_repository.this : r.arn] }
output "repo_urls" { value = { for k, r in aws_ecr_repository.this : k => r.repository_url } }
