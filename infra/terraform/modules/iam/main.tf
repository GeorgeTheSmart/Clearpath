# Least-privilege roles:
#  * agent (IRSA): may only write audit objects under audit/ in the audit bucket
#    and read its own secret; nothing else in AWS. Kubernetes permissions are
#    separate (Helm RBAC Role, one namespace, no delete/exec).
#  * GitHub Actions (OIDC): push images to the two ECR repos and run terraform
#    plan for this repo's main branch / production environment only.
data "aws_iam_policy_document" "agent_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer}:sub"
      values   = ["system:serviceaccount:${var.agent_namespace}:clearpath-agent"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "agent" {
  name               = "${var.name}-agent"
  assume_role_policy = data.aws_iam_policy_document.agent_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "agent" {
  statement {
    sid       = "WriteAuditOnly"
    actions   = ["s3:PutObject"]
    resources = ["${var.audit_bucket_arn}/audit/*"]
  }
  statement {
    sid       = "ReadOwnSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.agent_secret_arn]
  }
}

resource "aws_iam_role_policy" "agent" {
  name   = "agent"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent.json
}

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_github_oidc ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "gha_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.create_github_oidc ? aws_iam_openid_connect_provider.github[0].arn : var.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main", "repo:${var.github_repo}:environment:production", "repo:${var.github_repo}:environment:staging"]
    }
  }
}

resource "aws_iam_role" "gha" {
  name               = "${var.name}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.gha_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "gha" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrPush"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage"]
    resources = var.ecr_repo_arns
  }
  statement {
    sid       = "EksDescribe"
    actions   = ["eks:DescribeCluster"]
    resources = [var.cluster_arn]
  }
}

resource "aws_iam_role_policy" "gha" {
  name   = "ci"
  role   = aws_iam_role.gha.id
  policy = data.aws_iam_policy_document.gha.json
}
