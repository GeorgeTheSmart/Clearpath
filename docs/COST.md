# Cost and teardown

The **local path is free**: kind, Docker and Ollama. The AWS path is for one afternoon: `make aws-up`, demo, `make aws-down`. `make aws-up` asks for confirmation before creating anything.

## Hourly estimate (ap-south-1, dev env as written)

| Item | Qty | Rate used | Source (checked 2026-11-18) | $/h |
|---|---|---|---|---|
| EKS control plane, standard support | 1 | $0.10/h | AWS EKS pricing page | 0.100 |
| NAT gateway (single, not per AZ) | 1 | $0.056/h + $0.056/GB | AWS VPC pricing for Mumbai (archived copy; **verify**) | 0.056 |
| t3.large nodes, Spot (`spot = true` default) | 2 | about $0.033–0.038/h | third-party Spot tracker (DoiT), **verify** | ≈0.076 |
| t3.large nodes if On-Demand instead | 2 | $0.0896/h | same tracker, **verify** | (0.179) |
| EBS gp3 root volumes, KMS key, Secrets Manager secret, S3, ECR, CloudWatch control-plane logs | — | small, usage-based | — | < 0.05 (estimate) |

**Total:**
* Spot nodes: **about $0.23–0.28/h**, so a 5-hour afternoon costs about **$1.2–1.4**, plus NAT data processing (cents for a demo).
* On-Demand nodes: about $0.34–0.39/h.

Some costs persist after teardown if you forget them:
* a Secrets Manager secret is charged monthly (`recovery_window_in_days = 0` makes it delete at once);
* KMS keys go into a 7–30 day pending deletion (charged until deleted);
* the Terraform state bucket and lock table cost cents per month.

Prices change. Before applying, run the AWS Pricing Calculator, or:

```bash
aws ec2 describe-spot-price-history --instance-types t3.large --product-descriptions "Linux/UNIX" --region ap-south-1 --max-items 3
```

## Teardown checklist {#teardown}

1. `helm uninstall clearpath -n clearpath` and delete any `Service type=LoadBalancer`. Do this **before** destroy: ELBs created by Kubernetes are not in Terraform state.
2. `make aws-down` (`terraform destroy`).
3. Check for orphans:
   * `aws elbv2 describe-load-balancers`
   * `aws ec2 describe-volumes --filters Name=status,Values=available`
   * `aws ec2 describe-addresses` (unattached EIPs are billed)
   * `aws ec2 describe-network-interfaces --filters Name=status,Values=available`
4. CloudWatch log group `/aws/eks/clearpath-dev/cluster`: delete it, or set its retention.
5. `aws kms list-keys`: confirm the EKS key is pending deletion.
6. Optional: delete the state bucket and the `clearpath-tflock` table.
7. Billing console → Cost Explorer, filtered by tag `project=clearpath`, the next day.
