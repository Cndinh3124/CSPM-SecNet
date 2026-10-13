# SecNet CSPM Automation v1

Cost-minimized CSPM demonstration pipeline:

```
Terraform (minimal Security Group)
  -> Prowler assessment (run locally)
  -> Finding normalization
  -> Risk prioritization
  -> Gemini security analysis (run locally)
  -> CSV / XLSX / HTML / JSON reports
  -> Controlled remediation
  -> Prowler re-scan
  -> Verification
```

## Cost-minimized AWS design

The Terraform demo uses the account's existing default VPC and creates only a Security Group plus its SSH ingress rule. It does not create compute or billable managed services.

Not created: EC2, public IPv4, Internet Gateway, subnets, route tables, NAT Gateway, ALB, RDS, S3, ECS, or EKS.

Prowler and Gemini orchestration are intended to run locally. Gemini receives finding context only; do not send AWS credentials, access keys, secrets, or private data to the model.

## Design principles

- AWS findings are real; findings are not mocked.
- Terraform is the infrastructure source of truth.
- Prowler is the authoritative detection layer.
- Gemini is an advisory security-analysis component only.
- Gemini does not receive AWS credentials and does not execute AWS changes.
- Remediation authorization must be deterministic and policy-driven.
- A remediation is not considered successful until a subsequent Prowler scan verifies the control.
- The demo Security Group is tagged with `Project=SecNet-CSPM`, `CSPMTest=true`, `CSPMScope=demo`, and `CSPMTarget=true` where applicable.

## First real scenario: public SSH

The intentional public-SSH finding is **opt-in**. No EC2 instance is attached to this Security Group.

To enable the finding for a controlled scan, set this in a local `terraform.tfvars` file:

```hcl
enable_public_ssh_test = true
```

Prowler check:

```
ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
```

Expected lifecycle:

1. Terraform creates the Security Group in the existing default VPC.
2. Prowler detects the real failed control when the public-SSH scenario is enabled.
3. SecNet CSPM normalizes and prioritizes the finding.
4. Gemini explains impact and remediation guidance.
5. The remediation policy validates scope and risk.
6. The authorized remediation changes the Security Group rule.
7. Prowler runs again.
8. The finding is marked resolved only when the control passes.

## Validation and deployment

Run from `cspm-v2/terraform`:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
```

Review the plan. Expected resources: a Security Group and an ingress rule; no EC2 or managed services.

The Terraform data source requires an existing default VPC in the selected AWS region. If the account has no default VPC, stop and decide whether to create a dedicated VPC (no hourly VPC charge, but additional resources) or use an existing VPC.

After the demonstration, remove the demo Security Group through Terraform only after reviewing the destroy plan. Do not use this intentional vulnerable configuration for a production workload.
