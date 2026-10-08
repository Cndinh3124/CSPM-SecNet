# SecNet CSPM Automation v1

Production-style CSPM demonstration pipeline:

```
Terraform
  -> AWS demonstration infrastructure
  -> Prowler assessment
  -> Finding normalization
  -> Risk prioritization
  -> Gemini security analysis
  -> CSV / XLSX / HTML / JSON reports
  -> Controlled remediation
  -> Prowler re-scan
  -> Verification
```

## Design principles

- AWS resources are real; findings are not mocked.
- Terraform is the infrastructure source of truth.
- Prowler is the authoritative detection layer.
- Gemini is an advisory security-analysis component only.
- Gemini receives finding context but does not receive AWS credentials and does not execute AWS changes.
- Remediation authorization must be deterministic and policy-driven.
- A remediation is not considered successful until a subsequent Prowler scan verifies the control.
- Demonstration resources are tagged with `Project=SecNet-CSPM`, `CSPMTest=true`, `CSPMScope=demo`, and `CSPMTarget=true` where applicable.
- Intentional vulnerabilities are opt-in.

## First real scenario: public SSH

The first vertical slice intentionally creates:

```
Security Group
  TCP/22
  0.0.0.0/0
```

Prowler check:

```
ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
```

Expected lifecycle:

1. Terraform creates the controlled AWS resources.
2. Prowler detects the real failed control.
3. SecNet CSPM normalizes and prioritizes the finding.
4. Gemini explains root cause, impact and remediation guidance.
5. The remediation policy validates scope and risk.
6. The remediation executor changes the AWS configuration.
7. Prowler runs again.
8. The finding is marked resolved only when the control passes.

## Safety boundary

This is a real AWS environment used for a controlled security demonstration. The intentional vulnerable state must remain limited to resources tagged for the CSPM demonstration.

Before `terraform apply`:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file=terraform.tfvars
```

Review the plan before applying.

After the demonstration:

```bash
terraform destroy -var-file=terraform.tfvars
```

Do not use the vulnerable configuration for a production workload.
