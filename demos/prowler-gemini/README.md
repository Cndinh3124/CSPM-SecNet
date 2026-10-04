# SecNet CSPM Demonstration

## Objective

Build an isolated AWS environment for demonstrating
Cloud Security Posture Management (CSPM).

## Architecture

- AWS VPC
- Public and private subnets
- EC2 web workload
- MySQL RDS
- S3
- CloudTrail
- Security Groups

## Security Assessment

Prowler will be used to assess the AWS environment against
security and compliance controls.

## Demonstration Flow

1. Deploy baseline infrastructure with Terraform
2. Verify AWS infrastructure
3. Run initial Prowler assessment
4. Introduce controlled security misconfiguration
5. Detect the misconfiguration
6. Generate security alert
7. Perform remediation
8. Re-scan the environment
9. Verify the security posture improvement

## Main Demonstration Case

Security Group SSH exposure:

TCP/22 -> 0.0.0.0/0

The configuration will initially be secure and will be
intentionally changed during the demonstration.
