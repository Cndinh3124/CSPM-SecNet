# SecNet CSPM – Implementation Roadmap

## Baseline completed

- AWS Config data collection
- AWS Security Hub + CIS assessment
- Policy Registry
- Risk scoring
- Scope validation
- Remediation planning
- Cloud Custodian policy examples
- EventBridge -> Lambda -> SNS alert path
- JSON evidence/reporting
- Streamlit dashboard
- Terraform Infrastructure as Code

## Next hardening

1. Add IAM/S3/RDS/EBS controls to the registry as implementation permits.
2. Add scheduled scans with EventBridge Scheduler or CI/CD.
3. Persist findings/history in DynamoDB or S3 if multi-user retention is required.
4. Add approval workflow for high-risk remediation.
5. Add CloudTrail audit trail for every remediation execution.
6. Add multi-account AWS Organizations aggregation.
7. Add dashboard filters for severity, account, region and resource type.

The student lab can be considered functionally complete when the closed loop is demonstrated:
**misconfiguration -> detection -> risk -> alert -> scoped remediation -> verification -> dashboard evidence**.
