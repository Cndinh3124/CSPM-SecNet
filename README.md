# SecNet CSPM v4

SecNet CSPM is an AWS-focused Cloud Security Posture Management platform for continuous posture assessment, CIS compliance monitoring, risk prioritization, controlled remediation, alerting and reporting.

## Architecture

1. **Collection** — AWS Config + AWS APIs
2. **Assessment** — AWS Security Hub/CIS + SecNet policy registry
3. **Risk** — severity + resource exposure + scope + finding age
4. **Alerting** — EventBridge + SNS + optional Lambda formatter
5. **Remediation** — explicit-scope Cloud Custodian policies
6. **Verification** — re-scan and state reconciliation
7. **Reporting** — JSON evidence + Streamlit dashboard

The project deliberately keeps Dashboard read-only. AWS changes are made through Terraform or approved Cloud Custodian policies.

## Current lab scope

- AWS region: `ap-southeast-1`
- CIS AWS Foundations Benchmark
- EC2.2
- EC2.6
- EC2.53
- S3.1
- S3.5
- S3.22
- S3.23
- CloudTrail.2

The original solution proposal specifies a five-layer CSPM architecture using AWS Config/AWS API, Security Hub/Cloud Custodian, SNS/EventBridge, Lambda, and dashboard reporting, with Terraform as Infrastructure as Code. This implementation follows that architecture while keeping Microsoft Defender for Cloud as an optional comparison rather than a required dependency.

## Commands

```powershell
cd D:\CSPM-Project
.\.venv\Scripts\Activate.ps1

$env:PYTHONPATH=".\python"

python -m secnet_cspm scan
python -m secnet_cspm risk
python -m secnet_cspm plan
python -m secnet_cspm report
```

## Safety model

- Default remediation action is `SKIP`.
- Production resources are denied unless explicitly changed in policy.
- Only resources with an approved scope tag can be automatically remediated.
- The Dashboard does not mutate AWS.
- Never commit AWS credentials, access-key CSV files, Terraform state, or generated CloudTrail logs.

## Project owner

**Nguyễn Công Định**  
SecNet CSPM  
CSPM Developer / Cloud Security  
0962633364  
dinhlabs.tech@gmail.com

## Docker Compose demo (local)

The Compose stack starts PostgreSQL, the FastAPI API, the worker, and the existing React dashboard. It does not provision or modify AWS infrastructure.

1. Copy the example environment file and replace the local database password with a long random value:

   ```bash
   cp .env.example .env
   ```

2. Ensure AWS CLI credentials/profile are configured on the host. Compose mounts `${HOME}/.aws` read-only into the API and worker containers.
3. Validate the Compose configuration before starting services:

   ```bash
   docker compose config --quiet
   docker compose build
   docker compose up -d
   docker compose ps
   ```

4. Open the dashboard at `http://localhost:3000`, API health at `http://localhost:8000/health`, and API docs at `http://localhost:8000/docs`.

Stop the stack with `docker compose down`. This keeps the named PostgreSQL volume. To remove demo database data too, use `docker compose down -v` only when you intentionally want to delete it.

**Security note:** This is a local demo configuration, not production hardening. Do not expose ports 3000/8000 to the Internet. The mounted AWS credentials are read-only at the filesystem level, not permission-restricted at the AWS API level; use a dedicated least-privilege profile. The worker's remediation path must be reviewed separately before enabling AWS mutation.

