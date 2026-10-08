# Runbook: Prowler + Gemini CSPM

## Prerequisites

- Python 3.13+
- AWS CLI configured with least-privilege permissions
- Prowler installed
- Cloud Custodian installed
- Gemini API key
- Terraform

Never commit Gemini API keys or AWS credentials.

## Local setup

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH=".\python"
$env:GEMINI_API_KEY="<GEMINI_API_KEY>"
$env:GEMINI_MODEL="gemini-2.5-flash"
```

Linux/macOS:

```bash
source .venv/bin/activate
export PYTHONPATH=./python
export GEMINI_API_KEY="<GEMINI_API_KEY>"
export GEMINI_MODEL="gemini-2.5-flash"
```

## Step 1 — Provision the lab

Use Terraform to create the intentionally vulnerable Security Group. Keep the resource explicitly scoped for testing, for example with:

```
Project=CSPM
CSPMTest=true
```

Do not run auto-remediation against production.

## Step 2 — Scan with Prowler

```bash
python -m secnet_cspm scan --region ap-southeast-1
```

Expected:
- Prowler runs the configured EC2.53 check.
- A public TCP/22 rule becomes a FAILED finding.
- The finding is normalized and risk-scored.

## Step 3 — Analyze with Gemini

```bash
python -m secnet_cspm analyze --region ap-southeast-1 --limit 20
```

Output:
`tests/outputs/gemini-analysis.json`

The analysis contains root cause, impact, recommendation, auto-remediation recommendation, verification steps, confidence, and assumptions.

If Gemini fails, scanning remains valid. The finding must remain open and require manual analysis.

## Step 4 — Build the deterministic remediation plan

```bash
python -m secnet_cspm plan --region ap-southeast-1
```

Review `tests/outputs/cspm-remediation-plan.json`.

Gemini cannot increase the allowed scope.

## Step 5 — Execute approved remediation

```bash
python -m secnet_cspm remediate --region ap-southeast-1
```

Cloud Custodian is the executor. Gemini never calls AWS APIs directly.

## Step 6 — Verify

```bash
python -m secnet_cspm verify --region ap-southeast-1
```

Verification reruns the scanner and checks whether the same control/resource is still FAILED.

## Failure handling

- Gemini failure: keep finding open; continue without AI.
- Custodian failure: keep finding open; preserve execution logs.
- Verification failure: remediation is unsuccessful; investigate before retry.
- Unexpected resource scope: remediation must be skipped.

## Production hardening

- Use IAM roles instead of long-lived AWS keys.
- Store Gemini credentials in a secret manager.
- Use SQS for asynchronous scan/remediation jobs.
- Add CloudWatch metrics and alarms.
- Require approval for disruptive controls.
- Keep immutable remediation audit logs.
- Pin and regularly update dependencies after testing.
