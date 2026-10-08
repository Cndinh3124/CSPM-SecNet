# Prowler + Gemini CSPM Architecture

## Objective

SecNet CSPM uses Prowler as the security detection engine and Gemini as an analysis/advisory layer.

```
AWS -> Prowler -> Normalize -> Risk -> Gemini -> Policy -> Cloud Custodian -> Re-scan -> Verification
```

## Security boundary

Gemini is NOT an AWS administrator.

Gemini:
- explains findings
- identifies likely root cause from supplied evidence
- recommends remediation
- recommends verification steps
- provides confidence and assumptions

Gemini does NOT:
- receive AWS credentials
- execute AWS APIs
- override remediation policy
- grant remediation permission
- decide production scope

The deterministic policy registry remains authoritative for execution.

## Remediation authority

1. Prowler detects.
2. Python normalizes and scores.
3. Gemini advises.
4. Scope/policy engine authorizes.
5. Cloud Custodian executes only an approved policy.
6. Prowler re-scans.
7. Verification reconciles the finding.

AI recommendation != authorization.

## Example: EC2.53

Prowler detects SSH exposed to 0.0.0.0/0.

Gemini explains the risk and recommends restricting SSH. The policy engine independently checks the control, explicit CSPM test scope, and environment policy before Cloud Custodian can execute.

Verification reruns Prowler. A finding is not considered resolved merely because Cloud Custodian returned exit code 0.

## Operational modes

### Advisory
Prowler -> Gemini -> report only.

### Approval
Prowler -> Gemini -> plan -> human approval -> Cloud Custodian -> verification.

### Controlled auto-remediation
Prowler -> Gemini -> deterministic policy validation -> Cloud Custodian -> verification.

Only explicitly allowlisted controls should use the last mode.
