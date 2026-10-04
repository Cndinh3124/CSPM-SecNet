# SecNet CSPM + Gemini AI

Gemini is an advisory AI analysis layer on top of Prowler.

Architecture:

AWS
↓
Prowler
↓
CSV / JSON
↓
SecNet CSPM AI
↓
Gemini
↓
Structured Security Analysis
↓
Dashboard

Prowler remains the deterministic security assessment engine.

Gemini:
- explains findings
- analyzes technical cause
- explains security impact
- recommends remediation
- provides validation steps

Gemini does not execute AWS remediation.

## Installation

cd /opt/secnet-cspm-demo

python3 -m venv .venv-ai

source .venv-ai/bin/activate

pip install -r requirements-ai.txt

## Environment

cp .env.example .env

nano .env

set -a
source .env
set +a

## Analyze one Prowler CSV

python scripts/analyze_finding.py \
  --csv /opt/secnet-cspm-demo/scan-results/t1-misconfigured/YOUR_FILE.csv \
  --output-dir /opt/secnet-cspm-demo/data \
  --limit 1

## Analyze latest failures

python scripts/analyze_latest_failures.py \
  --scan-dir /opt/secnet-cspm-demo/scan-results/t1-misconfigured \
  --output-dir /opt/secnet-cspm-demo/data \
  --limit 5

## Start API

uvicorn api.main:app \
  --host 0.0.0.0 \
  --port 8090

## Health check

curl http://127.0.0.1:8090/health

## Security

Never commit .env.

Never send AWS credentials to Gemini.

Gemini output is advisory.

Human approval is required before remediation.
