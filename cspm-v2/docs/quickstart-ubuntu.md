# Ubuntu 24.04 Quick Start

cd /opt/secnet-cspm/cspm-v2
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

Verify:
aws sts get-caller-identity
python --version
terraform version
prowler --version
prowler --help

Terraform validation:
cd terraform
terraform init
terraform fmt -check
terraform validate
terraform plan

Do NOT run terraform apply until AWS account, scope and cost are confirmed.

Scan:
cd /opt/secnet-cspm/cspm-v2
source .venv/bin/activate
export GEMINI_API_KEY='<GEMINI_API_KEY>'
cspm scan --region ap-southeast-1 --limit 20

Reports are written under reports/<scan-id>/ and raw evidence under data/scans/<scan-id>/.
