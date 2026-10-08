import argparse
import json
from pathlib import Path

from .pipeline import run_scan
from .remediation.executor import execute


def main():
    parser = argparse.ArgumentParser(prog="cspm")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--region", default="ap-southeast-1")
    scan.add_argument("--limit", type=int, default=20)

    remediate = subparsers.add_parser("remediate")
    remediate.add_argument("--plan", required=True)
    remediate.add_argument("--approve", action="store_true")
    remediate.add_argument(
        "--execute",
        action="store_true",
        help="Perform AWS mutation. Default is dry-run.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        result = run_scan(args.region, args.limit)
        print("Scan completed:", result["scan_id"])
        print("Failed findings:", result["total_failed_findings"])
        print("AI analyzed:", result["ai_analyzed"])
        print("Remediation plans:", result["remediation_plans"])
        for key, value in result["reports"].items():
            print(f"{key}: {value}")
        return

    if args.command == "remediate":
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        result = execute(
            plan,
            approve=args.approve,
            dry_run=not args.execute,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
