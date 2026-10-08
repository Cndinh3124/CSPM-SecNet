import argparse
import json
from pathlib import Path

from .pipeline import run_scan


def main():
    parser = argparse.ArgumentParser(prog="cspm")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--region", default="ap-southeast-1")
    scan.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()

    if args.command == "scan":
        result = run_scan(args.region, args.limit)
        print("Scan completed:", result["scan_id"])
        print("Failed findings:", result["total_failed_findings"])
        print("AI analyzed:", result["ai_analyzed"])
        print("Remediation plans:", result["remediation_plans"])
        for key, value in result["reports"].items():
            print(f"{key}: {value}")
