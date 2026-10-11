import argparse
import json
from pathlib import Path

from .pipeline import run_scan
from .remediation.executor import execute


def main():
    parser = argparse.ArgumentParser(prog="cspm")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    scan = subparsers.add_parser("scan")

    scan.add_argument(
        "--region",
        default="ap-southeast-1",
        help="AWS region to scan.",
    )

    scan.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of findings to analyze with Gemini.",
    )

    scan.add_argument(
        "--check",
        help="Run a targeted Prowler check instead of a full scan.",
    )

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------
    remediate = subparsers.add_parser("remediate")

    remediate.add_argument(
        "--plan",
        required=True,
        help="Path to remediation plan JSON.",
    )
    remediate.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index when the JSON file contains a list of plans.",
    )
    remediate.add_argument(
        "--approve",
        action="store_true",
        help="Approve a remediation plan that requires approval.",
    )

    remediate.add_argument(
        "--execute",
        action="store_true",
        help="Perform AWS mutation. Default is dry-run.",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Scan command
    # ------------------------------------------------------------------
    if args.command == "scan":
        result = run_scan(
            args.region,
            args.limit,
            args.check,
        )

        print("Scan completed:", result["scan_id"])
        print("Failed findings:", result["total_failed_findings"])
        print("AI analyzed:", result["ai_analyzed"])
        print("Remediation plans:", result["remediation_plans"])

        for key, value in result["reports"].items():
            print(f"{key}: {value}")

        return

    # ------------------------------------------------------------------
    # Remediation command
    # ------------------------------------------------------------------

    if args.command == "remediate":
        try:
            data = json.loads(
                Path(args.plan).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"Cannot read plan JSON: {exc}")

        if isinstance(data, dict):
            plan = data
        elif isinstance(data, list):
            if not data:
                parser.error("The plan file contains an empty list.")
            if not all(isinstance(item, dict) for item in data):
                parser.error("Every item in the plan list must be a JSON object.")
            if args.index < 0 or args.index >= len(data):
                parser.error(
                    f"Plan index {args.index} is out of range; "
                    f"available indexes: 0-{len(data) - 1}."
                )
            plan = data[args.index]
            print(f"Selected plan index: {args.index} of {len(data)}")
        else:
            parser.error("The plan JSON must be an object or a list of objects.")

        result = execute(
            plan,
            approve=args.approve,
            dry_run=not args.execute,
        )

        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
