import argparse
import json

from .scanner import scan
from .planner import build_plan
from .finding_store import save_json
from .report import save_report
from cspm_engine.remediation_executor import execute_plan
from .ai_analyzer import run_ai_analysis
from .verification import verify_remediation
from .finding_store import load_json


def main():
    p = argparse.ArgumentParser(prog="secnet-cspm")
    p.add_argument(
        "command",
        choices=["scan", "risk", "plan", "report", "analyze", "remediate", "verify"],
    )
    p.add_argument("--region", default="ap-southeast-1")
    p.add_argument("--limit", type=int, default=20)
    args = p.parse_args()

    data = scan(args.region)

    if args.command == "analyze":
        report = run_ai_analysis(args.region, args.limit)
        print(json.dumps(report, ensure_ascii=False, indent=2))

    elif args.command in ("scan", "risk", "report"):
        path = save_report(data)
        print(f"Report: {path}")
        print(json.dumps(data["summary"], ensure_ascii=False, indent=2))

    elif args.command == "plan":
        plan = build_plan(data, args.region)
        path = save_json("cspm-remediation-plan.json", plan)
        print(f"Plan: {path}")
        print(json.dumps(plan, ensure_ascii=False, indent=2))

    elif args.command == "remediate":
        results = execute_plan()
        print(json.dumps(results, ensure_ascii=False, indent=2))

    elif args.command == "verify":
        report = load_json("tests/outputs/cspm-execution-log.json")
        verification = verify_remediation(report.get("results", []), args.region)
        print(json.dumps(verification, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
