import argparse, json
from .scanner import scan
from .planner import build_plan
from .finding_store import save_json
from .report import save_report

def main():
    p = argparse.ArgumentParser(prog="secnet-cspm")
    p.add_argument("command", choices=["scan", "risk", "plan", "report"])
    p.add_argument("--region", default="ap-southeast-1")
    args = p.parse_args()

    data = scan(args.region)
    if args.command in ("scan", "risk", "report"):
        path = save_report(data)
        print(f"Report: {path}")
        print(json.dumps(data["summary"], ensure_ascii=False, indent=2))
    elif args.command == "plan":
        plan = build_plan(data, args.region)
        path = save_json("cspm-remediation-plan.json", plan)
        print(f"Plan: {path}")
        print(json.dumps(plan, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
