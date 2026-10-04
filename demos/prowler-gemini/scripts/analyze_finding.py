import argparse
import json
from ai.analyzer import analyze_csv

parser = argparse.ArgumentParser(
    description="Analyze Prowler findings with Gemini"
)

parser.add_argument("--csv", required=True)
parser.add_argument("--output-dir", default="./data")
parser.add_argument("--limit", type=int, default=1)
parser.add_argument("--check-id")
parser.add_argument("--resource-id")
parser.add_argument(
    "--status",
    choices=["PASS", "FAIL", "MANUAL"],
    default="FAIL",
    help="Prowler finding status to analyze (default: FAIL)",
)

args = parser.parse_args()

output_file, results = analyze_csv(
    args.csv,
    args.output_dir,
    args.limit,
    args.check_id,
    args.resource_id,
    status=args.status,
)

print(f"Saved: {output_file}")

if results:
    print(json.dumps(results[0], ensure_ascii=False, indent=2))
