import argparse

from ai.analyzer import analyze_latest


parser = argparse.ArgumentParser(
    description="Analyze latest Prowler failures"
)

parser.add_argument(
    "--scan-dir",
    required=True,
)

parser.add_argument(
    "--output-dir",
    default="./data",
)

parser.add_argument(
    "--limit",
    type=int,
    default=20,
)


args = parser.parse_args()


output_file, results = analyze_latest(
    args.scan_dir,
    args.output_dir,
    args.limit,
)


print(
    f"Saved: {output_file}"
)

print(
    f"Analyzed: {len(results)}"
)
