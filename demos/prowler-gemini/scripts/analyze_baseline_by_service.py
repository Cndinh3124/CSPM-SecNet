import csv
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = (
    PROJECT_DIR
    / "scan-results"
    / "baseline"
    / "prowler-output-392024306192-20260927164118.csv"
)

TARGET_SERVICES = {
    "ec2",
    "iam",
    "s3",
    "rds",
    "vpc",
    "cloudtrail",
}


def main():
    if not CSV_FILE.exists():
        print(f"ERROR: CSV file not found:")
        print(f"  {CSV_FILE}")
        return

    with open(
        CSV_FILE,
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = list(
            csv.DictReader(
                file,
                delimiter=";",
            )
        )

    findings = defaultdict(Counter)

    for row in rows:
        service = row.get("SERVICE_NAME", "").strip().lower()
        status = row.get("STATUS", "").strip().upper()

        if service in TARGET_SERVICES:
            findings[service][status] += 1

    print("=" * 70)
    print("SECNET CSPM - BASELINE BY SERVICE")
    print("=" * 70)

    print(f"\nCSV file:")
    print(f"  {CSV_FILE}")

    print(f"\nTotal CSV findings:")
    print(f"  {len(rows)}")

    for service in sorted(TARGET_SERVICES):
        print(f"\n[{service.upper()}]")
        print(f"  PASS    : {findings[service]['PASS']}")
        print(f"  FAIL    : {findings[service]['FAIL']}")
        print(f"  MANUAL  : {findings[service]['MANUAL']}")

    print("\n" + "=" * 70)
    print("BASELINE ANALYSIS COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()
