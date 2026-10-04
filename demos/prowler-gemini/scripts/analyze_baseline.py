import csv
from collections import Counter
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = (
    PROJECT_DIR
    / "scan-results"
    / "baseline"
    / "prowler-output-392024306192-20260927164118.csv"
)


def main():
    with open(CSV_FILE, newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file, delimiter=";"))

    print("=" * 60)
    print("SECNET CSPM - PROWLER BASELINE")
    print("=" * 60)

    print(f"Total findings: {len(rows)}")

    status_count = Counter(row.get("STATUS", "") for row in rows)

    print("\nStatus:")
    for status, count in status_count.items():
        print(f"  {status}: {count}")

    print("\nFAIL findings:")

    for row in rows:
        if row.get("STATUS") == "FAIL":
            print(
                f"- {row.get('CHECK_ID')} | "
                f"{row.get('CHECK_TITLE')} | "
                f"{row.get('SEVERITY')}"
            )


if __name__ == "__main__":
    main()
