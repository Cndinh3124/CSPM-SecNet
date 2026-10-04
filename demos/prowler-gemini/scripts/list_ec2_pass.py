import csv
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = (
    PROJECT_DIR
    / "scan-results"
    / "baseline"
    / "prowler-output-392024306192-20260927164118.csv"
)


def main():
    with open(
        CSV_FILE,
        newline="",
        encoding="utf-8-sig",
    ) as file:
        rows = csv.DictReader(
            file,
            delimiter=";",
        )

        print("=" * 100)
        print("SECNET CSPM - EC2 BASELINE PASS CHECKS")
        print("=" * 100)

        count = 0

        for row in rows:
            service = row.get("SERVICE_NAME", "").strip().lower()
            status = row.get("STATUS", "").strip().upper()

            if service == "ec2" and status == "PASS":
                check_id = row.get("CHECK_ID", "")
                title = row.get("CHECK_TITLE", "")
                resource = row.get("RESOURCE_UID", "")

                print(f"\nCHECK_ID : {check_id}")
                print(f"TITLE    : {title}")
                print(f"RESOURCE : {resource}")

                count += 1

        print("\n" + "=" * 100)
        print(f"TOTAL EC2 PASS CHECKS: {count}")
        print("=" * 100)


if __name__ == "__main__":
    main()
