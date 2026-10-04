import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = (
    PROJECT_DIR
    / "scan-results"
    / "baseline"
    / "prowler-output-392024306192-20260927164118.csv"
)

with open(CSV_FILE, newline="", encoding="utf-8-sig") as file:
    rows = csv.DictReader(file, delimiter=";")

    services = sorted({
        row["SERVICE_NAME"]
        for row in rows
        if row["SERVICE_NAME"]
    })

print("=" * 60)
print("PROWLER SERVICE NAME")
print("=" * 60)

for service in services:
    print(service)
