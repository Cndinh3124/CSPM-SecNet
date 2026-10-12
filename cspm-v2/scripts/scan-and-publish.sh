#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

PROJECT_DIR="/opt/CSPM-SecNet/cspm-v2"
PROWLER_BIN="/root/.local/bin/prowler"
PYTHON_BIN="/root/.local/share/pipx/venvs/prowler/bin/python"
REGION="ap-southeast-1"

SCAN_ROOT="$PROJECT_DIR/data/scans"
OVERVIEW_DIR="$PROJECT_DIR/dashboard-data/overview"
ARCHIVE_DIR="$PROJECT_DIR/dashboard-data/archive/overview"
LOG_DIR="$PROJECT_DIR/logs"
LOCK_FILE="$PROJECT_DIR/data/.scan-and-publish.lock"

mkdir -p "$SCAN_ROOT" "$OVERVIEW_DIR" "$ARCHIVE_DIR" "$LOG_DIR"

# Prevent concurrent scans from publishing over one another.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "ERROR: Another scan-and-publish process is running."
    exit 1
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
SCAN_DIR="$SCAN_ROOT/scan-$RUN_ID"
PROWLER_DIR="$SCAN_DIR/prowler"
RUN_LOG="$LOG_DIR/scan-$RUN_ID.log"

mkdir -p "$PROWLER_DIR"
exec > >(tee -a "$RUN_LOG") 2>&1

echo "[$(date -Is)] Starting Prowler scan"
echo "Scan directory: $PROWLER_DIR"
echo "Region: $REGION"

# Check required binaries and AWS identity before starting.
test -x "$PROWLER_BIN" || {
    echo "ERROR: Prowler executable not found: $PROWLER_BIN"
    exit 1
}

test -x "$PYTHON_BIN" || {
    echo "ERROR: Prowler Python environment not found: $PYTHON_BIN"
    exit 1
}

if ! aws sts get-caller-identity; then
    echo "ERROR: AWS identity check failed; scan not started."
    exit 1
fi

# Run a read-only security assessment. Do not enable remediation.
set +e
"$PROWLER_BIN" aws \
    --region "$REGION" \
    --output-formats csv json-ocsf html \
    --output-directory "$PROWLER_DIR" \
    --log-file "$PROWLER_DIR/prowler.log" \
    --no-banner \
    --no-color \
    --ignore-exit-code-3
PROWLER_RC=$?
set -e

echo "Prowler exit code: $PROWLER_RC"

if [ "$PROWLER_RC" -ne 0 ]; then
    echo "ERROR: Prowler returned non-zero; Dashboard data unchanged."
    exit "$PROWLER_RC"
fi

# Select the main findings CSV, not compliance-specific CSV files.
shopt -s nullglob
CSV_FILES=( "$PROWLER_DIR"/prowler-output-*.csv )
shopt -u nullglob

if [ "${#CSV_FILES[@]}" -ne 1 ]; then
    echo "ERROR: Expected exactly one primary prowler-output-*.csv."
    echo "Found: ${#CSV_FILES[@]}"
    printf '  %s\n' "${CSV_FILES[@]}"
    echo "Dashboard data unchanged."
    exit 1
fi

SOURCE_CSV="${CSV_FILES[0]}"

# Validate delimiter, required columns, row count, and status values.
if ! "$PYTHON_BIN" - "$SOURCE_CSV" <<'PY'
import csv
import sys
from pathlib import Path

path = Path(sys.argv[1])

try:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        headers = set(reader.fieldnames or [])

        required = {"CHECK_ID", "STATUS", "PROVIDER"}
        missing = required - headers
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        rows = list(reader)
        if not rows:
            raise ValueError("CSV has no findings/check rows")

        invalid = [
            i for i, row in enumerate(rows, start=2)
            if not (row.get("CHECK_ID") or "").strip()
            or not (row.get("STATUS") or "").strip()
        ]
        if invalid:
            raise ValueError(
                f"Rows missing CHECK_ID/STATUS (first rows): {invalid[:10]}"
            )

        counts = {}
        for row in rows:
            status = row["STATUS"].strip().upper()
            counts[status] = counts.get(status, 0) + 1

        print(f"CSV validation: PASS")
        print(f"Rows: {len(rows)}")
        print(f"Columns: {len(headers)}")
        print(f"Statuses: {counts}")
except Exception as exc:
    print(f"CSV validation: FAIL: {exc}", file=sys.stderr)
    sys.exit(1)
PY
then
    echo "ERROR: CSV validation failed; Dashboard data unchanged."
    exit 1
fi

# Stage a complete copy on the same filesystem for atomic replacement.
TEMP_CSV="$OVERVIEW_DIR/.latest.csv.tmp"
trap 'rm -f "$TEMP_CSV"' EXIT

install -m 0640 "$SOURCE_CSV" "$TEMP_CSV"

# Confirm the staged copy is readable and has the same byte size.
if [ ! -s "$TEMP_CSV" ] || [ "$(stat -c %s "$TEMP_CSV")" -ne "$(stat -c %s "$SOURCE_CSV")" ]; then
    echo "ERROR: Staged CSV verification failed; Dashboard data unchanged."
    exit 1
fi

# Archive older CSVs from the Overview input directory.
# Keep the published filename stable so the Dashboard can detect changes.
for old_csv in "$OVERVIEW_DIR"/*.csv; do
    [ -e "$old_csv" ] || continue
    [ "$(basename "$old_csv")" = "latest.csv" ] && continue

    archive_name="$(basename "$old_csv").previous-$RUN_ID"
    echo "Archiving previous Overview CSV: $old_csv"
    mv -- "$old_csv" "$ARCHIVE_DIR/$archive_name"
done

# Atomic replacement of the stable Dashboard input file.
mv -f -- "$TEMP_CSV" "$OVERVIEW_DIR/latest.csv"
trap - EXIT

echo "Published: $OVERVIEW_DIR/latest.csv"
echo "Source preserved: $SOURCE_CSV"
echo "Run log: $RUN_LOG"

echo "Restarting Prowler Dashboard..."
systemctl restart prowler-dashboard.service

echo "Waiting for Dashboard HTTP endpoint..."
for i in $(seq 1 15); do
    if curl --max-time 2 -fsS \
        -o /dev/null http://127.0.0.1:11666/; then
        echo "Dashboard is healthy: HTTP 200"
        echo "[$(date -Is)] Scan and publish completed successfully"
        exit 0
    fi
    sleep 2
done

echo "ERROR: Dashboard did not become healthy within 30 seconds."
systemctl status prowler-dashboard.service --no-pager -l
exit 1
