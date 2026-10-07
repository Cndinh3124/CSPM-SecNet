#!/bin/bash

set -euo pipefail

PROJECT_DIR="/opt/secnet-cspm-demo"
REGION="ap-southeast-1"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="$PROJECT_DIR/scan-results/baseline-$TIMESTAMP"
DASHBOARD_OUTPUT_DIR="$PROJECT_DIR/output"

echo "=========================================="
echo "        SecNet CSPM - Baseline Scan"
echo "=========================================="
echo
echo "Region : $REGION"
echo "Output : $OUTPUT_DIR"
echo

mkdir -p "$OUTPUT_DIR"
mkdir -p "$DASHBOARD_OUTPUT_DIR"

echo "[1/4] Running Prowler..."

prowler aws \
    --region "$REGION" \
    --output-formats json-ocsf csv html \
    --output-directory "$OUTPUT_DIR"

echo
echo "[2/4] Locating scan result..."

CSV_FILE=$(find "$OUTPUT_DIR" -maxdepth 1 -name "*.csv" -type f | head -n 1)

if [ -z "$CSV_FILE" ]; then
    echo "ERROR: CSV result not found."
    exit 1
fi

echo "CSV: $CSV_FILE"

echo
echo "[3/4] Updating Prowler Dashboard data..."

cp "$CSV_FILE" "$DASHBOARD_OUTPUT_DIR/"

echo "Dashboard data updated:"
echo "  $DASHBOARD_OUTPUT_DIR/$(basename "$CSV_FILE")"

echo
echo "[4/4] Generating summary..."

python3 "$PROJECT_DIR/scripts/summarize_scan.py" "$CSV_FILE"

echo
echo "=========================================="
echo "Baseline scan completed successfully."
echo "=========================================="
echo
echo "Scan results:"
echo "  $OUTPUT_DIR"
echo
echo "Dashboard data:"
echo "  $DASHBOARD_OUTPUT_DIR/$(basename "$CSV_FILE")"
echo "=========================================="
