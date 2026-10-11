import csv
import os
import subprocess
import uuid
from pathlib import Path


def _read_csv_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        sample = stream.read(8192)
        stream.seek(0)

        delimiter = ";" if sample.count(";") > sample.count(",") else ","
        reader = csv.DictReader(stream, delimiter=delimiter)

        if not reader.fieldnames:
            return []

        return [
            {
                str(key).strip().upper(): str(value or "").strip()
                for key, value in row.items()
                if key is not None
            }
            for row in reader
        ]


def verify_public_ssh(
    region: str,
    control_id: str,
    output_dir: Path,
    resource_id: str,
) -> dict:
    """
    Verify one resource using fresh Prowler CSV output.

    PASS requires an explicit PASS result for the requested resource.
    FAIL requires an explicit FAIL result for the requested resource.
    Missing, malformed, or ambiguous evidence returns INCONCLUSIVE.
    """
    if not region or not control_id or not resource_id:
        return {
            "status": "INCONCLUSIVE",
            "reason": "region, control_id, and resource_id are required.",
            "failed_findings": 0,
        }

    run_dir = output_dir / f"verification-{uuid.uuid4().hex}"
    run_dir.mkdir(parents=True, exist_ok=False)

    cmd = [
        os.getenv("PROWLER_COMMAND", "prowler"),
        "aws",
        "--region", region,
        "--check", control_id,
        "--output-formats", "csv",
        "--output-directory", str(run_dir),
        "--no-banner",
        "--ignore-exit-code-3",
    ]

    try:
        result = subprocess.run(cmd, text=True, capture_output=True)
    except OSError as exc:
        return {
            "status": "INCONCLUSIVE",
            "reason": f"Unable to start Prowler: {exc}",
            "failed_findings": 0,
            "command": cmd,
        }

    base = {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
        "resource_id": resource_id,
        "control_id": control_id,
        "region": region,
    }

    if result.returncode != 0:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "reason": "Prowler exited with a non-zero status.",
            "failed_findings": 0,
        }

    rows = []
    parse_errors = []

    for path in run_dir.rglob("*.csv"):
        try:
            rows.extend(_read_csv_rows(path))
        except (OSError, csv.Error, UnicodeError) as exc:
            parse_errors.append(f"{path.name}: {exc}")

    if not rows:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "reason": "No readable CSV findings were produced.",
            "failed_findings": 0,
            "parse_errors": parse_errors,
        }

    matching = []

    for row in rows:
        check = row.get("CHECKID", "")
        status = row.get("STATUS", "").upper()
        resource = row.get("RESOURCEID", "")
        name = row.get("RESOURCENAME", "")

        if check != control_id:
            continue

        # Match the resource ID exactly or as a terminal path component.
        resource_matches = (
            resource == resource_id
            or resource.endswith(f"/{resource_id}")
        )
        name_matches = name == resource_id

        if not (resource_matches or name_matches):
            continue

        if status in {"FAIL", "PASS"}:
            matching.append(status)

    if not matching:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "reason": (
                "No explicit PASS/FAIL result matched both the control "
                "and the requested resource."
            ),
            "failed_findings": 0,
            "parse_errors": parse_errors,
        }

    if "FAIL" in matching:
        status = "FAIL"
        reason = "The target resource still has a failing finding."
    elif all(value == "PASS" for value in matching):
        status = "PASS"
        reason = "The target resource has explicit PASS results and no FAIL result."
    else:
        status = "INCONCLUSIVE"
        reason = "Conflicting or ambiguous results exist for the target resource."

    return {
        **base,
        "status": status,
        "reason": reason,
        "failed_findings": matching.count("FAIL"),
        "matched_results": matching,
        "parse_errors": parse_errors,
    }
