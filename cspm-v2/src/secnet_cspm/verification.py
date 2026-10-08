import json
import os
import subprocess
from pathlib import Path


def verify_public_ssh(region: str, control_id: str, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        os.getenv("PROWLER_COMMAND", "prowler"),
        "aws",
        "--region",
        region,
        "--check",
        control_id,
        "--output-formats",
        "json-ocsf",
        "csv",
        "--output-directory",
        str(output_dir),
        "--no-banner",
        "--ignore-exit-code-3",
    ]
    result = subprocess.run(cmd, text=True, capture_output=True)

    findings = []
    for path in output_dir.glob("*.ocsf.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = data.get("findings") or data.get("data") or data.get("results") or [data]
            if isinstance(data, list):
                findings.extend(data)
        except (OSError, json.JSONDecodeError):
            continue

    failed = [
        item for item in findings
        if isinstance(item, dict)
        and str(item.get("status_code") or item.get("status") or "").upper() in {"FAIL", "FAILED"}
    ]

    return {
        "status": "PASS" if not failed else "FAIL",
        "returncode": result.returncode,
        "failed_findings": len(failed),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
    }
