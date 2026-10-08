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
    ]
    result = subprocess.run(cmd, text=True, capture_output=True)
    return {
        "status": "PASS" if result.returncode == 0 else "VERIFY_FAILED",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
    }
