import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

PROWLER_CHECKS = {
    "EC2.53": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "S3.1": "s3_bucket_level_public_access_block",
}


def _find_prowler_executable():
    executable = shutil.which("prowler")

    if executable:
        return executable

    candidates = [
        Path("/root/.local/bin/prowler"),
        ROOT / ".venv" / "bin" / "prowler",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError(
        "Prowler executable was not found."
    )


def _run_prowler_check(control_id, region):
    check_id = PROWLER_CHECKS.get(control_id)

    if not check_id:
        raise ValueError(
            f"No Prowler check configured for {control_id}"
        )

    prowler = _find_prowler_executable()

    output_dir = Path(
        tempfile.mkdtemp(
            prefix=f"secnet-cspm-prowler-{control_id.lower()}-"
        )
    )

    try:
        command = [
            prowler,
            "aws",
            "--check",
            check_id,
            "--region",
            region,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(output_dir),
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )

        json_files = list(output_dir.rglob("*.ocsf.json"))

        if not json_files:
            raise RuntimeError(
                f"Prowler did not produce an OCSF JSON file "
                f"for {control_id}"
            )

        findings = []

        for json_file in json_files:
            data = json.loads(
                json_file.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(data, list):
                findings.extend(data)

        return findings

    finally:
        shutil.rmtree(
            output_dir,
            ignore_errors=True,
        )

def normalize_prowler_finding(control, finding):
    info = finding.get("finding_info", {})
    analytic = info.get("analytic", {})

    resources = finding.get("resources") or [{}]
    resource = resources[0]

    metadata = (
        resource.get("data", {})
        .get("metadata", {})
    )

    status_code = str(
        finding.get("status_code", "UNKNOWN")
    ).upper()

    status = {
        "PASS": "PASSED",
        "FAIL": "FAILED",
    }.get(status_code, "UNKNOWN")

    severity = str(
        finding.get("severity", "MEDIUM")
    ).upper()

    resource_id = (
        metadata.get("id")
        or resource.get("name")
        or resource.get("uid")
        or "unknown"
    )

    finding_uid = (
        info.get("uid")
        or analytic.get("uid")
        or f"{control['control_id']}:{resource_id}"
    )

    title = (
        info.get("title")
        or analytic.get("name")
        or ""
    )

    description = (
        info.get("desc")
        or finding.get("status_detail")
        or ""
    )

    public_exposure = any(
        keyword in (
            title.lower()
            + " "
            + description.lower()
        )
        for keyword in (
            "public",
            "internet",
            "0.0.0.0/0",
            "::/0",
        )
    )

    updated_at = (
        info.get("created_time_dt")
        or finding.get("time_dt")
    )

    return {
        "finding_id": (
            f"cspm:prowler:"
            f"{control['control_id']}:"
            f"{resource_id}:"
            f"{finding_uid}"
        ),
        "control": control["control_id"],
        "title": title,
        "description": description,
        "severity": severity,
        "status": status,
        "record_state": "ACTIVE",
        "workflow_status": "NEW",
        "resource": resource_id,
        "resource_type": resource.get(
            "type",
            "UNKNOWN",
        ),
        "updated_at": updated_at,
        "age_hours": 0,
        "public_exposure": public_exposure,
        "source": "Prowler",
        "prowler_check": analytic.get(
            "uid",
            "",
        ),
        "prowler_finding_uid": finding_uid,
        "tags": metadata.get(
            "tags",
            [],
        ),
    }
