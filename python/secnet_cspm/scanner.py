import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .securityhub import SecurityHubCollector
from .normalize import normalize
from .risk import enrich_finding
from .config import load_registry


ROOT = Path(__file__).resolve().parents[2]

# Cloud Custodian detection policy mapping.
# Only controls explicitly using Cloud Custodian are mapped here.
CUSTODIAN_POLICIES = {
    "EC2.53": ROOT / "python" / "policies" / "ssh-public.yml",
}


def _find_custodian_executable():
    """
    Locate the Cloud Custodian executable.

    Local development:
        .venv/Scripts/custodian.exe

    Linux/Docker:
        custodian
    """

    executable = shutil.which("custodian")

    if executable:
        return executable

    # Windows fallback when PATH is not refreshed.
    candidates = [
        ROOT / ".venv" / "Scripts" / "custodian.exe",
        ROOT / ".venv" / "Scripts" / "custodian",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError(
        "Cloud Custodian executable was not found. "
        "Install Cloud Custodian and make sure 'custodian' is available in PATH."
    )


def _run_custodian_detection(
    control_id,
    region,
):
    """
    Execute a Cloud Custodian detection policy and return
    the matched AWS resources.

    Detection is read-only. This function does not perform
    any remediation action.
    """

    policy_path = CUSTODIAN_POLICIES.get(control_id)

    if not policy_path:
        raise ValueError(
            f"No Cloud Custodian detection policy configured for {control_id}"
        )

    if not policy_path.exists():
        raise FileNotFoundError(
            f"Cloud Custodian policy not found: {policy_path}"
        )

    custodian = _find_custodian_executable()

    # Use a temporary output directory so every scan gets a
    # fresh result and stale resources.json files cannot be reused.
    output_dir = Path(
        tempfile.mkdtemp(
            prefix=f"secnet-cspm-{control_id.lower()}-"
        )
    )

    try:

        command = [
            custodian,
            "run",
            "-s",
            str(output_dir),
            "--cache-period",
            "0",
            "--region",
            region,
            str(policy_path),
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

        if process.returncode != 0:

            stdout = (process.stdout or "").strip()
            stderr = (process.stderr or "").strip()

            raise RuntimeError(
                "Cloud Custodian detection failed "
                f"for {control_id}. "
                f"exit_code={process.returncode}. "
                f"stdout={stdout[-2000:]}. "
                f"stderr={stderr[-2000:]}"
            )

        # Cloud Custodian creates:
        #
        # output/
        #   policy-name/
        #       resources.json
        #
        resource_files = list(
            output_dir.rglob("resources.json")
        )

        resources = []

        for resource_file in resource_files:

            try:

                data = json.loads(
                    resource_file.read_text(
                        encoding="utf-8"
                    )
                )

            except Exception as exc:

                raise RuntimeError(
                    f"Unable to read Cloud Custodian output "
                    f"{resource_file}: {exc}"
                ) from exc

            if isinstance(data, list):
                resources.extend(data)

        return resources

    finally:

        shutil.rmtree(
            output_dir,
            ignore_errors=True,
        )


def _custodian_finding(
    control,
    resource,
):
    """
    Convert a Cloud Custodian matched resource into
    the normalized CSPM finding format used by the backend.
    """

    control_id = control["control_id"]

    group_id = (
        resource.get("GroupId")
        or resource.get("group_id")
        or resource.get("Arn")
        or resource.get("GroupName")
        or "unknown"
    )

    # Stable ID is important because the backend uses finding_id
    # for deduplication/upsert across repeated scans.
    finding_id = (
        f"cspm:cloud-custodian:"
        f"{control_id}:"
        f"{group_id}"
    )

    matched_permissions = resource.get(
        "c7n:MatchedIpPermissions",
        [],
    )

    # A Cloud Custodian match for this policy means that the
    # Security Group contains public TCP/22 ingress.
    public_exposure = bool(matched_permissions)

    finding = {
        "finding_id": finding_id,
        "control": control_id,
        "title": (
            "Security Group allows public SSH access "
            "from the Internet"
        ),
        "description": (
            "Cloud Custodian detected a Security Group "
            "allowing TCP port 22 from 0.0.0.0/0."
        ),
        "severity": control.get(
            "severity",
            "MEDIUM",
        ),
        "status": "FAILED",
        "record_state": "ACTIVE",
        "workflow_status": "NEW",
        "resource": group_id,
        "resource_type": "AwsEc2SecurityGroup",
        "updated_at": None,
        "age_hours": 0,
        "public_exposure": public_exposure,
        "source": "Cloud Custodian",
        "matched_permissions": matched_permissions,
        "tags": resource.get(
            "Tags",
            [],
        ),
    }

    return enrich_finding(finding)


def _collect_custodian_control(
    control,
    region,
    controls,
    findings,
):
    """
    Run Cloud Custodian detection for one registered control
    and update the control/finding collections.
    """

    control_id = control["control_id"]

    resources = _run_custodian_detection(
        control_id,
        region,
    )

    # No matching resources means the control currently passes.
    if not resources:

        controls[control_id]["passed"] = 1
        controls[control_id]["status"] = "PASSED"

        return

    for resource in resources:

        finding = _custodian_finding(
            control,
            resource,
        )

        findings.append(finding)

        controls[control_id]["findings"].append(
            finding
        )

        controls[control_id]["failed"] += 1


def scan(region="ap-southeast-1"):
    """
    Execute a CSPM scan against AWS.

    Detection source is determined by the Policy Registry.

    Controls whose detection.primary is:
        - Cloud Custodian -> Cloud Custodian detection
        - otherwise        -> AWS Security Hub

    EC2.53 therefore uses Cloud Custodian while the remaining
    registered controls continue to use Security Hub.
    """

    registry = load_registry()

    collector = SecurityHubCollector(region)

    controls = {}
    findings = []

    # ---------------------------------------------------------
    # Initialize every registered control
    # ---------------------------------------------------------

    policies = registry.get(
        "policies",
        [],
    )

    for control in policies:

        control_id = control["control_id"]

        controls[control_id] = {
            "control_id": control_id,
            "resource": control.get(
                "resource"
            ),
            "severity": control.get(
                "severity",
                "MEDIUM",
            ),
            "status": "NO_DATA",
            "passed": 0,
            "failed": 0,
            "unknown": 0,
            "findings": [],
        }

    # ---------------------------------------------------------
    # Collect findings according to Policy Registry
    # ---------------------------------------------------------

    for control in policies:

        control_id = control["control_id"]

        detection = control.get(
            "detection",
            {},
        )

        primary_detection = str(
            detection.get(
                "primary",
                "AWS Security Hub",
            )
        ).strip().lower()

        # -----------------------------------------------------
        # Cloud Custodian detection
        # -----------------------------------------------------

        if primary_detection == "cloud custodian":

            try:

                _collect_custodian_control(
                    control=control,
                    region=region,
                    controls=controls,
                    findings=findings,
                )

            except Exception as exc:

                controls[control_id]["status"] = (
                    "UNKNOWN"
                )

                controls[control_id]["error"] = str(
                    exc
                )

                controls[control_id]["unknown"] += 1

            continue

        # -----------------------------------------------------
        # AWS Security Hub detection
        # -----------------------------------------------------

        try:

            raw_findings = collector.findings(
                control_id
            )

        except Exception as exc:

            controls[control_id]["status"] = (
                "UNKNOWN"
            )

            controls[control_id]["error"] = str(
                exc
            )

            controls[control_id]["unknown"] += 1

            continue

        for raw in raw_findings:

            finding = enrich_finding(
                normalize(raw)
            )

            findings.append(
                finding
            )

            finding_control = finding.get(
                "control",
                control_id,
            )

            # Make sure unexpected control IDs
            # do not break the scan.
            if finding_control not in controls:

                controls[finding_control] = {
                    "control_id": finding_control,
                    "resource": None,
                    "severity": "UNKNOWN",
                    "status": "UNKNOWN",
                    "passed": 0,
                    "failed": 0,
                    "unknown": 0,
                    "findings": [],
                }

            current = controls[
                finding_control
            ]

            current["findings"].append(
                finding
            )

            status = finding.get(
                "status",
                "UNKNOWN",
            )

            if status == "FAILED":

                current["failed"] += 1

            elif status == "PASSED":

                current["passed"] += 1

            else:

                current["unknown"] += 1

    # ---------------------------------------------------------
    # Calculate control status
    # ---------------------------------------------------------

    for control_id, control in controls.items():

        if control["failed"] > 0:

            control["status"] = "FAILED"

        elif control["unknown"] > 0:

            control["status"] = "UNKNOWN"

        elif control["passed"] > 0:

            control["status"] = "PASSED"

        else:

            control["status"] = "NO_DATA"

    # ---------------------------------------------------------
    # Control-level compliance
    #
    # NO_DATA is not considered PASSED.
    # ---------------------------------------------------------

    total_controls = len(
        controls
    )

    passed_controls = sum(
        1
        for control in controls.values()
        if control["status"] == "PASSED"
    )

    failed_controls = sum(
        1
        for control in controls.values()
        if control["status"] == "FAILED"
    )

    unknown_controls = sum(
        1
        for control in controls.values()
        if control["status"] == "UNKNOWN"
    )

    no_data_controls = sum(
        1
        for control in controls.values()
        if control["status"] == "NO_DATA"
    )

    compliance = (
        round(
            (
                passed_controls
                / total_controls
            )
            * 100,
            2,
        )
        if total_controls
        else 0.0
    )

    # ---------------------------------------------------------
    # Result
    # ---------------------------------------------------------

    return {
        "scan": {
            "engine_version": "4.0",
            "provider": "AWS",
            "region": region,
            "benchmark": (
                "CIS AWS Foundations Benchmark"
            ),
        },

        "summary": {
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": failed_controls,
            "unknown_controls": unknown_controls,
            "no_data_controls": no_data_controls,
            "control_compliance_percent": compliance,
            "total_findings": len(findings),
        },

        "controls": list(
            controls.values()
        ),

        "findings": findings,
    }