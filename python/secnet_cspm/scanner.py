from .securityhub import SecurityHubCollector
from .normalize import normalize
from .risk import enrich_finding
from .config import load_registry


def scan(region="ap-southeast-1"):
    """
    Execute a CSPM scan against AWS Security Hub.

    Every control defined in the policy registry is represented
    in the scan result, including controls with no findings.
    """

    registry = load_registry()

    collector = SecurityHubCollector(region)

    controls = {}
    findings = []

    # ---------------------------------------------------------
    # Initialize every registered control
    # ---------------------------------------------------------

    for control in registry.get("policies", []):
        control_id = control["control_id"]

        controls[control_id] = {
            "control_id": control_id,
            "resource": control.get("resource"),
            "severity": control.get("severity", "MEDIUM"),
            "status": "NO_DATA",
            "passed": 0,
            "failed": 0,
            "unknown": 0,
            "findings": [],
        }

    # ---------------------------------------------------------
    # Collect Security Hub findings
    # ---------------------------------------------------------

    for control in registry.get("policies", []):

        control_id = control["control_id"]

        try:
            raw_findings = collector.findings(control_id)

        except Exception as exc:

            controls[control_id]["status"] = "UNKNOWN"
            controls[control_id]["error"] = str(exc)

            continue

        for raw in raw_findings:

            finding = enrich_finding(
                normalize(raw)
            )

            findings.append(finding)

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

            current = controls[finding_control]

            current["findings"].append(finding)

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
            "benchmark": "CIS AWS Foundations Benchmark",
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