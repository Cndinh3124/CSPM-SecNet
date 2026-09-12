import json
from datetime import datetime, timezone
from pathlib import Path

from .scope_validator import validate_resource


PROJECT_ROOT = Path(__file__).resolve().parents[2]

REGISTRY_FILE = (
    PROJECT_ROOT
    / "docs"
    / "cspm-policy-registry.json"
)

SCAN_DIR = (
    PROJECT_ROOT
    / "tests"
    / "outputs"
)


def load_registry():
    with open(
        REGISTRY_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def get_latest_scan():

    reports = list(
        SCAN_DIR.glob("cspm-scan-*.json")
    )

    if not reports:
        raise FileNotFoundError(
            "Không tìm thấy CSPM scan report."
        )

    return max(
        reports,
        key=lambda file: file.stat().st_mtime
    )


def load_scan():

    scan_file = get_latest_scan()

    with open(
        scan_file,
        "r",
        encoding="utf-8"
    ) as file:
        scan = json.load(file)

    return scan, scan_file


def create_plan():

    registry = load_registry()
    scan, scan_file = load_scan()

    policy_map = {
        policy["control_id"]: policy
        for policy in registry.get("policies", [])
    }

    plan = []

    # =============================================================
    # ENGINE V3.1 SCHEMA
    #
    # scan
    # summary
    # controls[]
    #
    # controls[].failed[]
    # controls[].stale[]
    # controls[].passed[]
    # =============================================================

    for control in scan.get("controls", []):

        control_id = control.get(
            "control_id"
        )

        control_status = control.get(
            "status"
        )

        # ---------------------------------------------------------
        # ONLY PROCESS FAILED CONTROLS
        # ---------------------------------------------------------

        if control_status != "FAILED":
            continue

        policy = policy_map.get(
            control_id
        )

        if not policy:

            plan.append({
                "control_id": control_id,
                "resource_id": None,
                "resource_type": None,
                "remediation_type": None,
                "severity": control.get(
                    "severity",
                    "UNKNOWN"
                ),
                "action": "SKIP",
                "scope": {},
                "reason": (
                    "Policy not found in "
                    "CSPM policy registry"
                )
            })

            continue

        remediation = policy.get(
            "remediation",
            {}
        )

        remediation_status = remediation.get(
            "status",
            "not_configured"
        )

        remediation_type = remediation.get(
            "type"
        )

        severity = policy.get(
            "severity",
            control.get(
                "severity",
                "UNKNOWN"
            )
        )

        description = policy.get(
            "description",
            ""
        )

        # ---------------------------------------------------------
        # REMEDIATION NOT IMPLEMENTED
        # ---------------------------------------------------------

        if remediation_status != "implemented":

            plan.append({
                "control_id": control_id,
                "resource_id": None,
                "resource_type": None,
                "remediation_type": remediation_type,
                "severity": severity,
                "description": description,
                "action": "SKIP",
                "scope": {},
                "reason": (
                    "Remediation is not implemented "
                    "in CSPM policy registry"
                )
            })

            continue

        # ---------------------------------------------------------
        # SCOPE
        # ---------------------------------------------------------

        scope = remediation.get(
            "scope",
            {}
        )

        scope_mode = scope.get(
            "mode"
        )

        scope_key = scope.get(
            "key"
        )

        scope_value = scope.get(
            "value"
        )

        allowed_resources = scope.get(
            "allowed_resources",
            []
        )

        # ---------------------------------------------------------
        # PROCESS FAILED RESOURCES
        # ---------------------------------------------------------

        for resource in control.get(
            "failed",
            []
        ):

            resource_id = resource.get(
                "resource_id"
            )

            resource_type = resource.get(
                "resource_type"
            )

            resource_status = resource.get(
                "status",
                "FAILED"
            )

            action = "SKIP"

            reason = (
                "Resource is outside "
                "remediation scope"
            )

            # -----------------------------------------------------
            # STALE PROTECTION
            # -----------------------------------------------------

            if resource_status == "STALE":

                action = "SKIP"

                reason = (
                    "Resource is stale or "
                    "no longer exists"
                )

            # -----------------------------------------------------
            # EXPLICIT SCOPE
            # -----------------------------------------------------

            elif scope_mode == "explicit":

                if resource_id in allowed_resources:

                    action = "ALLOW"

                    reason = (
                        "Resource explicitly allowed "
                        "by remediation policy"
                    )

                else:

                    action = "SKIP"

                    reason = (
                        "Resource is not in explicit "
                        "remediation scope"
                    )

            # -----------------------------------------------------
            # TAG SCOPE
            # -----------------------------------------------------

            elif scope_mode == "tag":

                try:

                    is_valid, validation_reason = (
                        validate_resource(
                            resource_id,
                            resource_type
                        )
                    )

                    if is_valid:

                        action = "ALLOW"

                        reason = (
                            f"Required tag "
                            f"{scope_key}={scope_value} "
                            f"verified"
                        )

                    else:

                        action = "SKIP"

                        reason = validation_reason

                except Exception as error:

                    action = "SKIP"

                    reason = (
                        "Scope validation error: "
                        f"{error}"
                    )

            # -----------------------------------------------------
            # UNKNOWN SCOPE
            # -----------------------------------------------------

            else:

                action = "SKIP"

                reason = (
                    "Unknown remediation scope"
                )

            # -----------------------------------------------------
            # ADD PLAN ITEM
            # -----------------------------------------------------

            plan.append({
                "control_id": control_id,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "remediation_type": remediation_type,
                "severity": severity,
                "description": description,

                "scope": {
                    "mode": scope_mode,
                    "key": scope_key,
                    "value": scope_value
                },

                "action": action,
                "reason": reason,

                "finding": {
                    "record_state": resource.get(
                        "record_state"
                    ),
                    "workflow_status": resource.get(
                        "workflow_status"
                    ),
                    "updated_at": resource.get(
                        "updated_at"
                    ),
                    "last_observed_at": resource.get(
                        "last_observed_at"
                    ),
                    "title": resource.get(
                        "title"
                    )
                }
            })

    return plan, scan_file


def build_summary(plan):

    total = len(plan)

    allowed = sum(
        1
        for item in plan
        if item.get("action") == "ALLOW"
    )

    skipped = sum(
        1
        for item in plan
        if item.get("action") == "SKIP"
    )

    return {
        "total_candidates": total,
        "allowed": allowed,
        "skipped": skipped
    }


def print_plan(
    plan,
    summary
):

    print("=" * 70)
    print("CSPM REMEDIATION PLAN v2")
    print("=" * 70)
    print()

    print(
        f"Total candidates : "
        f"{summary['total_candidates']}"
    )

    print(
        f"Allowed          : "
        f"{summary['allowed']}"
    )

    print(
        f"Skipped          : "
        f"{summary['skipped']}"
    )

    print()

    if not plan:

        print(
            "No remediation candidates found."
        )

        return

    for item in plan:

        print(
            f"[{item['action']}] "
            f"{item['control_id']}"
        )

        print(
            f"  Resource : "
            f"{item.get('resource_id', '-')}"
        )

        print(
            f"  Type     : "
            f"{item.get('resource_type', '-')}"
        )

        print(
            f"  Method   : "
            f"{item.get('remediation_type', '-')}"
        )

        print(
            f"  Severity : "
            f"{item.get('severity', '-')}"
        )

        scope = item.get(
            "scope",
            {}
        )

        print(
            f"  Scope    : "
            f"{scope.get('mode', '-')}"
        )

        print(
            f"  Reason   : "
            f"{item.get('reason', '-')}"
        )

        print()


def save_plan(
    plan,
    summary,
    scan_file
):

    output_file = (
        PROJECT_ROOT
        / "tests"
        / "outputs"
        / "cspm-remediation-plan.json"
    )

    report = {
        "planner": "CSPM Remediation Planner",
        "version": "2.0",

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "source_scan": str(
            scan_file
        ),

        "dry_run": True,

        "execution": (
            "NOT_PERFORMED"
        ),

        "execution_policy": {
            "automatic_execution": False,
            "require_scope_validation": True,
            "allow_production_resources": False
        },

        "summary": summary,

        "plan": plan
    }

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            ensure_ascii=False,
            indent=2
        )

    return output_file


def main():

    plan, scan_file = create_plan()

    summary = build_summary(
        plan
    )

    print_plan(
        plan,
        summary
    )

    output_file = save_plan(
        plan,
        summary,
        scan_file
    )

    print(
        f"Source scan: {scan_file}"
    )

    print(
        f"Plan: {output_file}"
    )


if __name__ == "__main__":
    main()