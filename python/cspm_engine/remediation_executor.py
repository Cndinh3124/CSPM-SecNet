import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PLAN_FILE = (
    PROJECT_ROOT
    / "tests"
    / "outputs"
    / "cspm-remediation-plan.json"
)

EXECUTION_LOG_FILE = (
    PROJECT_ROOT
    / "tests"
    / "outputs"
    / "cspm-execution-log.json"
)


def load_plan():

    if not PLAN_FILE.exists():
        raise FileNotFoundError(
            f"Không tìm thấy remediation plan: {PLAN_FILE}"
        )

    with open(
        PLAN_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def execute_cloud_custodian(item):

    control_id = item.get(
        "control_id"
    )

    if control_id == "EC2.53":

        policy_file = (
            PROJECT_ROOT
            / "policies"
            / "ec2-53.yml"
        )

        if not policy_file.exists():
            raise FileNotFoundError(
                f"Không tìm thấy policy: {policy_file}"
            )

        output_dir = (
            PROJECT_ROOT
            / "tests"
            / "outputs"
            / "custodian-execution"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        command = [
            "custodian",
            "run",
            str(policy_file),
            "-s",
            str(output_dir),
            "--cache-period",
            "0"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT
        )

        return {
            "command": command,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }

    raise ValueError(
        f"Chưa hỗ trợ remediation type/control: "
        f"{control_id}"
    )


def execute_item(item):

    control_id = item.get(
        "control_id"
    )

    resource_id = item.get(
        "resource_id"
    )

    remediation_type = item.get(
        "remediation_type"
    )

    action = item.get(
        "action"
    )

    # ---------------------------------------------------------
    # SAFETY CHECK
    # ---------------------------------------------------------

    if action != "ALLOW":

        return {
            "control_id": control_id,
            "resource_id": resource_id,
            "action": action,
            "execution_status": "SKIPPED",
            "reason": (
                "Remediation item is not ALLOW"
            )
        }

    # ---------------------------------------------------------
    # SUPPORTED REMEDIATION
    # ---------------------------------------------------------

    try:

        if remediation_type == "cloud-custodian":

            result = execute_cloud_custodian(
                item
            )

            return {
                "control_id": control_id,
                "resource_id": resource_id,
                "action": "ALLOW",
                "remediation_type": remediation_type,
                "execution_status": (
                    "SUCCESS"
                    if result["success"]
                    else "FAILED"
                ),
                "return_code": result[
                    "return_code"
                ],
                "stdout": result[
                    "stdout"
                ],
                "stderr": result[
                    "stderr"
                ]
            }

        return {
            "control_id": control_id,
            "resource_id": resource_id,
            "action": "ALLOW",
            "remediation_type": remediation_type,
            "execution_status": "FAILED",
            "reason": (
                "Unsupported remediation type"
            )
        }

    except Exception as error:

        return {
            "control_id": control_id,
            "resource_id": resource_id,
            "action": "ALLOW",
            "remediation_type": remediation_type,
            "execution_status": "FAILED",
            "reason": str(error)
        }


def execute_plan():

    plan_report = load_plan()

    plan = plan_report.get(
        "plan",
        []
    )

    results = []

    for item in plan:

        result = execute_item(
            item
        )

        results.append(
            result
        )

    return results


def build_summary(results):

    total = len(results)

    success = sum(
        1
        for item in results
        if item.get(
            "execution_status"
        ) == "SUCCESS"
    )

    failed = sum(
        1
        for item in results
        if item.get(
            "execution_status"
        ) == "FAILED"
    )

    skipped = sum(
        1
        for item in results
        if item.get(
            "execution_status"
        ) == "SKIPPED"
    )

    return {
        "total_items": total,
        "success": success,
        "failed": failed,
        "skipped": skipped
    }


def save_execution_log(
    results,
    summary
):

    report = {
        "executor": (
            "CSPM Remediation Executor"
        ),

        "version": "1.0",

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "source_plan": str(
            PLAN_FILE
        ),

        "summary": summary,

        "execution_policy": {
            "execute_only_allow": True,
            "require_scope_validation": True,
            "allow_production_resources": False
        },

        "results": results
    }

    with open(
        EXECUTION_LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            ensure_ascii=False,
            indent=2
        )

    return EXECUTION_LOG_FILE


def print_results(
    results,
    summary
):

    print("=" * 70)
    print("CSPM REMEDIATION EXECUTOR v1.0")
    print("=" * 70)
    print()

    print(
        f"Total items : "
        f"{summary['total_items']}"
    )

    print(
        f"Success     : "
        f"{summary['success']}"
    )

    print(
        f"Failed      : "
        f"{summary['failed']}"
    )

    print(
        f"Skipped     : "
        f"{summary['skipped']}"
    )

    print()

    for item in results:

        print(
            f"[{item.get('execution_status')}] "
            f"{item.get('control_id')}"
        )

        print(
            f"  Resource : "
            f"{item.get('resource_id', '-')}"
        )

        if item.get("reason"):

            print(
                f"  Reason   : "
                f"{item['reason']}"
            )

        print()


def main():

    results = execute_plan()

    summary = build_summary(
        results
    )

    print_results(
        results,
        summary
    )

    output_file = save_execution_log(
        results,
        summary
    )

    print(
        f"Execution log: {output_file}"
    )


if __name__ == "__main__":
    main()