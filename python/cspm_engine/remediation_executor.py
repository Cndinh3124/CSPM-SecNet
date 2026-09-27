import json
import subprocess
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
        encoding="utf-8",
    ) as file:
        return json.load(file)


def execute_cloud_custodian(item):
    control_id = item.get("control")

    if control_id == "EC2.53":
        policy_file = (
            PROJECT_ROOT
            / "python"
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
            exist_ok=True,
        )

        command = [
            "custodian",
            "run",
            str(policy_file),
            "-s",
            str(output_dir),
            "--cache-period",
            "0",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )

        return {
            "command": command,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
        }

    raise ValueError(
        f"Chưa hỗ trợ remediation control: {control_id}"
    )


def execute_item(item):
    control_id = item.get("control")
    resource_id = item.get("resource")

    action = item.get(
        "action",
        {},
    )

    remediation_type = action.get("type")

    allowed = item.get(
        "allowed",
        False,
    )

    # ---------------------------------------------------------
    # SAFETY CHECK
    # ---------------------------------------------------------

    if allowed is not True:
        return {
            "control": control_id,
            "resource": resource_id,
            "allowed": False,
            "execution_status": "SKIPPED",
            "reason": item.get(
                "reason",
                "Remediation is not allowed",
            ),
        }

    # ---------------------------------------------------------
    # SUPPORTED REMEDIATION
    # ---------------------------------------------------------

    try:
        if remediation_type == "cloud-custodian":
            result = execute_cloud_custodian(item)

            return {
                "control": control_id,
                "resource": resource_id,
                "allowed": True,
                "remediation_type": remediation_type,
                "execution_status": (
                    "SUCCESS"
                    if result["success"]
                    else "FAILED"
                ),
                "return_code": result["return_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }

        return {
            "control": control_id,
            "resource": resource_id,
            "allowed": True,
            "remediation_type": remediation_type,
            "execution_status": "FAILED",
            "reason": "Unsupported remediation type",
        }

    except Exception as error:
        return {
            "control": control_id,
            "resource": resource_id,
            "allowed": True,
            "remediation_type": remediation_type,
            "execution_status": "FAILED",
            "reason": str(error),
        }


def execute_plan():
    plan_report = load_plan()

    plan = plan_report.get(
        "items",
        [],
    )

    results = []

    for item in plan:
        result = execute_item(item)
        results.append(result)

    return results


def build_summary(results):
    total = len(results)

    success = sum(
        1
        for item in results
        if item.get("execution_status") == "SUCCESS"
    )

    failed = sum(
        1
        for item in results
        if item.get("execution_status") == "FAILED"
    )

    skipped = sum(
        1
        for item in results
        if item.get("execution_status") == "SKIPPED"
    )

    return {
        "total_items": total,
        "success": success,
        "failed": failed,
        "skipped": skipped,
    }


def save_execution_log(results, summary):
    report = {
        "executor": "CSPM Remediation Executor",
        "results": results,
        "summary": summary,
    }

    EXECUTION_LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        EXECUTION_LOG_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            ensure_ascii=False,
            indent=2,
        )

    return EXECUTION_LOG_FILE


def main():
    try:
        results = execute_plan()
        summary = build_summary(results)

        log_file = save_execution_log(
            results,
            summary,
        )

        print("\n=== CSPM REMEDIATION RESULT ===")
        print(
            json.dumps(
                summary,
                ensure_ascii=False,
                indent=2,
            )
        )

        print(
            f"\nExecution log: {log_file}"
        )

        print("\n=== DETAILS ===")

        for result in results:
            print(
                json.dumps(
                    result,
                    ensure_ascii=False,
                    indent=2,
                )
            )

    except Exception as error:
        print(
            f"Remediation executor failed: {error}"
        )
        raise


if __name__ == "__main__":
    main()
