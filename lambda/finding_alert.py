import json
import os
import boto3

sns = boto3.client("sns")

ALLOWED_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
}


def lambda_handler(event, context):
    topic = os.environ.get("SNS_TOPIC_ARN")

    if not topic:
        print("[SecNet] ERROR: SNS_TOPIC_ARN not configured")
        return {
            "statusCode": 200,
            "body": "SNS_TOPIC_ARN not configured",
        }

    detail = event.get("detail", {})
    findings = detail.get("findings") or []

    if not findings:
        print("[SecNet] WARNING: Event contains no findings")
        return {
            "statusCode": 200,
            "body": "No findings in event",
        }

    processed = 0
    sent = 0
    skipped = 0

    for finding in findings:
        processed += 1

        title = finding.get(
            "Title",
            "SecNet Security Finding",
        )

        severity = (
            (finding.get("Severity") or {})
            .get("Label", "UNKNOWN")
            .upper()
        )

        compliance = finding.get("Compliance") or {}

        control = compliance.get(
            "SecurityControlId",
            "UNKNOWN",
        )

        resources = finding.get("Resources") or [{}]

        resource_id = resources[0].get("Id")

        workflow = (
            (finding.get("Workflow") or {})
            .get("Status", "UNKNOWN")
            .upper()
        )

        record_state = (
            finding.get(
                "RecordState",
                "UNKNOWN",
            )
            .upper()
        )

        finding_id = finding.get(
            "Id",
            "UNKNOWN",
        )

        print("[SecNet] Finding received")
        print(f"[SecNet] Control: {control}")
        print(f"[SecNet] Severity: {severity}")
        print(f"[SecNet] Title: {title}")
        print(f"[SecNet] Resource: {resource_id}")
        print(f"[SecNet] Workflow: {workflow}")
        print(f"[SecNet] RecordState: {record_state}")
        print(f"[SecNet] FindingId: {finding_id}")

        # ---------------------------------------------------------
        # Alert policy
        # ---------------------------------------------------------

        if severity not in ALLOWED_SEVERITIES:
            print(
                "[SecNet] SKIP: severity "
                f"{severity} is not alertable"
            )
            skipped += 1
            continue

        if workflow == "RESOLVED":
            print(
                "[SecNet] SKIP: finding workflow is RESOLVED"
            )
            skipped += 1
            continue

        if record_state != "ACTIVE":
            print(
                "[SecNet] SKIP: record state is "
                f"{record_state}"
            )
            skipped += 1
            continue

        # ---------------------------------------------------------
        # Build alert
        # ---------------------------------------------------------

        subject = f"[SecNet][{severity}] {control}"

        message = json.dumps(
            {
                "product": "SecNet CSPM",
                "title": title,
                "severity": severity,
                "control": control,
                "resource": resource_id,
                "workflow": workflow,
                "record_state": record_state,
                "finding_id": finding_id,
            },
            ensure_ascii=False,
            indent=2,
        )

        try:
            response = sns.publish(
                TopicArn=topic,
                Subject=subject[:100],
                Message=message,
            )

            print(
                "[SecNet] SNS alert published successfully"
            )
            print(
                "[SecNet] SNS MessageId: "
                f"{response.get('MessageId')}"
            )

            sent += 1

        except Exception as exc:
            print(
                "[SecNet] ERROR: failed to publish "
                f"SNS alert: {exc}"
            )
            raise

    print(
        "[SecNet] Alert processing completed: "
        f"processed={processed}, "
        f"sent={sent}, "
        f"skipped={skipped}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "processed": processed,
                "sent": sent,
                "skipped": skipped,
            }
        ),
    }