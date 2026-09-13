import json, os, boto3

sns = boto3.client("sns")

def lambda_handler(event, context):
    topic = os.environ.get("SNS_TOPIC_ARN")
    if not topic:
        return {"statusCode": 200, "body": "SNS_TOPIC_ARN not configured"}
    detail = event.get("detail", {})
    finding = detail.get("findings", [{}])[0]
    title = finding.get("Title", "SecNet Security Finding")
    severity = (finding.get("Severity") or {}).get("Label", "UNKNOWN")
    control = (finding.get("Compliance") or {}).get("SecurityControlId", "UNKNOWN")
    subject = f"[SecNet][{severity}] {control}"
    message = json.dumps({
        "product": "SecNet CSPM",
        "title": title,
        "severity": severity,
        "control": control,
        "resource": (finding.get("Resources") or [{}])[0].get("Id"),
        "workflow": (finding.get("Workflow") or {}).get("Status"),
    }, ensure_ascii=False, indent=2)
    sns.publish(TopicArn=topic, Subject=subject[:100], Message=message)
    return {"statusCode": 200, "body": "alert published"}
