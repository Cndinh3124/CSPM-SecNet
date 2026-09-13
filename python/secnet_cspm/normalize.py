from datetime import datetime, timezone

def _hours_since(value):
    if not value:
        return 0
    try:
        dt = datetime.fromisoformat(value.replace("Z","+00:00"))
        return max(0, int((datetime.now(timezone.utc)-dt).total_seconds()/3600))
    except Exception:
        return 0

def normalize(f):
    resource = (f.get("Resources") or [{}])[0]
    compliance = f.get("Compliance", {})
    control = compliance.get("SecurityControlId") or f.get("GeneratorId","")
    status = compliance.get("Status","UNKNOWN")
    sev = str(f.get("Severity",{}).get("Label","MEDIUM")).upper()
    updated = f.get("UpdatedAt")
    return {
        "finding_id": f.get("Id"),
        "control": control,
        "title": f.get("Title",""),
        "description": f.get("Description",""),
        "severity": sev,
        "status": status,
        "record_state": f.get("RecordState",""),
        "workflow_status": (f.get("Workflow") or {}).get("Status",""),
        "resource": resource.get("Id"),
        "resource_type": resource.get("Type"),
        "updated_at": updated,
        "age_hours": _hours_since(updated),
        "public_exposure": "public" in (f.get("Title","").lower()+" "+f.get("Description","").lower()),
        "source": "AWS Security Hub",
    }
