import csv
import hashlib
import json
from pathlib import Path


def _get(value, *keys, default=""):
    if not isinstance(value, dict):
        return default
    for key in keys:
        current = value.get(key)
        if current not in (None, ""):
            return current
    return default


def _first_resource(finding):
    resources = finding.get("resources") or []
    return resources[0] if resources and isinstance(resources[0], dict) else {}


def _fingerprint(*parts):
    payload = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_ocsf(finding, scan_id, region):
    resource = _first_resource(finding)
    resource_data = resource.get("data") or {}
    resource_metadata = resource_data.get("metadata") or {}
    finding_info = finding.get("finding_info") or {}
    analytic = finding_info.get("analytic") or {}
    cloud = finding.get("cloud") or {}
    account = cloud.get("account") or {}
    unmapped = finding.get("unmapped") or {}
    remediation = finding.get("remediation") or {}

    control_id = str(
        _get(finding.get("metadata") or {}, "event_code")
        or _get(analytic, "uid")
        or ""
    )
    resource_arn = str(_get(resource_metadata, "arn") or resource.get("uid"))
    resource_id = str(
        _get(resource_metadata, "id")
        or resource.get("name")
        or resource.get("uid")
        or ""
    )
    finding_region = str(
        resource.get("region")
        or cloud.get("region")
        or region
    )

    status_code = str(
        _get(finding, "status_code", default=_get(finding, "status"))
    ).upper()
    status = "FAIL" if status_code in {"FAIL", "FAILED"} else status_code

    labels = resource.get("labels") or unmapped.get("labels") or []
    compliance = unmapped.get("compliance") or {}

    normalized = {
        "scan_id": scan_id,
        "fingerprint": _fingerprint(
            account.get("uid"),
            finding_region,
            control_id,
            resource_arn,
        ),
        "control_id": control_id,
        "status": status,
        "severity": str(_get(finding, "severity", default="UNKNOWN")).upper(),
        "title": str(_get(finding_info, "title")),
        "resource_id": resource_id,
        "resource_type": str(resource.get("type") or ""),
        "resource_arn": resource_arn,
        "account_id": str(account.get("uid") or unmapped.get("provider_uid") or ""),
        "region": finding_region,
        "service": str((resource.get("group") or {}).get("name") or ""),
        "description": str(_get(finding_info, "desc")),
        "message": str(_get(finding, "message", "status_detail")),
        "risk_details": str(finding.get("risk_details") or ""),
        "remediation": str(remediation.get("desc") or ""),
        "remediation_references": remediation.get("references") or [],
        "labels": labels,
        "compliance": compliance,
        "raw": finding,
    }
    return normalized


def _parse_json(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # OCSF exports are commonly a single finding or a dict containing findings.
        data = data.get("findings") or data.get("data") or data.get("results") or [data]
    return data if isinstance(data, list) else []


def parse_file(path, scan_id, region):
    if path.suffix.lower() == ".json":
        data = _parse_json(path)
    elif path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            data = list(csv.DictReader(handle))
    else:
        return []

    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        status = str(
            _get(item, "status_code", "status", "Status", default="")
        ).upper()
        if status not in {"FAIL", "FAILED"}:
            continue

        if item.get("finding_info") and item.get("resources"):
            out.append(normalize_ocsf(item, scan_id, region))
            continue

        # Compatibility path for simple/legacy CSV-like records.
        out.append(
            {
                "scan_id": scan_id,
                "fingerprint": _fingerprint(
                    _get(item, "account_id", "AccountId"),
                    _get(item, "region", "Region", default=region),
                    _get(item, "check_id", "CheckID", "control_id", "control"),
                    _get(item, "resource_id", "ResourceId", "resource_uid"),
                ),
                "control_id": str(_get(item, "check_id", "CheckID", "control_id", "control")),
                "status": "FAIL",
                "severity": str(_get(item, "severity", "Severity", default="UNKNOWN")).upper(),
                "title": str(_get(item, "title", "FindingTitle", "check_title")),
                "resource_id": str(_get(item, "resource_id", "ResourceId", "resource_uid")),
                "resource_type": str(_get(item, "resource_type", "ResourceType")),
                "resource_arn": str(_get(item, "resource_arn", "ResourceArn")),
                "account_id": str(_get(item, "account_id", "AccountId")),
                "region": str(_get(item, "region", "Region", default=region)),
                "service": str(_get(item, "service_name", "ServiceName", "service")),
                "description": str(_get(item, "description", "Description")),
                "message": str(_get(item, "message", "status_detail")),
                "risk_details": "",
                "remediation": "",
                "remediation_references": [],
                "labels": [],
                "compliance": {},
                "raw": item,
            }
        )
    return out


def parse_directory(directory, scan_id, region):
    out = []
    for path in Path(directory).rglob("*"):
        if path.suffix.lower() not in {".json", ".csv"}:
            continue
        try:
            out.extend(parse_file(path, scan_id, region))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return out
