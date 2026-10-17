import csv
import hashlib
import json
from pathlib import Path


FAILED_STATUSES = {"FAIL", "FAILED"}


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


def _normalize_status(value):
    status = str(value or "").strip().upper()
    if status == "FAILED":
        return "FAIL"
    return status


def _account_region_control_resource(account_id, region, control_id, resource):
    return _fingerprint(account_id, region, control_id, resource)


def normalize_ocsf(finding, scan_id, region):
    resource = _first_resource(finding)
    resource_data = resource.get("data") or {}
    resource_metadata = resource_data.get("metadata") or {}
    finding_info = finding.get("finding_info") or {}
    analytic = finding_info.get("analytic") or {}
    metadata = finding.get("metadata") or {}
    cloud = finding.get("cloud") or {}
    account = cloud.get("account") or {}
    unmapped = finding.get("unmapped") or {}
    remediation = finding.get("remediation") or {}

    control_id = str(
        _get(metadata, "event_code")
        or _get(analytic, "uid")
        or _get(finding_info, "uid")
    )
    resource_uid = str(resource.get("uid") or "")
    resource_arn = str(_get(resource_metadata, "arn") or (
        resource_uid if resource_uid.startswith("arn:") else ""
    ))
    resource_id = str(
        _get(resource_metadata, "id")
        or resource.get("uid")
        or resource.get("name")
    )
    finding_region = str(resource.get("region") or cloud.get("region") or region)
    status = _normalize_status(
        _get(finding, "status_code", "status", "Status", default="")
    )

    labels = resource.get("labels") or unmapped.get("labels") or []
    compliance = unmapped.get("compliance") or {}
    account_id = str(account.get("uid") or unmapped.get("provider_uid") or "")
    stable_resource = resource_arn or resource_id
    finding_uid = str(_get(finding_info, "uid") or _get(metadata, "finding_uid"))

    return {
        "scan_id": scan_id,
        "finding_uid": finding_uid,
        "fingerprint": _account_region_control_resource(
            account_id, finding_region, control_id, stable_resource
        ),
        "control_id": control_id,
        "status": status,
        "severity": str(_get(finding, "severity", default="UNKNOWN")).upper(),
        "title": str(_get(finding_info, "title")),
        "resource_id": resource_id,
        "resource_type": str(resource.get("type") or ""),
        "resource_arn": resource_arn,
        "account_id": account_id,
        "region": finding_region,
        "service": str((resource.get("group") or {}).get("name") or ""),
        "description": str(_get(finding_info, "desc")),
        "message": str(_get(finding, "message", "status_detail", "status_detail")),
        "risk_details": str(finding.get("risk_details") or ""),
        "remediation": str(_get(remediation, "desc")),
        "remediation_references": remediation.get("references") or [],
        "labels": labels,
        "compliance": compliance,
        "raw": finding,
    }


def _parse_json(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # OCSF exports can be a single finding or a wrapper containing findings.
        for key in ("findings", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data if isinstance(data, list) else []


def _parse_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\\t")
            delimiter = dialect.delimiter
        except csv.Error:
            first_line = sample.splitlines()[0] if sample else ""
            delimiter = ";" if first_line.count(";") > first_line.count(",") else ","
        return list(csv.DictReader(handle, delimiter=delimiter))


def _normalize_csv_finding(item, scan_id, region):
    account_id = str(_get(
        item, "ACCOUNT_UID", "account_id", "AccountId", "ACCOUNT_ID", "ACCOUNT_UID"
    ))
    finding_region = str(_get(item, "REGION", "region", "Region", default=region))
    control_id = str(_get(
        item, "CHECK_ID", "check_id", "CheckID", "CONTROL_ID", "control_id", "control"
    ))
    resource_uid = str(_get(
        item, "RESOURCE_UID", "resource_uid", "RESOURCE_ID", "resource_id",
        "ResourceId", "ResourceArn", "RESOURCE_ARN"
    ))
    resource_arn = str(_get(item, "RESOURCE_ARN", "resource_arn"))
    if not resource_arn and resource_uid.startswith("arn:"):
        resource_arn = resource_uid
    resource_id = str(_get(
        item, "RESOURCE_ID", "resource_id", "ResourceId", "RESOURCE_UID",
        "resource_uid", "RESOURCE_NAME"
    ))
    finding_uid = str(_get(item, "FINDING_UID", "finding_uid"))
    stable_resource = resource_arn or resource_uid or resource_id

    return {
        "scan_id": scan_id,
        "finding_uid": finding_uid,
        "fingerprint": _account_region_control_resource(
            account_id, finding_region, control_id, stable_resource
        ),
        "control_id": control_id,
        "status": _normalize_status(_get(item, "STATUS", "status", "Status")),
        "severity": str(_get(item, "SEVERITY", "severity", "Severity", default="UNKNOWN")).upper(),
        "title": str(_get(item, "CHECK_TITLE", "check_title", "title", "FindingTitle")),
        "resource_id": resource_id,
        "resource_type": str(_get(item, "RESOURCE_TYPE", "resource_type", "ResourceType")),
        "resource_arn": resource_arn,
        "account_id": account_id,
        "region": finding_region,
        "service": str(_get(item, "SERVICE_NAME", "service_name", "ServiceName", "service")),
        "description": str(_get(item, "DESCRIPTION", "description", "Description")),
        "message": str(_get(item, "STATUS_EXTENDED", "status_extended", "message", "status_detail")),
        "risk_details": str(_get(item, "RISK", "risk")),
        "remediation": str(_get(
            item, "REMEDIATION_RECOMMENDATION_TEXT", "remediation", "Remediation"
        )),
        "remediation_references": [
            str(value) for value in [
                _get(item, "REMEDIATION_RECOMMENDATION_URL", "remediation_url"),
                _get(item, "RELATED_URL", "related_url"),
            ] if value
        ],
        "labels": _get(item, "RESOURCE_TAGS", "resource_tags", default=[]),
        "compliance": _get(item, "COMPLIANCE", "compliance", default={}),
        "raw": item,
    }


def parse_file(path, scan_id, region):
    path = Path(path)
    if path.suffix.lower() == ".json":
        data = _parse_json(path)
    elif path.suffix.lower() == ".csv":
        data = _parse_csv(path)
    else:
        return []

    out = []
    for item in data:
        if not isinstance(item, dict):
            continue

        status = _normalize_status(
            _get(item, "status_code", "STATUS_CODE", "status", "Status", "STATUS")
        )
        if status not in FAILED_STATUSES:
            continue

        if item.get("finding_info") and item.get("resources"):
            out.append(normalize_ocsf(item, scan_id, region))
        else:
            out.append(_normalize_csv_finding(item, scan_id, region))
    return out


def _merge_findings(existing, incoming):
    """Merge CSV/OCSF representations, preferring OCSF fields when available."""
    merged = dict(existing)
    existing_raw = merged.get("raw")
    incoming_raw = incoming.get("raw")
    existing_is_ocsf = (
        isinstance(existing_raw, dict)
        and bool(existing_raw.get("finding_info"))
        and bool(existing_raw.get("resources"))
    )
    incoming_is_ocsf = (
        isinstance(incoming_raw, dict)
        and bool(incoming_raw.get("finding_info"))
        and bool(incoming_raw.get("resources"))
    )
    prefer_incoming = incoming_is_ocsf and not existing_is_ocsf

    for key, value in incoming.items():
        if key == "raw":
            if incoming_is_ocsf or not merged.get(key):
                merged[key] = value
            continue
        if value in ("", None, [], {}):
            continue
        if prefer_incoming or merged.get(key) in ("", None, [], {}):
            merged[key] = value
    return merged


def parse_directory(directory, scan_id, region):
    """Parse primary Prowler reports and deduplicate CSV/OCSF representations."""
    root = Path(directory)
    findings_by_key = {}
    key_by_fingerprint = {}
    key_by_uid = {}

    # Compliance exports live in subdirectories and are not re-ingested because
    # they represent the same scan through a different compliance lens.
    for path in sorted(root.iterdir() if root.exists() else []):
        if not path.is_file() or path.suffix.lower() not in {".json", ".csv"}:
            continue
        try:
            findings = parse_file(path, scan_id, region)
        except (json.JSONDecodeError, UnicodeDecodeError, csv.Error, OSError):
            continue

        for finding in findings:
            fingerprint = finding.get("fingerprint") or _fingerprint(
                finding.get("account_id"),
                finding.get("region"),
                finding.get("control_id"),
                finding.get("resource_id"),
            )
            uid = finding.get("finding_uid")
            # Prefer the source finding UID, but use the stable resource/control
            # fingerprint as a fallback for legacy exports with different UIDs.
            key = key_by_uid.get(uid) if uid else None
            if key is None:
                key = key_by_fingerprint.get(fingerprint)

            if key is None:
                key = uid or fingerprint
                findings_by_key[key] = finding
            else:
                findings_by_key[key] = _merge_findings(findings_by_key[key], finding)

            key_by_fingerprint[fingerprint] = key
            if uid:
                key_by_uid[uid] = key

    return list(findings_by_key.values())
