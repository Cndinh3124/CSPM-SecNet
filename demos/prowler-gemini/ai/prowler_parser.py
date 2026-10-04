import csv
from pathlib import Path


def _clean(value):
    if value is None:
        return ""
    return str(value).strip()


def _extract_resource_id(resource_uid: str) -> str:
    """Extract resource ID from a Prowler RESOURCE_UID."""
    resource_uid = _clean(resource_uid)
    if not resource_uid:
        return ""

    return resource_uid.rstrip("/").rsplit("/", 1)[-1]


def find_latest_csv(directory: str) -> Path:
    files = sorted(
        Path(directory).glob("*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not files:
        raise FileNotFoundError(f"No CSV files found in {directory}")

    return files[0]


def load_findings(
    csv_path: str,
    status="FAIL",
    limit=20,
    check_id=None,
    resource_id=None,
):
    rows = []

    with open(
        csv_path,
        newline="",
        encoding="utf-8-sig",
        errors="replace",
    ) as f:
        reader = csv.DictReader(f, delimiter=";")

        for row in reader:
            normalized = {
                str(k).strip().upper(): _clean(v)
                for k, v in row.items()
                if k is not None
            }

            current_status = normalized.get("STATUS", "").upper()
            if current_status != status.upper():
                continue

            current_check_id = normalized.get("CHECK_ID", "")
            current_resource_id = normalized.get("RESOURCE_ID", "")
            current_resource_uid = normalized.get("RESOURCE_UID", "")

            # Fallback: derive resource ID from UID if CSV field is empty.
            if not current_resource_id:
                current_resource_id = _extract_resource_id(
                    current_resource_uid
                )

            if check_id and current_check_id != check_id:
                continue

            if resource_id:
                if (
                    current_resource_id != resource_id
                    and current_resource_uid != resource_id
                    and not current_resource_uid.endswith(f"/{resource_id}")
                ):
                    continue

            finding = {
                "check_id": current_check_id,
                "status": current_status,
                "severity": normalized.get("SEVERITY", ""),
                "service": (
                    normalized.get("SERVICE_NAME", "")
                    or normalized.get("SERVICE", "")
                ),
                "resource_id": current_resource_id,
                "resource_uid": current_resource_uid,
                "resource_type": normalized.get("RESOURCE_TYPE", ""),
                "region": normalized.get("REGION", ""),
                "finding_uid": normalized.get("FINDING_UID", ""),
                "title": (
                    normalized.get("CHECK_TITLE", "")
                    or normalized.get("TITLE", "")
                ),
                "message": (
                    normalized.get("STATUS_EXTENDED", "")
                    or normalized.get("STATUS_EXTENDED_TEXT", "")
                    or normalized.get("MESSAGE", "")
                ),
            }

            rows.append(finding)

            if len(rows) >= limit:
                break

    return rows
