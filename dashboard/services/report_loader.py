import os
from pathlib import Path

import requests
import streamlit as st


# ============================================================
# CONFIG
# ============================================================

API_BASE_URL = os.getenv(
    "CSPM_API_URL",
    "http://localhost:8000/api/v1",
).rstrip("/")


# ============================================================
# API CLIENT
# ============================================================

def _get(path: str, timeout: int = 15):
    """
    Call SecNet CSPM FastAPI.
    """
    url = f"{API_BASE_URL}/{path.lstrip('/')}"

    response = requests.get(
        url,
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# LATEST SCAN
# ============================================================

@st.cache_data(ttl=8)
def load_latest_scan():
    """
    Load latest scan directly from FastAPI.
    """

    data = _get("/scans")

    scans = data.get("value", [])

    if not scans:
        return None

    # API already returns newest first,
    # but sorting here makes the Dashboard robust.
    scans = sorted(
        scans,
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )

    return scans[0]


# ============================================================
# SCAN DETAIL
# ============================================================

@st.cache_data(ttl=8)
def load_scan_detail(scan_id: int):
    """
    Load complete scan detail:

    - scan metadata
    - CIS controls
    - resource summary
    - findings
    """

    return _get(
        f"/scans/{scan_id}/detail",
        timeout=20,
    )


# ============================================================
# LATEST REPORT
# ============================================================

@st.cache_data(ttl=8)
def load_latest_report():
    """
    Compatibility layer for existing Dashboard pages.

    Existing pages can continue using:

        scan, path, demo = load_latest_report()

    without needing to know that the data now comes
    from FastAPI/PostgreSQL instead of JSON files.
    """

    latest_scan = load_latest_scan()

    if not latest_scan:
        return _empty_report(), None, False

    scan_id = latest_scan.get("id")

    if not scan_id:
        return _empty_report(), None, False

    detail = load_scan_detail(scan_id)

    # Convert API detail into the structure expected
    # by the existing Dashboard adapter.
    report = _normalize_detail(detail)

    return report, f"API:/scans/{scan_id}/detail", False


# ============================================================
# HISTORY
# ============================================================

@st.cache_data(ttl=8)
def load_history():
    """
    Load scan history from FastAPI.
    """

    data = _get("/scans")

    scans = data.get("value", [])

    rows = []

    for scan in scans:
        if not isinstance(scan, dict):
            continue

        scan_id = scan.get("id")

        if not scan_id:
            continue

        try:
            detail = load_scan_detail(scan_id)
        except Exception:
            # A historical failed scan may not have detail data.
            detail = None

        rows.append(
            (
                f"API:/scans/{scan_id}",
                _normalize_detail(detail, scan),
            )
        )

    return rows


# ============================================================
# NORMALIZATION
# ============================================================

def _normalize_detail(detail, fallback_scan=None):
    """
    Normalize FastAPI scan detail into the format
    consumed by the existing Dashboard.

    This allows us to migrate the backend source
    without rewriting all pages at once.
    """

    fallback_scan = fallback_scan or {}

    if not detail:
        return {
            "generated_at": fallback_scan.get("finished_at")
            or fallback_scan.get("created_at")
            or "",

            "region": fallback_scan.get(
                "region",
                "ap-southeast-1",
            ),

            "engine": "SecNet CSPM API",

            "controls": [],

            "resource_summary": {
                "active": 0,
                "passed": 0,
                "failed": 0,
                "stale": 0,
                "unknown": 0,
            },
        }

    scan = detail.get("scan") or fallback_scan
    controls = detail.get("controls") or []
    resource_summary = detail.get(
        "resource_summary"
    ) or {}

    normalized_controls = []

    for control in controls:
        if not isinstance(control, dict):
            continue

        normalized_controls.append(
            {
                "control_id": control.get(
                    "control_id",
                    "UNKNOWN",
                ),

                "status": control.get(
                    "status",
                    "UNKNOWN",
                ),

                "passed": control.get(
                    "passed",
                    [],
                ),

                "failed": control.get(
                    "failed",
                    [],
                ),

                "unknown": control.get(
                    "unknown",
                    [],
                ),

                "passed_count": control.get(
                    "passed_count",
                    len(control.get("passed", [])),
                ),

                "failed_count": control.get(
                    "failed_count",
                    len(control.get("failed", [])),
                ),

                "unknown_count": control.get(
                    "unknown_count",
                    len(control.get("unknown", [])),
                ),

                "compliance_percent": control.get(
                    "compliance_percent",
                    0,
                ),
            }
        )

    return {
        "generated_at": (
            scan.get("finished_at")
            or scan.get("created_at")
            or ""
        ),

        "region": scan.get(
            "region",
            "ap-southeast-1",
        ),

        "engine": "SecNet CSPM API",

        "controls": normalized_controls,

        "resource_summary": {
            "active": _number(
                resource_summary.get("active")
            ),

            "passed": _number(
                resource_summary.get("passed")
            ),

            "failed": _number(
                resource_summary.get("failed")
            ),

            "stale": _number(
                resource_summary.get("stale")
            ),

            "unknown": _number(
                resource_summary.get("unknown")
            ),
        },

        # Preserve API findings so future pages
        # can consume them without another API call.
        "findings": detail.get(
            "findings",
            [],
        ),

        "summary": detail.get(
            "summary",
            {},
        ),
    }


# ============================================================
# EMPTY REPORT
# ============================================================

def _empty_report():
    return {
        "generated_at": "",
        "region": "ap-southeast-1",
        "engine": "SecNet CSPM API",
        "controls": [],
        "resource_summary": {
            "active": 0,
            "passed": 0,
            "failed": 0,
            "stale": 0,
            "unknown": 0,
        },
        "findings": [],
        "summary": {},
    }


# ============================================================
# HELPERS
# ============================================================

def _number(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default