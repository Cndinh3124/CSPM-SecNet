from __future__ import annotations

from typing import Any

from .scanner import scan

def verify_remediation(
    previous_results: list[dict[str, Any]],
    region: str = "ap-southeast-1",
) -> dict[str, Any]:
    current = scan(region)
    current_keys = {
        (item.get("control"), item.get("resource"))
        for item in current.get("findings", [])
        if item.get("status") == "FAILED"
    }

    results = []
    for item in previous_results:
        key = (item.get("control"), item.get("resource"))
        resolved = key not in current_keys
        results.append({
            "control": item.get("control"),
            "resource": item.get("resource"),
            "previous_status": item.get("execution_status"),
            "verification": "PASS" if resolved else "FAIL",
            "resolved": resolved,
        })

    return {
        "region": region,
        "verification_count": len(results),
        "resolved_count": sum(1 for x in results if x["resolved"]),
        "failed_count": sum(1 for x in results if not x["resolved"]),
        "results": results,
        "current_scan_summary": current.get("summary", {}),
    }
