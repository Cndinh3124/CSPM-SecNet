from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .finding_store import save_json
from .gemini import analyze_finding
from .scanner import scan

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def analyze_scan(
    scan_data: dict[str, Any],
    region: str,
    limit: int = 20,
) -> dict[str, Any]:
    findings = [
        item for item in scan_data.get("findings", [])
        if item.get("status") == "FAILED"
    ][:limit]

    results = []
    for finding in findings:
        started = time.monotonic()
        try:
            analysis = analyze_finding(
                finding=finding,
                context={
                    "provider": "AWS",
                    "region": region,
                    "benchmark": scan_data.get("scan", {}).get("benchmark"),
                    "scan_summary": scan_data.get("summary", {}),
                },
            )
            results.append({
                "finding_id": finding.get("finding_id"),
                "control": finding.get("control"),
                "resource": finding.get("resource"),
                "status": "ANALYZED",
                "analysis": analysis,
                "duration_seconds": round(time.monotonic() - started, 3),
            })
        except Exception as exc:
            results.append({
                "finding_id": finding.get("finding_id"),
                "control": finding.get("control"),
                "resource": finding.get("resource"),
                "status": "ERROR",
                "error": str(exc),
                "duration_seconds": round(time.monotonic() - started, 3),
            })

    return {
        "version": "1.0",
        "generated_at": _utcnow(),
        "region": region,
        "scanner": "Prowler",
        "ai_engine": "Gemini",
        "findings_analyzed": len(results),
        "results": results,
    }

def run_ai_analysis(region: str = "ap-southeast-1", limit: int = 20) -> dict[str, Any]:
    scan_data = scan(region)
    report = analyze_scan(scan_data, region, limit)
    path = save_json("gemini-analysis.json", report)
    report["output_file"] = str(path)
    return report
