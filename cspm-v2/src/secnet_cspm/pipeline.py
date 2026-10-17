from typing import Any

from . import dashboard, gemini, parser, prowler, reporting, storage
from .policy import build_remediation_plan, evaluate
from .risk import priority, score


_PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = []
    for original in findings:
        finding = dict(original)
        finding["priority"] = priority(finding)
        ranked.append(finding)
    return sorted(
        ranked,
        key=lambda item: (
            _PRIORITY_ORDER.get(item.get("priority", "P4"), 5),
            -score(item),
            item.get("control_id", ""),
            item.get("resource_id", ""),
        ),
    )


def _merge_analysis_into_all_findings(
    findings: list[dict[str, Any]],
    analyzed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_fingerprint = {
        item.get("fingerprint"): item
        for item in analyzed
        if item.get("fingerprint")
    }
    output = []
    for original in findings:
        item = dict(original)
        analysis = by_fingerprint.get(item.get("fingerprint"))
        if analysis:
            item.update(analysis)
        else:
            item["ai_status"] = "SKIPPED"
        output.append(item)
    return output


def run_scan(region: str, limit: int = 20, check: str | None = None):
    """Run a CSPM scan and generate complete findings plus bounded AI analysis.

    The complete normalized finding set is persisted and reported. Only the
    highest-priority limited findings are sent to the AI advisory step.
    Remediation plans remain subject to policy evaluation.
    """
    if not isinstance(region, str) or not region.strip():
        raise ValueError("region must be a non-empty string.")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer.")

    sid = storage.new_scan_id()
    root = storage.scan_dir(sid)
    out = root / "prowler"

    prowler.run(region, out, check=check)
    try:
        dashboard_result = dashboard.sync_scan_csv(out)
    except Exception as exc:  # noqa: BLE001
        dashboard_result = {
            "status": "ERROR",
            "reason": type(exc).__name__,
            "files_copied": 0,
        }

    findings = parser.parse_directory(out, sid, region)
    normalized = _rank_findings(findings)
    storage.write_json(root / "normalized/findings.json", normalized)

    analyzed: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []
    selected_findings = normalized[:limit]

    for original_finding in selected_findings:
        finding = dict(original_finding)
        try:
            analysis = gemini.analyze(finding)
            if not isinstance(analysis, dict):
                raise TypeError("Gemini analysis must return a dictionary.")
        except Exception as exc:  # noqa: BLE001
            finding["ai_status"] = "ERROR"
            finding["ai_error"] = type(exc).__name__
            analyzed.append(finding)
            continue

        finding.update(analysis)
        finding["ai_status"] = "OK"
        try:
            decision = evaluate(finding, analysis)
            finding["policy_decision"] = {
                "allowed": decision.allowed,
                "approval_required": decision.approval_required,
                "action": decision.action,
                "reason": decision.reason,
            }
            if decision.allowed:
                plans.append(build_remediation_plan(decision, finding, analysis))
        except (TypeError, ValueError) as exc:
            finding["policy_status"] = "ERROR"
            finding["policy_error"] = type(exc).__name__
        analyzed.append(finding)

    storage.write_json(root / "ai/analysis.json", analyzed)
    storage.write_json(root / "remediation/plans.json", plans)

    # Reports contain every failed finding. AI analysis is attached where available.
    report_items = _merge_analysis_into_all_findings(normalized, analyzed)
    report_dir = storage.REPORT_ROOT / sid
    reporting.write_csv(report_dir / "findings.csv", report_items)
    reporting.write_xlsx(report_dir / "findings.xlsx", report_items)
    reporting.write_html(report_dir / "report.html", report_items)

    ai_successful = sum(item.get("ai_status") == "OK" for item in analyzed)
    ai_errors = sum(item.get("ai_status") == "ERROR" for item in analyzed)
    ai_skipped = len(normalized) - len(analyzed)

    result = {
        "scan_id": sid,
        "region": region,
        "check": check,
        "dashboard": dashboard_result,
        "total_failed_findings": len(normalized),
        "ai_attempted": len(analyzed),
        "ai_analyzed": ai_successful,
        "ai_errors": ai_errors,
        "ai_skipped": ai_skipped,
        "remediation_plans": len(plans),
        "reports": {
            "csv": str(report_dir / "findings.csv"),
            "xlsx": str(report_dir / "findings.xlsx"),
            "html": str(report_dir / "report.html"),
            "json": str(root / "ai/analysis.json"),
            "normalized_json": str(root / "normalized/findings.json"),
            "remediation": str(root / "remediation/plans.json"),
        },
    }
    storage.write_json(root / "metadata.json", result)
    return result
