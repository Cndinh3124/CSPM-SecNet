from typing import Any

from . import dashboard, gemini, parser, prowler, reporting, storage
from .policy import build_remediation_plan, evaluate
from .risk import priority


def run_scan(region: str, limit: int = 20, check: str | None = None):
    """Run a CSPM scan and generate findings, AI analysis and reports.

    Args:
        region: AWS region to scan.
        limit: Maximum number of findings sent for AI analysis.
        check: Optional Prowler check ID.

    Returns:
        Dictionary containing scan metadata and report paths.
    """

    if not isinstance(region, str) or not region.strip():
        raise ValueError("region must be a non-empty string.")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer.")

    sid = storage.new_scan_id()
    root = storage.scan_dir(sid)
    out = root / "prowler"

    # 1. Run Prowler.
    prowler.run(
        region,
        out,
        check=check,
    )
    try:
        dashboard_result = dashboard.sync_scan_csv(out)
    except Exception as exc:
        dashboard_result = {
            "status": "ERROR",
            "reason": type(exc).__name__,
            "files_copied": 0,
        }

    # 2. Parse findings.
    findings = parser.parse_directory(
        out,
        sid,
        region,
    )

    # 3. Assign risk priorities.
    normalized = []

    for finding in findings:
        finding["priority"] = priority(finding)
        normalized.append(finding)

    storage.write_json(
        root / "normalized/findings.json",
        normalized,
    )

    # 4. Analyze a bounded number of findings.
    analyzed: list[dict[str, Any]] = []
    plans: list[dict[str, Any]] = []

    selected_findings = normalized[:limit]

    for original_finding in selected_findings:
        # Work on a copy so normalized findings remain unchanged.
        finding = dict(original_finding)

        # 4a. AI analysis is an advisory step.
        try:
            analysis = gemini.analyze(finding)

            if not isinstance(analysis, dict):
                raise TypeError(
                    "Gemini analysis must return a dictionary."
                )

        except Exception as exc:  # noqa: BLE001
            # Intentional exception boundary around the external AI call:
            # preserve the finding but do not create a remediation plan.
            finding["ai_status"] = "ERROR"
            finding["ai_error"] = type(exc).__name__
            analyzed.append(finding)
            continue

        finding.update(analysis)
        finding["ai_status"] = "OK"

        # 4b. Policy evaluation and plan creation are separate from AI.
        try:
            decision = evaluate(
                finding,
                analysis,
            )

            finding["policy_decision"] = {
                "allowed": decision.allowed,
                "approval_required": decision.approval_required,
                "action": decision.action,
                "reason": decision.reason,
            }

            if decision.allowed:
                plan = build_remediation_plan(
                    decision,
                    finding,
                    analysis,
                )
                plans.append(plan)

        except (TypeError, ValueError) as exc:
            # Invalid policy input or plan data must never produce a plan.
            finding["policy_status"] = "ERROR"
            finding["policy_error"] = type(exc).__name__

        analyzed.append(finding)

    # 5. Persist normalized AI results and review plans.
    storage.write_json(
        root / "ai/analysis.json",
        analyzed,
    )

    storage.write_json(
        root / "remediation/plans.json",
        plans,
    )

    # 6. Generate reports.
    report_dir = storage.REPORT_ROOT / sid

    reporting.write_csv(
        report_dir / "findings.csv",
        analyzed,
    )

    reporting.write_xlsx(
        report_dir / "findings.xlsx",
        analyzed,
    )

    reporting.write_html(
        report_dir / "report.html",
        analyzed,
    )

    # 7. Calculate AI statistics.
    ai_successful = sum(
        finding.get("ai_status") == "OK"
        for finding in analyzed
    )

    ai_errors = sum(
        finding.get("ai_status") == "ERROR"
        for finding in analyzed
    )

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
            "remediation": str(root / "remediation/plans.json"),
        },
    }


    storage.write_json(
        root / "metadata.json",
        result,
    )

    return result
