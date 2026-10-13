
"""CSPM scan pipeline.

Flow:
Prowler -> Parser -> Risk -> Gemini -> Policy -> Reports

This module creates remediation review plans only.
It does not execute AWS remediation.
"""

from . import gemini, parser, prowler, reporting, storage
from .policy import build_plan, evaluate
from .risk import priority


def run_scan(region, limit=20, check=None):
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
    analyzed = []
    plans = []

    selected_findings = normalized[:limit]

    for original_finding in selected_findings:
        # Work on a copy so the normalized finding data remains unchanged.
        finding = dict(original_finding)

        try:
            analysis = gemini.analyze(finding)

            if not isinstance(analysis, dict):
                raise ValueError(
                    "Gemini analysis must return a dictionary."
                )

            finding.update(analysis)
            finding["ai_status"] = "OK"

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
                plan = build_plan(
                    finding,
                    analysis,
                    decision,
                )
                plans.append(plan)

        except Exception as exc:
            # Keep the scan findings even if AI or policy processing fails.
            finding["ai_status"] = "ERROR"
            finding["ai_error"] = (
                f"{type(exc).__name__}: {exc}"
            )

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

    # 7. Calculate accurate AI statistics.
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
