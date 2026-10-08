from . import gemini, parser, prowler, reporting, storage
from .policy import build_plan, evaluate
from .risk import priority


def run_scan(region, limit=20):
    sid = storage.new_scan_id()
    root = storage.scan_dir(sid)
    out = root / "prowler"

    prowler.run(region, out)
    findings = parser.parse_directory(out, sid, region)

    normalized = []
    for finding in findings:
        finding["priority"] = priority(finding)
        normalized.append(finding)

    storage.write_json(root / "normalized/findings.json", normalized)

    analyzed = []
    plans = []
    for finding in normalized[:limit]:
        try:
            analysis = gemini.analyze(finding)
            finding.update(analysis)
            finding["ai_status"] = "OK"

            decision = evaluate(finding, analysis)
            finding["policy_decision"] = {
                "allowed": decision.allowed,
                "approval_required": decision.approval_required,
                "action": decision.action,
                "reason": decision.reason,
            }
            if decision.allowed:
                plans.append(build_plan(finding, analysis, decision))
        except Exception as exc:
            finding["ai_status"] = "ERROR"
            finding["ai_error"] = str(exc)
        analyzed.append(finding)

    storage.write_json(root / "ai/analysis.json", analyzed)
    storage.write_json(root / "remediation/plans.json", plans)

    report_dir = storage.REPORT_ROOT / sid
    reporting.write_csv(report_dir / "findings.csv", analyzed)
    reporting.write_xlsx(report_dir / "findings.xlsx", analyzed)
    reporting.write_html(report_dir / "report.html", analyzed)

    result = {
        "scan_id": sid,
        "region": region,
        "total_failed_findings": len(normalized),
        "ai_analyzed": len(analyzed),
        "remediation_plans": len(plans),
        "reports": {
            "csv": str(report_dir / "findings.csv"),
            "xlsx": str(report_dir / "findings.xlsx"),
            "html": str(report_dir / "report.html"),
            "json": str(root / "ai/analysis.json"),
            "remediation": str(root / "remediation/plans.json"),
        },
    }
    storage.write_json(root / "metadata.json", result)
    return result
