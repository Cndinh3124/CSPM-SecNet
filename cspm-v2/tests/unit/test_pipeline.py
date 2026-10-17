from secnet_cspm.pipeline import _merge_analysis_into_all_findings, _rank_findings


def test_rank_findings_puts_high_risk_public_resources_first():
    findings = [
        {"control_id": "low", "severity": "LOW", "title": "Unused setting", "resource_id": "a"},
        {"control_id": "high", "severity": "HIGH", "title": "Public resource exposed to internet", "resource_id": "b"},
        {"control_id": "medium", "severity": "MEDIUM", "title": "Missing configuration", "resource_id": "c"},
    ]

    ranked = _rank_findings(findings)

    assert [item["control_id"] for item in ranked] == ["high", "medium", "low"]
    assert ranked[0]["priority"] == "P1"


def test_merge_analysis_keeps_all_findings_and_marks_unanalyzed():
    findings = [
        {"fingerprint": "a", "control_id": "first", "priority": "P1"},
        {"fingerprint": "b", "control_id": "second", "priority": "P2"},
    ]
    analyzed = [
        {"fingerprint": "a", "control_id": "first", "ai_status": "OK", "summary": "Reviewed"},
    ]

    merged = _merge_analysis_into_all_findings(findings, analyzed)

    assert len(merged) == 2
    assert merged[0]["summary"] == "Reviewed"
    assert merged[0]["ai_status"] == "OK"
    assert merged[1]["ai_status"] == "SKIPPED"
