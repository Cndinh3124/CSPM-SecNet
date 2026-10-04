import json
from pathlib import Path

from .gemini_client import GeminiAnalyzer
from .prowler_parser import (
    find_latest_csv,
    load_findings,
)


def analyze_csv(
    csv_path: str,
    output_dir: str,
    limit: int = 20,
    check_id: str = None,
    resource_id: str = None,
    status: str = "FAIL",
):

    findings = load_findings(
    csv_path,
    status=status,
    limit=limit,
    check_id=check_id,
    resource_id=resource_id,
)

    analyzer = GeminiAnalyzer()

    results = []

    for finding in findings:

        try:

            analysis = analyzer.analyze(
                finding
            )

            results.append(
                {
                    "finding": finding,
                    "ai_analysis": analysis.model_dump(),
                }
            )

        except Exception as exc:

            results.append(
                {
                    "finding": finding,
                    "error": str(exc),
                }
            )

    Path(output_dir).mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        Path(output_dir)
        / "ai-analysis.json"
    )

    output_file.write_text(
        json.dumps(
            results,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return output_file, results


def analyze_latest(
    scan_dir: str,
    output_dir: str,
    limit: int = 20,
):

    csv_path = find_latest_csv(
        scan_dir
    )

    return analyze_csv(
        str(csv_path),
        output_dir,
        limit,
    )
