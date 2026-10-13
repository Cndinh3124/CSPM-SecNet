import csv

from secnet_cspm.dashboard import sync_scan_csv


def write_prowler_csv(path):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["CHECK_ID", "STATUS", "TIMESTAMP"],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerow({
            "CHECK_ID": "example_check",
            "STATUS": "FAIL",
            "TIMESTAMP": "2026-10-13T00:00:00",
        })


def test_sync_skips_when_not_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("PROWLER_DASHBOARD_DIR", raising=False)
    monkeypatch.delenv("PROWLER_DASHBOARD_OUTPUT_DIR", raising=False)

    result = sync_scan_csv(tmp_path)

    assert result["status"] == "SKIPPED"
    assert result["files_copied"] == 0


def test_sync_copies_valid_csv(tmp_path, monkeypatch):
    prowler_checkout = tmp_path / "prowler"
    scan_dir = tmp_path / "scan" / "prowler"
    dashboard_output = prowler_checkout / "output"

    prowler_checkout.mkdir()
    scan_dir.mkdir(parents=True)
    source = scan_dir / "findings.csv"
    write_prowler_csv(source)

    monkeypatch.setenv(
        "PROWLER_DASHBOARD_DIR", str(prowler_checkout)
    )
    monkeypatch.setenv(
        "PROWLER_DASHBOARD_OUTPUT_DIR", str(dashboard_output)
    )

    result = sync_scan_csv(scan_dir)

    assert result["status"] == "SYNCED"
    assert result["files_copied"] == 1
    assert (dashboard_output / "findings.csv").exists()


def test_sync_rejects_wrong_output_directory(tmp_path, monkeypatch):
    prowler_checkout = tmp_path / "prowler"
    scan_dir = tmp_path / "scan"
    prowler_checkout.mkdir()
    scan_dir.mkdir()

    monkeypatch.setenv(
        "PROWLER_DASHBOARD_DIR", str(prowler_checkout)
    )
    monkeypatch.setenv(
        "PROWLER_DASHBOARD_OUTPUT_DIR", str(tmp_path / "wrong")
    )

    result = sync_scan_csv(scan_dir)

    assert result["status"] == "ERROR"
    assert result["files_copied"] == 0
