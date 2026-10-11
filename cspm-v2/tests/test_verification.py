import csv
import subprocess
from pathlib import Path

from secnet_cspm.verification import verify_public_ssh


CONTROL = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
TARGET = "sg-0b18998e447203ad1"


def fake_prowler(monkeypatch, status, *, returncode=0, include_target=True):
    def run(cmd, text, capture_output):
        output_dir = Path(cmd[cmd.index("--output-directory") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "findings.csv"

        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=["CHECKID", "STATUS", "RESOURCEID", "RESOURCENAME"],
            )
            writer.writeheader()
            if include_target:
                writer.writerow({
                    "CHECKID": CONTROL,
                    "STATUS": status,
                    "RESOURCEID": (
                        f"arn:aws:ec2:ap-southeast-1:392024306192:"
                        f"security-group/{TARGET}"
                    ),
                    "RESOURCENAME": TARGET,
                })
            else:
                writer.writerow({
                    "CHECKID": CONTROL,
                    "STATUS": status,
                    "RESOURCEID": "sg-another-resource",
                    "RESOURCENAME": "sg-another-resource",
                })

        return subprocess.CompletedProcess(
            cmd, returncode, stdout="", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", run)


def test_target_fail(monkeypatch, tmp_path):
    fake_prowler(monkeypatch, "FAIL")
    result = verify_public_ssh("ap-southeast-1", CONTROL, tmp_path, TARGET)
    assert result["status"] == "FAIL"
    assert result["failed_findings"] == 1


def test_target_pass(monkeypatch, tmp_path):
    fake_prowler(monkeypatch, "PASS")
    result = verify_public_ssh("ap-southeast-1", CONTROL, tmp_path, TARGET)
    assert result["status"] == "PASS"


def test_missing_target_is_inconclusive(monkeypatch, tmp_path):
    fake_prowler(monkeypatch, "PASS", include_target=False)
    result = verify_public_ssh("ap-southeast-1", CONTROL, tmp_path, TARGET)
    assert result["status"] == "INCONCLUSIVE"


def test_scan_error_is_inconclusive(monkeypatch, tmp_path):
    fake_prowler(monkeypatch, "PASS", returncode=2)
    result = verify_public_ssh("ap-southeast-1", CONTROL, tmp_path, TARGET)
    assert result["status"] == "INCONCLUSIVE"
