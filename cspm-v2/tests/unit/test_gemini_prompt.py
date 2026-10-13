from secnet_cspm.gemini import SYSTEM_INSTRUCTION, _validate_result


def test_system_instruction_requires_vietnamese_security_analysis():
    assert "Ngôn ngữ bắt buộc: tiếng Việt" in SYSTEM_INSTRUCTION
    assert "Root Cause Analysis" in SYSTEM_INSTRUCTION
    assert "Không gọi AWS API" in SYSTEM_INSTRUCTION
    assert "Cloud Custodian" in SYSTEM_INSTRUCTION
    assert "Output JSON bắt buộc" in SYSTEM_INSTRUCTION


def test_validate_result_preserves_current_schema_and_vietnamese_text():
    result = {
        "summary": "Security Group cho phép SSH từ Internet.",
        "root_cause": "Giả thuyết: rule được mở để quản trị từ xa.",
        "impact": "Tăng bề mặt tấn công.",
        "recommended_remediation": "Giới hạn nguồn truy cập SSH.",
        "remediation_plan": {
            "target": "Chỉ cho phép nguồn quản trị được phê duyệt.",
            "action": "Thu hẹp source CIDR.",
            "expected_change": "Giảm public exposure.",
            "risk": "Có thể mất kết nối quản trị.",
            "rollback": "Khôi phục rule đã được phê duyệt nếu cần.",
        },
        "auto_remediation": "REVIEW_REQUIRED",
        "verification_steps": ["Kiểm tra lại inbound rules.", "Chạy lại Prowler."],
        "confidence": 0.8,
        "assumptions": ["Chưa xác minh đường quản trị thay thế."],
    }

    validated = _validate_result(result)

    assert validated["summary"].startswith("Security Group")
    assert validated["confidence"] == 0.8
    assert validated["auto_remediation"] == "REVIEW_REQUIRED"


def test_validate_result_rejects_invalid_remediation_enum():
    result = {
        "summary": "Tóm tắt",
        "root_cause": "Chưa rõ",
        "impact": "Chưa rõ",
        "recommended_remediation": "Kiểm tra thêm",
        "remediation_plan": {},
        "auto_remediation": "EXECUTE_NOW",
        "verification_steps": [],
        "confidence": 0.5,
        "assumptions": [],
    }

    try:
        _validate_result(result)
    except ValueError as exc:
        assert "auto_remediation" in str(exc)
    else:
        raise AssertionError("Invalid remediation enum must be rejected.")
