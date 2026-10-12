
import json
import os
import random
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


SYSTEM_INSTRUCTION = """Bạn là Senior AWS Security Engineer hỗ trợ một hệ thống CSPM.

Phân tích security finding được cung cấp và trả kết quả PHÂN TÍCH BẰNG TIẾNG VIỆT.

QUY TẮC:
1. Chỉ sử dụng dữ liệu trong finding. Không tự tạo AWS state.
2. Phân biệt FACT, INFERENCE và UNKNOWN trong assumptions hoặc nội dung phân tích khi cần.
3. Không gọi AWS API và không thực hiện thay đổi hạ tầng.
4. Recommendation của bạn chỉ là tư vấn, không phải authorization.
5. Không tự quyết định production scope.
6. Nếu thiếu dữ liệu để xác định remediation an toàn, chọn MANUAL hoặc REVIEW_REQUIRED.
7. Các enum phải giữ nguyên tiếng Anh: SAFE, REVIEW_REQUIRED, MANUAL.
8. Trả về JSON hợp lệ, không Markdown.

Phân tích phải bao gồm:
- summary: lỗi gì và evidence chính.
- root_cause: nguyên nhân kỹ thuật.
- impact: tác động bảo mật và vận hành.
- recommended_remediation: cách khắc phục ưu tiên.
- remediation_plan: target, action, expected_change, risk, rollback.
- auto_remediation: SAFE | REVIEW_REQUIRED | MANUAL.
- verification_steps: cách xác minh sau remediation.
- confidence: 0..1.
- assumptions: các giả định hoặc thông tin còn thiếu.
"""


REQUIRED_FIELDS = {
    "summary",
    "root_cause",
    "impact",
    "recommended_remediation",
    "remediation_plan",
    "auto_remediation",
    "verification_steps",
    "confidence",
    "assumptions",
}

VALID_REMEDIATION_MODES = {
    "SAFE",
    "REVIEW_REQUIRED",
    "MANUAL",
}

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _is_retryable_error(exc: Exception) -> bool:
    """Determine whether a Gemini API error may be temporary."""
    code = getattr(exc, "code", None)

    if code in RETRYABLE_STATUS_CODES:
        return True

    error_text = str(exc).lower()

    retryable_markers = (
        "429",
        "500 internal",
        "502",
        "503",
        "504",
        "resource_exhausted",
        "unavailable",
        "deadline exceeded",
        "high demand",
        "temporarily unavailable",
    )

    return any(marker in error_text for marker in retryable_markers)


def analyze(finding: dict) -> dict:
    """Analyze one CSPM finding with Gemini.

    Gemini provides recommendations only. It does not authorize or execute
    AWS remediation.
    """
    key = os.getenv("GEMINI_API_KEY")

    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    client = genai.Client(api_key=key)

    prompt = f"""{SYSTEM_INSTRUCTION}

Security finding:
{json.dumps(finding, ensure_ascii=False, indent=2)}

Schema JSON bắt buộc:
{{
  "summary": "string",
  "root_cause": "string",
  "impact": "string",
  "recommended_remediation": "string",
  "remediation_plan": {{
    "target_type": "string",
    "target_id": "string",
    "action": "string",
    "expected_change": "string",
    "risk": "string",
    "rollback": "string"
  }},
  "auto_remediation": "SAFE | REVIEW_REQUIRED | MANUAL",
  "verification_steps": ["string"],
  "confidence": 0.0,
  "assumptions": ["string"]
}}

Chỉ trả về một JSON object hợp lệ. Không thêm Markdown hoặc nội dung bên ngoài JSON.
"""

    response = None

    # Retry tối đa 3 lần cho lỗi tạm thời.
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ),
            )
            break

        except Exception as exc:
            if not _is_retryable_error(exc) or attempt == 2:
                raise

            # Chờ tăng dần, thêm jitter để giảm retry đồng thời.
            delay = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(delay)

    if response is None or not response.text:
        raise RuntimeError("Gemini returned an empty response")

    try:
        result = json.loads(response.text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Gemini returned invalid JSON"
        ) from exc

    if not isinstance(result, dict):
        raise ValueError("Gemini response must be a JSON object")

    missing_fields = REQUIRED_FIELDS - result.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise ValueError(
            f"Gemini response is missing required fields: {missing}"
        )

    if result["auto_remediation"] not in VALID_REMEDIATION_MODES:
        raise ValueError("Invalid auto_remediation value")

    if not isinstance(result["remediation_plan"], dict):
        raise ValueError("remediation_plan must be a JSON object")

    if not isinstance(result["verification_steps"], list):
        raise ValueError("verification_steps must be a JSON array")

    if not isinstance(result["assumptions"], list):
        raise ValueError("assumptions must be a JSON array")

    confidence = result["confidence"]

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise ValueError("confidence must be a number between 0 and 1")

    result["model"] = model
    return result
