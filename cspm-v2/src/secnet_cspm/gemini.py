import json
import os

from google import genai
from google.genai import types


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


def analyze(finding):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
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
"""

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )
    result = json.loads(response.text)
    result["model"] = model
    return result
