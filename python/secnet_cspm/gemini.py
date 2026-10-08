import json
import os
from typing import Any

try:
    from google import genai
    from google.genai import types
except ImportError as exc:
    raise RuntimeError(
        "google-genai is required. Install it with: pip install google-genai"
    ) from exc

DEFAULT_MODEL = "gemini-2.5-flash"

def _client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    return genai.Client(api_key=api_key)

def analyze_finding(
    finding: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    client = _client()
    model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
    payload = {
        "finding": finding,
        "context": context or {},
        "rules": {
            "ai_is_advisor_only": True,
            "must_not_execute_aws_changes": True,
            "must_not_upgrade_remediation_privilege": True,
            "unknown_context_requires_manual_review": True,
        },
    }
    prompt = f"""
You are a cloud security analyst assisting a CSPM platform.
Analyze the following AWS security finding.

Return ONLY valid JSON with these keys:
summary, root_cause, impact, recommended_remediation,
auto_remediation, verification_steps, confidence, assumptions.

Rules:
- Do not invent AWS resource facts not present in the input.
- Treat scanner evidence as authoritative for whether the control failed.
- You are an advisor. Never claim that you executed an AWS change.
- auto_remediation must contain allowed (boolean) and reason (string).
- If changing the resource could interrupt access or availability, recommend manual approval.
- confidence must be a number from 0.0 to 1.0.

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )
    text = (response.text or "").strip()
    if not text:
        raise RuntimeError("Gemini returned an empty response")
    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Gemini returned invalid JSON: {text[:1000]}"
        ) from exc
    result["model"] = model
    return result
