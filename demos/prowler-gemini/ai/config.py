import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    max_findings: int
    output_dir: str


def get_settings() -> Settings:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    return Settings(
        api_key=api_key,
        model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash-lite"),
        max_findings=int(os.getenv("AI_MAX_FINDINGS", "20")),
        output_dir=os.getenv("AI_OUTPUT_DIR", "./data"),
    )
