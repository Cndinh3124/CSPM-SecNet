from google import genai
from google.genai import types

from .config import get_settings
from .prompts import build_finding_prompt
from .schemas import FindingAnalysis


class GeminiAnalyzer:

    def __init__(self):
        self.settings = get_settings()

        self.client = genai.Client(
            api_key=self.settings.api_key
        )

    def analyze(self, finding: dict) -> FindingAnalysis:

        response = self.client.models.generate_content(
            model=self.settings.model,
            contents=build_finding_prompt(finding),
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=FindingAnalysis,
            ),
        )

        return FindingAnalysis.model_validate_json(
            response.text
        )
