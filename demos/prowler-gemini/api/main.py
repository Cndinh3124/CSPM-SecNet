from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ai.gemini_client import GeminiAnalyzer


app = FastAPI(
    title="SecNet CSPM AI API",
    version="1.0.0",
)


analyzer = GeminiAnalyzer()


class FindingRequest(BaseModel):

    check_id: str

    status: str

    severity: str = ""

    service: str = ""

    resource_id: str = ""

    resource_type: str = ""

    region: str = ""

    title: str = ""

    message: str = ""


@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "secnet-cspm-ai",
    }


@app.post("/api/v1/ai/analyze")
def analyze(
    request: FindingRequest,
):

    try:

        result = analyzer.analyze(
            request.model_dump()
        )

        return {
            "finding": request.model_dump(),
            "analysis": result.model_dump(),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )
