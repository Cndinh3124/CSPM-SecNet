from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.api.auth import router as auth_router


app = FastAPI(
    title="SecNet CSPM API",
    version="1.0.0",
    description="Cloud Security Posture Management control-plane API",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    router,
    prefix="/api/v1",
)

app.include_router(
    auth_router,
    prefix="/api/v1",
)


@app.get(
    "/health",
    tags=["system"],
)
def health():
    return {
        "status": "ok",
        "service": "secnet-cspm-api",
        "version": "1.0.0",
    }