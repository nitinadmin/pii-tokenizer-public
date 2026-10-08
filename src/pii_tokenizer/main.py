"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pii_tokenizer.config import settings
from pii_tokenizer.routers.pipeline import router as pipeline_router

app = FastAPI(
    title="PII Tokenization Pipeline",
    description=(
        "Security-first document processing with PII tokenization, validation, "
        "and an LLM-safe processing boundary."
    ),
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    # The API uses no cookies; credentialed cross-origin requests are not needed.
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.include_router(pipeline_router)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Return a lightweight liveness response."""
    return {"status": "ok"}


def run() -> None:
    """Run the development server."""
    import uvicorn

    uvicorn.run("pii_tokenizer.main:app", host="0.0.0.0", port=8000)
