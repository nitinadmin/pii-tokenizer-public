"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    """Runtime configuration.

    Credentials are intentionally not required at import time. In production,
    prefer the AWS SDK credential chain (IAM roles, workload identity, or
    environment variables) over long-lived access keys.
    """

    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_SESSION_TOKEN: str = os.getenv("AWS_SESSION_TOKEN", "")
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "pii-tokenizer-data")
    S3_VAULT_BUCKET_NAME: str = os.getenv(
        "S3_VAULT_BUCKET_NAME", "pii-tokenizer-tokenvault"
    )

    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv(
        "ANTHROPIC_MODEL", "claude-sonnet-5-5"
    )

    GUARDDUTY_FAIL_OPEN: bool = _env_bool("GUARDDUTY_FAIL_OPEN", False)
    GUARDDUTY_MAX_WAIT: int = int(os.getenv("GUARDDUTY_MAX_WAIT", "60"))

    STRICT_VALIDATION: bool = _env_bool("STRICT_VALIDATION", True)
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    UPLOAD_TTL_SECONDS: int = int(os.getenv("UPLOAD_TTL_SECONDS", "3600"))

    # Bucket creation should be explicit in production.
    AUTO_CREATE_BUCKETS: bool = _env_bool("AUTO_CREATE_BUCKETS", False)

    LOG_DIR: Path = Path(os.getenv("LOG_DIR", "./logs"))
    CORS_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
        if origin.strip()
    ]

    def __init__(self) -> None:
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
