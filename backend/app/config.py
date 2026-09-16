"""
MAILTRACE AI - Core Application Configuration.
Uses pydantic-settings to manage environment variables with sensible local defaults.
"""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MAILTRACE AI"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api"

    # Database: SQLite default for zero-dependency local execution
    DATABASE_URL: str = "sqlite:///./mailtrace.db"

    # CORS origins: support comma-separated string or list of URLs
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Optional Threat Intelligence placeholders
    MAXMIND_DB_PATH: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # AI / ML Threat Detection Model (Dataset 3 Fine-Tuned DistilBERT)
    MODEL_PATH: str = "ml/models/dataset3_v1.0.0"
    MODEL_MAX_LENGTH: int = 384

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


settings = Settings()
