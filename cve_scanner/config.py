from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ANTHROPIC_API_KEY: str | None = None
    GROQ_API_KEY: str | None = None
    GROQ_MODEL: str = "llama-3.1-70b-versatile"
    GROQ_API_URL: str = "https://api.groq.com/openai/v1/chat/completions"
    TRIVY_PATH: str = "trivy"
    SEMGREP_PATH: str = "semgrep"
    DB_PATH: str = "./scanner.db"
    REPORT_OUTPUT_DIR: str = "./reports"
    EPSS_API_URL: str = "https://api.first.org/data/1.0/epss"
    KEV_FEED_URL: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    KEV_CACHE_TTL_HOURS: int = 12
    CVE_CACHE_TTL_HOURS: int = 24
    LOG_LEVEL: str = "INFO"
    HTTP_TIMEOUT_SECONDS: int = 10
    HTTP_RETRY_COUNT: int = 2
    RUN_TESTS: bool = False
    SANDBOX_TIMEOUT: int = 120
    BREAKING_CHANGES_DB: str = "./data/breaking_changes_db.yaml"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
