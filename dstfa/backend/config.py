from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parent
_ENV_FILE = _BACKEND_ROOT / ".env"


class Settings(BaseSettings):
    # Optional until LLM phase; set in backend/.env for Gemini calls.
    GEMINI_API_KEY: str = ""
    APP_ENV: str = "development"
    ALLOWED_ORIGINS: str = "http://localhost:3000"
    MAX_FILE_SIZE_MB: int = 20
    SANDBOX_TIMEOUT_SECONDS: int = 10
    DNS_RESOLVER: str = "8.8.8.8"

    model_config = SettingsConfigDict(env_file=_ENV_FILE)


settings = Settings()
