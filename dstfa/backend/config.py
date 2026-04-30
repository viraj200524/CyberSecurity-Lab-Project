from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parent
_ENV_FILE = _BACKEND_ROOT / ".env"


class Settings(BaseSettings):
    # Optional until LLM phase; set in backend/.env for Groq (https://console.groq.com/docs/models).
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    APP_ENV: str = "development"
    ALLOWED_ORIGINS: str = "http://localhost:3000"
    MAX_FILE_SIZE_MB: int = 20
    SANDBOX_TIMEOUT_SECONDS: int = 10
    DNS_RESOLVER: str = "8.8.8.8"

    # Ignore unknown keys in .env (e.g. legacy GEMINI_API_KEY) so startup does not fail.
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")


settings = Settings()
