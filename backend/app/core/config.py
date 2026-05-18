
# class Settings(BaseSettings):
#     DATABASE_URL: str
#     REDIS_URL: str
#     ELASTIC_URL: str
#     OLLAMA_BASE_URL: str
#     OLLAMA_EMBED_MODEL: str
#     OLLAMA_LLM_MODEL: str
#     SECRET_KEY: str
#     APP_ENV: str = "development"
#     MODEL_PROVIDER: str = "ollama"

#     class Config:
#         env_file = str(ENV_PATH)

# settings = Settings()

from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional

ENV_PATH = Path(__file__).resolve().parents[3] / ".env"

class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    ELASTIC_URL: str
    OLLAMA_BASE_URL: str
    OLLAMA_EMBED_MODEL: str
    OLLAMA_LLM_MODEL: str
    SECRET_KEY: str
    APP_ENV: str = "development"
    MODEL_PROVIDER: str = "ollama"
    SLACK_WEBHOOK_URL: Optional[str] = None   # ← new, optional

    class Config:
        env_file = str(ENV_PATH)

settings = Settings()