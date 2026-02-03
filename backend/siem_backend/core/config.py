from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SIEM Backend"
    api_prefix: str = "/api"
    log_level: str = "INFO"

    database_url: str = "sqlite:///./siem.db"

    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SIEM_",
        extra="ignore",
    )


settings = Settings()