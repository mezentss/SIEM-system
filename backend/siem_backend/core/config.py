from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SIEM Backend"
    api_prefix: str = "/api"
    log_level: str = "INFO"

    # База данных (PostgreSQL для многопользовательского доступа)
    # Формат: postgresql+psycopg2://user:password@host:port/dbname
    database_url: str = "postgresql+psycopg2://siem_user:siem_password@localhost:5432/siem_db"

    # Настройки пула соединений
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800  # 30 минут

    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SIEM_",
        extra="ignore",
    )

    @property
    def is_postgresql(self) -> bool:
        """Проверяет, используется ли PostgreSQL."""
        return self.database_url.startswith("postgresql")

    @property
    def is_sqlite(self) -> bool:
        """Проверяет, используется ли SQLite (для локальной разработки)."""
        return self.database_url.startswith("sqlite")


settings = Settings()