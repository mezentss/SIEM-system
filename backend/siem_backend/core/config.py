from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SIEM Backend"
    api_prefix: str = "/api"
    log_level: str = "INFO"

    database_url: str = "sqlite:///./siem.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SIEM_",
        extra="ignore",
    )


settings = Settings()
