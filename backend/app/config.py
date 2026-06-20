from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Gemini
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    # Coral bridge (new)
    coral_bridge_url: str = ""          # e.g. http://127.0.0.1:8787
    coral_bridge_token: str = ""        # x-coral-bridge-token header

    # Coral legacy endpoint
    coral_endpoint: str = ""            # direct Coral HTTP endpoint
    coral_api_key: str = ""             # Bearer token for legacy endpoint

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
