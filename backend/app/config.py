from pydantic_settings import BaseSettings
from pathlib import Path
import yaml


class Settings(BaseSettings):
    app_name: str = "Home Network Threat & Risk Platform"
    app_version: str = "1.0.0"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///data/risk_platform.db"

    # Paths
    data_dir: Path = Path("data")
    config_dir: Path = Path("config")
    artifacts_dir: Path = Path("data/artifacts")

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # AI Configuration
    ai_provider: str = "ollama"  # ollama or openai-compatible
    ai_base_url: str = "http://localhost:11434"
    ai_model: str = "llama3.2"
    ai_api_key: str = ""

    # Threat Intelligence
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    alienvault_otx_api_key: str = ""
    threat_feed_cache_ttl: int = 3600  # 1 hour
    threat_feed_mode: str = "fallback"  # live, offline, fallback

    # Scanner defaults
    default_scan_rate: int = 100  # packets per second
    scan_timeout: int = 300  # seconds

    class Config:
        env_file = ".env"
        env_prefix = "RISK_"


settings = Settings()


def load_yaml_config(filename: str) -> dict:
    config_path = settings.config_dir / filename
    if config_path.exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}
