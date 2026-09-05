"""
SentinelAI Configuration Module

Loads application settings from environment variables / .env file.
All configuration is centralized here using Pydantic Settings.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parents[3] / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "SentinelAI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://luzayer:@localhost:5432/sentinelai"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Authentication ---
    JWT_SECRET: str = "change-me"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 1440  # 24 hours

    # --- Ollama LLM ---
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1"

    # --- File Upload ---
    MAX_UPLOAD_SIZE_MB: int = 100
    UPLOAD_DIR: str = "./uploads"
    ALLOWED_IMAGE_EXTENSIONS: str = ".jpg,.jpeg,.png,.gif,.bmp,.tiff,.webp"
    ALLOWED_VIDEO_EXTENSIONS: str = ".mp4,.avi,.mov,.mkv,.webm,.flv"
    ALLOWED_AUDIO_EXTENSIONS: str = ".mp3,.wav,.ogg,.flac,.aac,.m4a"
    ALLOWED_DOCUMENT_EXTENSIONS: str = ".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.rtf"
    ALLOWED_ARCHIVE_EXTENSIONS: str = ".zip,.tar,.gz,.7z,.rar"

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # --- Optional External Intelligence ---
    VIRUSTOTAL_API_KEY: str | None = None
    URLSCAN_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def allowed_extensions(self) -> set[str]:
        """All allowed file extensions combined."""
        all_ext = (
            self.ALLOWED_IMAGE_EXTENSIONS
            + ","
            + self.ALLOWED_VIDEO_EXTENSIONS
            + ","
            + self.ALLOWED_AUDIO_EXTENSIONS
            + ","
            + self.ALLOWED_DOCUMENT_EXTENSIONS
            + ","
            + self.ALLOWED_ARCHIVE_EXTENSIONS
        )
        return {ext.strip().lower() for ext in all_ext.split(",") if ext.strip()}

    @property
    def image_extensions(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_IMAGE_EXTENSIONS.split(",") if ext.strip()}

    @property
    def video_extensions(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_VIDEO_EXTENSIONS.split(",") if ext.strip()}

    @property
    def audio_extensions(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_AUDIO_EXTENSIONS.split(",") if ext.strip()}

    @property
    def document_extensions(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_DOCUMENT_EXTENSIONS.split(",") if ext.strip()}


settings = Settings()
