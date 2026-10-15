"""Process-level configuration, read from environment variables.

Runtime-tunable settings (SMTP credentials, API keys, follow-up cadence) live in
the database and are edited from the Settings page; see ``datacleaner.settings``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("DATACLEANER_DATA_DIR", "./data")))
    database_url: str | None = field(default_factory=lambda: os.environ.get("DATACLEANER_DATABASE_URL"))
    secret_key: str | None = field(default_factory=lambda: os.environ.get("DATACLEANER_SECRET_KEY"))
    host: str = field(default_factory=lambda: os.environ.get("DATACLEANER_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("DATACLEANER_PORT", "8080")))
    # Run the scheduler loop inside the web process. Turn off if you drive
    # `datacleaner tick` from cron/systemd instead.
    scheduler_enabled: bool = field(default_factory=lambda: _bool(os.environ.get("DATACLEANER_SCHEDULER"), True))
    scheduler_interval_seconds: int = field(
        default_factory=lambda: int(os.environ.get("DATACLEANER_SCHEDULER_INTERVAL", "300"))
    )
    # Mark session cookies Secure. Enable when serving over HTTPS.
    secure_cookies: bool = field(default_factory=lambda: _bool(os.environ.get("DATACLEANER_SECURE_COOKIES"), False))
    # Default SearXNG URL; docker-compose points this at the bundled container.
    searxng_url: str | None = field(default_factory=lambda: os.environ.get("DATACLEANER_SEARXNG_URL"))

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'datacleaner.db').resolve()}"

    @property
    def key_file(self) -> Path:
        return self.data_dir / "secret.key"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
