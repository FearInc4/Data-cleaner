"""One place that wires config, encryption, database and the broker catalog."""

from __future__ import annotations

import logging
import os

from .config import Config
from .crypto import Vault, set_vault
from .db import init_engine, session_scope

log = logging.getLogger(__name__)

_config: Config | None = None


def init(config: Config | None = None, *, sync_catalog: bool = True) -> Config:
    global _config
    config = config or Config()
    # Database, WAL files and key file hold personal data: owner-only by default.
    os.umask(0o077)
    config.ensure_dirs()
    if config.secret_key:
        vault = Vault.from_secret(config.secret_key)
    else:
        vault = Vault.from_key_file(config.key_file)
    set_vault(vault)
    init_engine(config.db_url)
    if sync_catalog:
        from .brokers import sync_catalog as _sync

        with session_scope() as session:
            stats = _sync(session)
            log.info("Broker catalog synced: %s", stats)
        if config.searxng_url:
            from .settings import Settings

            with session_scope() as session:
                s = Settings(session)
                if not s.searxng_url:
                    s.set("searxng_url", config.searxng_url)
    _config = config
    return config


def get_config() -> Config:
    if _config is None:
        raise RuntimeError("datacleaner.app_state.init() has not been called")
    return _config


# --- first-run claim token ------------------------------------------------------
# Until the first account exists, anyone who can reach the server could claim it.
# The setup page therefore needs a one-time token that only someone with access
# to the server's console or data directory can read.

def _token_path() -> "os.PathLike[str]":
    return get_config().data_dir / "setup-token"


def ensure_setup_token(session) -> str | None:
    """Create (or return) the setup token while no user exists; remove it afterwards."""
    from sqlalchemy import func, select

    from .models import User

    path = _token_path()
    if (session.scalar(select(func.count()).select_from(User)) or 0) > 0:
        if path.exists():
            path.unlink()
        return None
    if path.exists():
        return path.read_text().strip()
    import secrets

    token = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return token


def check_setup_token(session, given: str | None) -> bool:
    import hmac

    expected = ensure_setup_token(session)
    return bool(expected and given and hmac.compare_digest(expected, given.strip()))


def clear_setup_token() -> None:
    path = _token_path()
    if path.exists():
        path.unlink()
