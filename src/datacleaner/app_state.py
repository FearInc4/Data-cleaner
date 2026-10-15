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
