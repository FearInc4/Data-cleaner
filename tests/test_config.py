"""Process configuration for container stacks: secret files, proxies, the data folder."""

import os
import stat
import sys

import pytest

from datacleaner import app_state
from datacleaner.app_state import DataDirError
from datacleaner.config import Config


def test_secrets_can_come_from_files(tmp_path, monkeypatch):
    key = tmp_path / "secret_key"
    key.write_text("from-a-docker-secret\n")
    monkeypatch.setenv("DATACLEANER_SECRET_KEY_FILE", str(key))
    monkeypatch.setenv("DATACLEANER_GOOGLE_CLIENT_SECRET", "plain-env-wins")
    gfile = tmp_path / "g"
    gfile.write_text("ignored")
    monkeypatch.setenv("DATACLEANER_GOOGLE_CLIENT_SECRET_FILE", str(gfile))
    cfg = Config(data_dir=tmp_path)
    assert cfg.secret_key == "from-a-docker-secret"
    assert cfg.google_client_secret == "plain-env-wins"


def test_unreadable_secret_file_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv("DATACLEANER_SECRET_KEY_FILE", str(tmp_path / "missing"))
    with pytest.raises(SystemExit, match="Can.t read DATACLEANER_SECRET_KEY_FILE.*chown"):
        Config(data_dir=tmp_path)


def test_trusted_proxies(monkeypatch, tmp_path):
    assert Config(data_dir=tmp_path).trusted_proxies is None
    monkeypatch.setenv("DATACLEANER_TRUSTED_PROXIES", "172.16.0.0/12")
    assert Config(data_dir=tmp_path).trusted_proxies == "172.16.0.0/12"


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_unwritable_data_folder_explains_the_fix(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    data.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(DataDirError, match="chown"):
            app_state.init(Config(data_dir=data, scheduler_enabled=False), sync_catalog=False)
    finally:
        data.chmod(stat.S_IRWXU)


def test_cli_reports_data_folder_errors(monkeypatch, capsys):
    from datacleaner import cli

    def fail(_args):
        raise DataDirError("Data Cleaner can't write to its data folder /data")

    monkeypatch.setattr(cli, "cmd_check_catalog", fail)
    assert cli.main(["check-catalog"]) == 1
    assert "can't write to its data folder" in capsys.readouterr().err


def test_searxng_url_follows_the_compose_file_until_edited_by_hand(tmp_path):
    from datacleaner.db import session_scope
    from datacleaner.settings import Settings

    def start(url):
        app_state.init(Config(data_dir=tmp_path, scheduler_enabled=False, searxng_url=url))
        with session_scope() as session:
            return Settings(session).searxng_url

    def edit(url):
        with session_scope() as session:
            Settings(session).set("searxng_url", url)

    # An install from before the port change: the old compose value, stored without a marker.
    app_state.init(Config(data_dir=tmp_path, scheduler_enabled=False))
    edit("http://searxng:8080")
    assert start("http://searxng:8080") == "http://searxng:8080"  # old compose file kept: still works
    assert start("http://searxng:25328") == "http://searxng:25328"  # new compose file: follows it
    assert start("http://search:9000") == "http://search:9000"  # and any later change
    edit("https://search.example")
    assert start("http://searxng:25328") == "https://search.example"  # typed in Settings: kept


def test_a_hand_set_searxng_url_on_an_old_install_is_kept(tmp_path):
    from datacleaner.db import session_scope
    from datacleaner.settings import Settings

    app_state.init(Config(data_dir=tmp_path, scheduler_enabled=False))
    with session_scope() as session:
        Settings(session).set("searxng_url", "http://my-searxng:8888")
    app_state.init(Config(data_dir=tmp_path, scheduler_enabled=False, searxng_url="http://searxng:25328"))
    with session_scope() as session:
        assert Settings(session).searxng_url == "http://my-searxng:8888"
