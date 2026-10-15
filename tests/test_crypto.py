import os
import stat

import pytest

from datacleaner.crypto import DecryptionError, Vault
from datacleaner.security import hash_password, verify_password


def test_key_file_created_private(tmp_path):
    path = tmp_path / "secret.key"
    v1 = Vault.from_key_file(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    v2 = Vault.from_key_file(path)
    assert v2.decrypt(v1.encrypt("hello")) == "hello"


def test_passphrase_and_wrong_key():
    v = Vault.from_secret("a long deployment passphrase")
    token = v.encrypt_json({"a": 1})
    assert Vault.from_secret("a long deployment passphrase").decrypt_json(token) == {"a": 1}
    with pytest.raises(DecryptionError):
        Vault.from_secret("another passphrase").decrypt(token)
    assert v.derive("session") != v.derive("other")


def test_password_hashing():
    h = hash_password("hunter2hunter2")
    assert verify_password("hunter2hunter2", h)
    assert not verify_password("hunter3hunter3", h)
    assert not verify_password("x", "garbage")
