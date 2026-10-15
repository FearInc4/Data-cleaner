"""Encryption of PII and secrets at rest.

Everything sensitive (profile PII, SMTP/IMAP passwords, API keys, reply bodies)
is stored as Fernet tokens (AES-128-CBC + HMAC-SHA256). The key comes from
``DATACLEANER_SECRET_KEY`` or, if unset, a key file generated on first run
with mode 0600 inside the data directory.

This protects database files that leak via backups, sync folders or a stolen
disk image without the key. It does not protect against someone who already
has shell access to the running host; nothing local can.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

_vault: "Vault | None" = None


class DecryptionError(Exception):
    pass


class Vault:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)
        self._key = key

    def derive(self, label: str) -> bytes:
        """A separate secret for another purpose (e.g. signing session cookies)."""
        return hmac.new(self._key, label.encode(), hashlib.sha256).digest()

    @classmethod
    def from_secret(cls, secret: str) -> "Vault":
        """Accept a raw Fernet key, or derive one from an arbitrary passphrase."""
        try:
            raw = secret.encode()
            Fernet(raw)
            return cls(raw)
        except (ValueError, TypeError):
            pass
        # Fixed salt is acceptable here: the passphrase is a deployment secret,
        # not a user password, and per-install uniqueness comes from the secret.
        derived = hashlib.scrypt(secret.encode(), salt=b"datacleaner-v1", n=2**14, r=8, p=1, dklen=32)
        return cls(base64.urlsafe_b64encode(derived))

    @classmethod
    def from_key_file(cls, path: Path) -> "Vault":
        if path.exists():
            return cls(path.read_bytes().strip())
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return cls(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise DecryptionError(
                "Could not decrypt stored data. Is DATACLEANER_SECRET_KEY / secret.key the one this database was created with?"
            ) from exc

    def encrypt_json(self, value: Any) -> str:
        return self.encrypt(json.dumps(value, separators=(",", ":")))

    def decrypt_json(self, token: str) -> Any:
        return json.loads(self.decrypt(token))


def set_vault(vault: Vault) -> None:
    global _vault
    _vault = vault


def get_vault() -> Vault:
    if _vault is None:
        raise RuntimeError("Vault not initialised; call datacleaner.app_state.init() first")
    return _vault
