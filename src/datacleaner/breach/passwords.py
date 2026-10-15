"""Pwned Passwords k-anonymity check.

Only the first five hex characters of the password's SHA-1 leave this machine.
The password itself is never stored or logged.
"""

from __future__ import annotations

import hashlib

import httpx

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def pwned_count(password: str, client: httpx.Client | None = None) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - protocol requires SHA-1
    prefix, suffix = digest[:5], digest[5:]
    own = client is None
    client = client or httpx.Client(timeout=20)
    try:
        resp = client.get(RANGE_URL.format(prefix=prefix), headers={"Add-Padding": "true"})
        resp.raise_for_status()
    finally:
        if own:
            client.close()
    for line in resp.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            n = int(count.strip() or 0)
            if n > 0:  # padding entries have a count of 0
                return n
    return 0
