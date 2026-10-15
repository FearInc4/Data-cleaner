"""Per-broker email aliases.

Every broker gets its own address, e.g. ``jane+dc-spokeo-1@gmail.com``:

- Replies and web-form confirmation emails are matched to the right request
  just by looking at who they were sent to.
- If spam later arrives at ``+dc-spokeo-1``, you know who leaked or sold it.

Modes:
- ``plus``: sub-addressing on your own mailbox (Gmail, Outlook/Microsoft 365,
  iCloud, Fastmail, Proton, Google Workspace and most custom domains).
- ``catchall``: ``dc-spokeo-1@yourdomain`` for a domain whose catch-all delivers
  to the connected mailbox.
- ``off``: just use your address.
"""

from __future__ import annotations

import re

# Providers known not to deliver plus-addressed mail.
NO_PLUS_DOMAINS = {"yahoo.com", "ymail.com", "rocketmail.com", "aol.com", "aim.com"}
_TAG = re.compile(r"dc-([a-z0-9-]+)-(\d+)$")
MAX_LOCAL = 64


def supports_plus(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return not (domain in NO_PLUS_DOMAINS or domain.startswith("yahoo."))


def make_alias(base_email: str | None, broker_slug: str, profile_id: int, *, mode: str = "plus",
               catchall_domain: str | None = None) -> str | None:
    if mode == "off":
        return None
    if mode == "catchall":
        domain = (catchall_domain or "").strip().lower().lstrip("@")
        if not domain or "." not in domain:
            return None
        room = MAX_LOCAL - len(f"dc--{profile_id}")
        return f"dc-{broker_slug[:room].rstrip('-')}-{profile_id}@{domain}"
    if not base_email or "@" not in base_email or not supports_plus(base_email):
        return None
    local, domain = base_email.rsplit("@", 1)
    local = local.split("+", 1)[0]
    room = MAX_LOCAL - len(f"{local}+dc--{profile_id}")
    if room < 3:
        return None
    return f"{local}+dc-{broker_slug[:room].rstrip('-')}-{profile_id}@{domain.lower()}"


def parse_alias(address: str, *, catchall_domain: str | None = None) -> tuple[str, int] | None:
    """Return (broker slug or slug prefix, profile id) for an alias address, else None."""
    address = (address or "").strip().lower()
    if "@" not in address:
        return None
    local, domain = address.rsplit("@", 1)
    if "+" in local:
        tag = local.split("+", 1)[1]
    elif catchall_domain and domain == catchall_domain.strip().lower().lstrip("@"):
        tag = local
    else:
        return None
    m = _TAG.fullmatch(tag)
    if not m:
        return None
    return m.group(1), int(m.group(2))
