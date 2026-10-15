"""Broker catalog: curated YAML entries + imported state registry entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any
from urllib.parse import quote, quote_plus, urlparse

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..jurisdictions import US_STATE_NAMES
from ..models import Broker, BrokerCategory

VALID_METHODS = {"email", "form", "phone", "mail", "portal"}
VALID_REQUIRES = {"captcha", "email_verification", "profile_url", "id_document", "phone_call", "account"}


class CatalogError(ValueError):
    pass


@dataclass
class BrokerSpec:
    slug: str
    name: str
    website: str | None = None
    domains: list[str] = field(default_factory=list)
    category: str = BrokerCategory.OTHER
    regions: list[str] = field(default_factory=lambda: ["US"])
    priority: int = 3
    privacy_email: str | None = None
    opt_out_url: str | None = None
    search_url: str | None = None
    methods: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    parent: str | None = None
    owns: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    notes: str | None = None
    verified: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any], where: str = "") -> "BrokerSpec":
        known = set(cls.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise CatalogError(f"{where}: unknown fields {sorted(unknown)}")
        for req in ("slug", "name"):
            if not raw.get(req):
                raise CatalogError(f"{where}: missing '{req}'")
        spec = cls(**raw)
        spec.validate(where)
        return spec

    def validate(self, where: str = "") -> None:
        where = where or self.slug
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.slug):
            raise CatalogError(f"{where}: slug must be lowercase letters, digits and hyphens")
        if self.category not in BrokerCategory.ALL:
            raise CatalogError(f"{where}: unknown category {self.category!r}")
        bad = set(self.methods) - VALID_METHODS
        if bad:
            raise CatalogError(f"{where}: unknown methods {sorted(bad)}")
        bad = set(self.requires) - VALID_REQUIRES
        if bad:
            raise CatalogError(f"{where}: unknown requires {sorted(bad)}")
        if "email" in self.methods and not self.privacy_email:
            raise CatalogError(f"{where}: method 'email' needs privacy_email")
        if "form" in self.methods and not self.opt_out_url:
            raise CatalogError(f"{where}: method 'form' needs opt_out_url")
        for url in (self.website, self.opt_out_url, self.search_url):
            if url and not url.startswith("https://"):
                raise CatalogError(f"{where}: URLs must be https: {url}")
        if self.priority not in (1, 2, 3):
            raise CatalogError(f"{where}: priority must be 1, 2 or 3")
        if not self.domains and self.website:
            self.domains = [registrable_domain(self.website)]


def load_catalog() -> list[BrokerSpec]:
    specs: list[BrokerSpec] = []
    seen: set[str] = set()
    data_dir = resources.files("datacleaner.brokers") / "data"
    for entry in sorted(data_dir.iterdir(), key=lambda p: p.name):
        if not entry.name.endswith((".yaml", ".yml")):
            continue
        items = yaml.safe_load(entry.read_text(encoding="utf-8")) or []
        if not isinstance(items, list):
            raise CatalogError(f"{entry.name}: top level must be a list")
        for i, raw in enumerate(items):
            spec = BrokerSpec.from_dict(raw, where=f"{entry.name}[{i}]")
            if spec.slug in seen:
                raise CatalogError(f"{entry.name}: duplicate slug {spec.slug}")
            seen.add(spec.slug)
            specs.append(spec)
    return specs


def sync_catalog(session: Session) -> dict[str, int]:
    """Upsert curated catalog entries. Registry-imported and user-added rows are left alone."""
    stats = {"created": 0, "updated": 0}
    existing = {b.slug: b for b in session.scalars(select(Broker))}
    for spec in load_catalog():
        row = existing.get(spec.slug)
        if row is None:
            row = Broker(slug=spec.slug, source="catalog")
            session.add(row)
            stats["created"] += 1
        elif row.source != "catalog":
            # A registry import got there first; the curated entry wins but keeps registry tags.
            row.source = "catalog"
            stats["updated"] += 1
        else:
            stats["updated"] += 1
        row.name = spec.name
        row.website = spec.website
        row.domains = spec.domains
        row.category = spec.category
        row.regions = spec.regions
        row.priority = spec.priority
        row.privacy_email = spec.privacy_email
        row.opt_out_url = spec.opt_out_url
        row.search_url = spec.search_url
        row.methods = spec.methods
        row.requires = spec.requires
        row.parent = spec.parent
        row.owns = spec.owns
        row.steps = spec.steps
        row.notes = spec.notes
        row.verified = spec.verified
    session.flush()
    return stats


# --- helpers ---------------------------------------------------------------

_MULTI_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "co.jp"}


def registrable_domain(url_or_host: str) -> str:
    host = url_or_host
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def host_matches(host: str, domains: list[str]) -> bool:
    host = (host or "").lower().strip(".")
    for d in domains:
        d = d.lower().strip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def find_broker_for_url(session: Session, url: str) -> Broker | None:
    host = urlparse(url).hostname or ""
    if not host:
        return None
    for broker in session.scalars(select(Broker).where(Broker.active.is_(True))):
        if broker.domains and host_matches(host, broker.domains):
            return broker
    return None


_PLACEHOLDER = re.compile(r"\{(\w+)(?::(\w+))?\}")


def _transform(value: str, how: str | None) -> str:
    if how in (None, "q"):
        return quote(value, safe="")
    if how == "plus":
        return quote_plus(value)
    if how == "slug":
        return quote(re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-"), safe="-")
    if how == "Slug":
        words = re.split(r"[^A-Za-z0-9]+", value)
        return quote("-".join(w.capitalize() for w in words if w), safe="-")
    if how == "upper":
        return quote(value.upper(), safe="")
    if how == "lower":
        return quote(value.lower(), safe="")
    raise CatalogError(f"unknown search_url transform {how!r}")


def render_search_url(template: str, values: dict[str, str]) -> str | None:
    """Fill a broker search_url template. Returns None if a needed value is missing."""
    missing = False

    def repl(m: re.Match[str]) -> str:
        nonlocal missing
        key, how = m.group(1), m.group(2)
        # {First} / {Last} are just capitalised spellings of first/last.
        val = values.get(key) or values.get(key.lower()) or ""
        if not val:
            missing = True
            return ""
        return _transform(val, how)

    url = _PLACEHOLDER.sub(repl, template)
    return None if missing else url


def search_values_for(profile) -> dict[str, str]:
    addr = profile.current_address or {}
    state = (addr.get("region") or profile.region or "").upper()
    return {
        "first": profile.get("first_name") or "",
        "last": profile.get("last_name") or "",
        "middle": profile.get("middle_name") or "",
        "city": addr.get("city") or "",
        "state": state,
        "state_name": US_STATE_NAMES.get(state, ""),
        "zip": addr.get("postal_code") or "",
    }
