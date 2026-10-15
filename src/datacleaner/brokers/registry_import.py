"""Import state data broker registries (CSV exports).

Supported sources (the importer maps columns by header keywords, so it keeps
working when agencies rename columns between years):

- California CPPA registry: https://cppa.ca.gov/data_broker_registry/ ("Download CSV")
- Vermont Secretary of State data broker search export
- Texas Secretary of State data broker registry
- Oregon DFR data broker registry
- Privacy Rights Clearinghouse consolidated database export
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Broker, BrokerCategory
from . import registrable_domain

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s,;\"'<>]+", re.I)
BARE_DOMAIN_RE = re.compile(r"^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/\S*)?$", re.I)


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _norm(h: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", h.lower()).strip()


def _pick(headers: list[str], *, must: tuple[str, ...], any_of: tuple[str, ...] = (), avoid: tuple[str, ...] = ()) -> str | None:
    best = None
    best_score = -1
    for h in headers:
        n = _norm(h)
        if not all(m in n for m in must):
            continue
        if any(a in n for a in avoid):
            continue
        score = sum(1 for a in any_of if a in n)
        # Prefer shorter, more specific headers when scores tie.
        if score > best_score or (score == best_score and best is not None and len(n) < len(_norm(best))):
            best, best_score = h, score
    return best


@dataclass
class ColumnMap:
    name: str | None
    website: str | None
    email: str | None
    optout: str | None


def map_columns(headers: list[str]) -> ColumnMap:
    name = (
        _pick(headers, must=("name",), any_of=("broker", "business", "legal", "company"),
              avoid=("contact", "person", "officer", "dba", "url", "email"))
    )
    website = (
        _pick(headers, must=("website",), avoid=("opt", "delet", "request", "privacy"))
        or _pick(headers, must=("url",), any_of=("primary", "web"), avoid=("opt", "delet", "request", "privacy", "email"))
    )
    email = _pick(headers, must=("email",), any_of=("consumer", "contact", "privacy", "request", "rights"))
    optout = (
        _pick(headers, must=("delet",), any_of=("url", "link", "web", "request"), avoid=("email",))
        or _pick(headers, must=("opt",), any_of=("url", "link", "web", "out"), avoid=("email",))
        or _pick(headers, must=("request",), any_of=("url", "link", "web"), avoid=("email",))
    )
    return ColumnMap(name=name, website=website, email=email, optout=optout)


def _first_email(value: str | None) -> str | None:
    if not value:
        return None
    m = EMAIL_RE.search(value)
    return m.group(0).lower() if m else None


def _first_url(value: str | None) -> str | None:
    if not value:
        return None
    m = URL_RE.search(value)
    if m:
        return m.group(0).rstrip(".)")
    value = value.strip()
    if BARE_DOMAIN_RE.match(value):
        return "https://" + value
    return None


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:100] or "broker"


def import_registry_csv(session: Session, data: bytes | str, registry: str) -> ImportResult:
    registry = registry.upper()
    if isinstance(data, bytes):
        text = data.decode("utf-8-sig", errors="replace")
    else:
        text = data.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    cols = map_columns(headers)
    result = ImportResult()
    if not cols.name:
        result.errors.append(f"Could not find a broker name column in headers: {headers}")
        return result

    brokers = list(session.scalars(select(Broker)))
    by_domain: dict[str, Broker] = {}
    by_slug = {b.slug: b for b in brokers}
    for b in brokers:
        for d in b.domains or []:
            by_domain.setdefault(d, b)

    for line_no, row in enumerate(reader, start=2):
        name = (row.get(cols.name) or "").strip()
        if not name:
            result.skipped += 1
            continue
        website = _first_url(row.get(cols.website)) if cols.website else None
        email = _first_email(row.get(cols.email)) if cols.email else None
        optout = _first_url(row.get(cols.optout)) if cols.optout else None
        domain = registrable_domain(website) if website else (registrable_domain(optout) if optout else None)

        broker = by_domain.get(domain) if domain else None
        if broker is None:
            slug = _slugify(domain or name)
            broker = by_slug.get(slug)
        if broker is None:
            slug = _slugify(domain or name)
            n = 2
            while slug in by_slug:
                slug = f"{_slugify(domain or name)}-{n}"
                n += 1
            broker = Broker(
                slug=slug, name=name[:200], website=website, domains=[domain] if domain else [],
                category=BrokerCategory.OTHER, regions=["US"], priority=3, source=f"registry_{registry.lower()}",
                methods=[], requires=[], owns=[], steps=[], registries=[],
            )
            session.add(broker)
            by_slug[slug] = broker
            if domain:
                by_domain[domain] = broker
            result.created += 1
        else:
            result.updated += 1

        if registry not in (broker.registries or []):
            broker.registries = sorted(set(broker.registries or []) | {registry})
        # Never overwrite curated contact details; fill gaps only.
        methods = set(broker.methods or [])
        if email and not broker.privacy_email:
            broker.privacy_email = email
        if broker.privacy_email:
            methods.add("email")
        if optout and not broker.opt_out_url:
            broker.opt_out_url = optout
        if broker.opt_out_url:
            methods.add("form")
        broker.methods = sorted(methods)
        if not broker.website and website:
            broker.website = website

    session.flush()
    return result
