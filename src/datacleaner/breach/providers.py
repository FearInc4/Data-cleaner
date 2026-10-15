"""Breach and paste exposure providers.

None of these download breach data. They return metadata: which breach, when,
and what kinds of data leaked. Passwords are only ever checked with
k-anonymity (see ``passwords.py``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from ..models import FindingKind, Profile, ScanRun, utcnow
from ..scan.findings import upsert_finding
from ..settings import Settings

log = logging.getLogger(__name__)
USER_AGENT = "DataCleaner/0.1 (+https://github.com/FearInc4/Data-cleaner)"


@dataclass
class Exposure:
    kind: str  # breach, paste, code
    source: str  # provider name
    name: str  # breach / paste id / repo path
    identifier: str  # which email/username/phone matched
    date: str | None = None
    data_classes: list[str] = field(default_factory=list)
    url: str | None = None
    description: str | None = None


class ProviderError(Exception):
    pass


class Provider(Protocol):
    name: str
    supports: set[str]  # identifier kinds: email, username, phone

    def lookup(self, identifier: str, kind: str) -> list[Exposure]: ...


def _split_classes(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).replace(",", ";").split(";") if v.strip()]


class XposedOrNot:
    """Free, no key. https://xposedornot.com; about 1 request/second."""

    name = "xposedornot"
    supports = {"email"}
    base = "https://api.xposedornot.com"

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=30, headers={"User-Agent": USER_AGENT})

    def lookup(self, identifier: str, kind: str) -> list[Exposure]:
        resp = self.client.get(f"{self.base}/v1/breach-analytics", params={"email": identifier})
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            raise ProviderError("XposedOrNot rate limit; try again later")
        resp.raise_for_status()
        data = resp.json() or {}
        out = []
        details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
        for b in details:
            out.append(Exposure(
                kind="breach", source=self.name, name=b.get("breach") or "Unknown breach", identifier=identifier,
                date=str(b.get("xposed_date") or "") or None, data_classes=_split_classes(b.get("xposed_data")),
                url=b.get("references") or None, description=(b.get("details") or "")[:500] or None,
            ))
        for p in data.get("ExposedPastes") or []:
            if isinstance(p, dict):
                pid = str(p.get("id") or p.get("paste_id") or p.get("title") or "paste")
                out.append(Exposure(kind="paste", source=self.name, name=pid, identifier=identifier,
                                    date=str(p.get("date") or "") or None, url=p.get("url") or None))
        summary = data.get("PastesSummary") or {}
        if not data.get("ExposedPastes") and int(summary.get("cnt") or 0) > 0:
            out.append(Exposure(kind="paste", source=self.name, name=f"{summary.get('cnt')} paste(s)",
                                identifier=identifier, date=summary.get("last_seen") or None,
                                description=f"Seen in {summary.get('cnt')} public paste(s)"))
        return out


class LeakCheckPublic:
    """Free public endpoint, limited. https://leakcheck.io"""

    name = "leakcheck"
    supports = {"email", "username"}
    base = "https://leakcheck.io/api/public"

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=30, headers={"User-Agent": USER_AGENT})

    def lookup(self, identifier: str, kind: str) -> list[Exposure]:
        resp = self.client.get(self.base, params={"check": identifier})
        if resp.status_code == 429:
            raise ProviderError("LeakCheck rate limit; try again later")
        resp.raise_for_status()
        data = resp.json() or {}
        if not data.get("success"):
            msg = str(data.get("error") or "")
            if "not found" in msg.lower():
                return []
            raise ProviderError(f"LeakCheck: {msg or 'unknown error'}")
        fields = _split_classes(data.get("fields"))
        return [
            Exposure(kind="breach", source=self.name, name=s.get("name") or "Unknown source", identifier=identifier,
                     date=s.get("date") or None, data_classes=fields)
            for s in data.get("sources") or [] if isinstance(s, dict)
        ]


class HaveIBeenPwned:
    """Paid API key required for account lookups. https://haveibeenpwned.com/API/v3"""

    name = "hibp"
    supports = {"email"}
    base = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=30)
        self.headers = {"hibp-api-key": api_key, "user-agent": USER_AGENT}

    def _get(self, path: str, params: dict | None = None):
        for _ in range(3):
            resp = self.client.get(f"{self.base}{path}", params=params, headers=self.headers)
            if resp.status_code == 429:
                time.sleep(min(float(resp.headers.get("retry-after", "2")), 10))
                continue
            return resp
        raise ProviderError("HIBP rate limit")

    def lookup(self, identifier: str, kind: str) -> list[Exposure]:
        out: list[Exposure] = []
        resp = self._get(f"/breachedaccount/{quote(identifier)}", {"truncateResponse": "false"})
        if resp.status_code == 401:
            raise ProviderError("HIBP API key rejected")
        if resp.status_code not in (200, 404):
            resp.raise_for_status()
        if resp.status_code == 200:
            for b in resp.json():
                out.append(Exposure(
                    kind="breach", source=self.name, name=b.get("Title") or b.get("Name"), identifier=identifier,
                    date=b.get("BreachDate"), data_classes=list(b.get("DataClasses") or []),
                    url=f"https://haveibeenpwned.com/Breach/{b.get('Name')}" if b.get("Name") else None,
                ))
        resp = self._get(f"/pasteaccount/{quote(identifier)}")
        if resp.status_code == 200:
            for p in resp.json() or []:
                src, pid = p.get("Source"), p.get("Id")
                url = f"https://pastebin.com/{pid}" if src == "Pastebin" and pid else None
                out.append(Exposure(kind="paste", source=self.name, name=f"{src}: {p.get('Title') or pid}",
                                    identifier=identifier, date=(p.get("Date") or "")[:10] or None, url=url))
        return out


class GitHubCodeSearch:
    """Finds emails/phones committed to public repositories. Needs a (free) token."""

    name = "github"
    supports = {"email", "phone"}

    def __init__(self, token: str, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=30)
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}

    def lookup(self, identifier: str, kind: str) -> list[Exposure]:
        resp = self.client.get("https://api.github.com/search/code", params={"q": f'"{identifier}"', "per_page": 20},
                               headers=self.headers)
        if resp.status_code in (403, 429):
            raise ProviderError("GitHub search rate limit")
        if resp.status_code == 422:
            return []
        resp.raise_for_status()
        return [
            Exposure(kind="code", source=self.name, name=f"{i['repository']['full_name']}/{i['path']}",
                     identifier=identifier, url=i.get("html_url"))
            for i in resp.json().get("items", [])
        ]


class Psbdmp:
    """Pastebin dump search (psbdmp.ws). Experimental: the service's API changes often."""

    name = "psbdmp"
    supports = {"email"}

    def __init__(self, client: httpx.Client | None = None, base: str = "https://psbdmp.ws/api/v3/search"):
        self.client = client or httpx.Client(timeout=30, headers={"User-Agent": USER_AGENT})
        self.base = base

    def lookup(self, identifier: str, kind: str) -> list[Exposure]:
        resp = self.client.get(f"{self.base}/{quote(identifier)}")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        items = data if isinstance(data, list) else data.get("data", [])
        out = []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            pid = it.get("id") or it.get("paste_id")
            out.append(Exposure(kind="paste", source=self.name, name=f"pastebin:{pid}", identifier=identifier,
                                date=(str(it.get("time") or it.get("date") or ""))[:10] or None,
                                url=f"https://pastebin.com/{pid}" if pid else None))
        return out


def providers_from_settings(settings: Settings) -> list[Provider]:
    out: list[Provider] = []
    if settings.xposedornot_enabled:
        out.append(XposedOrNot())
    if settings.leakcheck_enabled:
        out.append(LeakCheckPublic())
    if settings.hibp_api_key:
        out.append(HaveIBeenPwned(settings.hibp_api_key))
    if settings.github_token:
        out.append(GitHubCodeSearch(settings.github_token))
    if settings.psbdmp_enabled:
        out.append(Psbdmp())
    return out


KIND_MAP = {"breach": FindingKind.BREACH, "paste": FindingKind.PASTE, "code": FindingKind.CODE}


def identifiers_for(profile: Profile) -> list[tuple[str, str]]:
    ids = [(e, "email") for e in profile.emails]
    ids += [(u, "username") for u in profile.get("usernames", []) if u]
    ids += [(p, "phone") for p in profile.phones]
    return ids


def run_breach_check(session: Session, profile: Profile, providers: list[Provider], *, now: datetime | None = None,
                     delay: float = 1.1) -> ScanRun:
    now = now or utcnow()
    session.commit()  # don't hold a write lock during network calls
    errors: list[str] = []
    found = new = 0
    collected: list[Exposure] = []
    for provider in providers:
        for ident, kind in identifiers_for(profile):
            if kind not in provider.supports:
                continue
            try:
                exposures = provider.lookup(ident, kind)
            except Exception as exc:
                errors.append(f"{provider.name}: {exc}")
                log.info("%s lookup failed: %s", provider.name, exc)
                continue
            finally:
                if delay:
                    time.sleep(delay)
            collected.extend(exposures)
    for ex in collected:
        _, created = upsert_finding(
            session, profile, kind=KIND_MAP[ex.kind], source=ex.source, key=f"{ex.identifier}|{ex.name}",
            now=now, url=ex.url, title=ex.name, snippet=f"Matched {ex.identifier}" + (f". {ex.description}" if ex.description else ""),
            data_classes=ex.data_classes, occurred_on=ex.date, score=1.0,
        )
        found += 1
        new += int(created)
    run = ScanRun(profile=profile, kind="breach", started_at=now, finished_at=utcnow(),
                  status="error" if errors and not found else "done",
                  summary={"providers": [p.name for p in providers], "exposures": found, "new": new, "errors": errors[:10]})
    session.add(run)
    return run


# --- what to do about it -------------------------------------------------------

ADVICE = [
    (("password", "passwords", "password hints"),
     "Change this password anywhere you reused it, and turn on two-factor authentication. A password manager makes unique passwords painless."),
    (("social security numbers", "ssn", "government issued ids", "passport numbers", "national ids"),
     "Freeze your credit at Equifax, Experian, TransUnion, Innovis and ChexSystems (free), and get an IRS Identity Protection PIN."),
    (("credit cards", "credit card cvv", "bank account numbers", "partial credit card data"),
     "Tell your bank or card issuer, replace the card, and watch your statements."),
    (("phone numbers",),
     "Expect more scam calls and texts. Ask your carrier for a port-out PIN or number lock to block SIM-swap attacks."),
    (("physical addresses", "addresses"),
     "Your address is now in breach data. Removing it from data brokers limits how easily it can be tied back to you."),
    (("dates of birth", "dob"),
     "Combined with your name, your date of birth is used for identity checks. A credit freeze helps here."),
    (("security questions and answers",),
     "Change your security answers. Treat them like passwords (random answers stored in a password manager)."),
]


def advice_for(data_classes: list[str]) -> list[str]:
    low = {d.lower() for d in data_classes}
    out = []
    for keys, text in ADVICE:
        if any(k in low or any(k in d for d in low) for k in keys):
            out.append(text)
    return out
