"""Search-engine exposure scan: where does this person show up on the open web?"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from ..brokers import find_broker_for_url
from ..jurisdictions import US_STATE_NAMES
from ..models import FindingKind, Profile, ScanRun, utcnow
from ..settings import Settings
from .findings import upsert_finding
from .matcher import phone_formats, profile_terms, score_text

log = logging.getLogger(__name__)

MIN_SCORE = 0.4
# Sites that host the person's own accounts; still listed, but marked as such.
SELF_HOSTED_HINTS = ("linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "github.com")


@dataclass
class SearchResult:
    url: str
    title: str
    snippet: str
    engine: str = ""


class SearchProvider(Protocol):
    name: str

    def search(self, query: str) -> list[SearchResult]: ...


class SearxngProvider:
    name = "searxng"

    def __init__(self, base_url: str, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=30)

    def search(self, query: str) -> list[SearchResult]:
        resp = self.client.get(f"{self.base_url}/search", params={"q": query, "format": "json", "safesearch": 0})
        resp.raise_for_status()
        data = resp.json()
        return [
            SearchResult(url=r.get("url", ""), title=r.get("title", ""), snippet=r.get("content", ""),
                         engine=",".join(r.get("engines", []) or [r.get("engine", "")]))
            for r in data.get("results", []) if r.get("url")
        ]


class BraveProvider:
    name = "brave"
    endpoint = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=30)

    def search(self, query: str) -> list[SearchResult]:
        resp = self.client.get(self.endpoint, params={"q": query, "count": 20},
                               headers={"X-Subscription-Token": self.api_key, "Accept": "application/json"})
        resp.raise_for_status()
        results = (resp.json().get("web") or {}).get("results", [])
        return [SearchResult(url=r.get("url", ""), title=r.get("title", ""), snippet=r.get("description", ""), engine="brave")
                for r in results if r.get("url")]


def provider_from_settings(settings: Settings) -> SearchProvider | None:
    if settings.searxng_url:
        return SearxngProvider(settings.searxng_url)
    if settings.brave_api_key:
        return BraveProvider(settings.brave_api_key)
    return None


def build_queries(profile: Profile, limit: int = 12) -> list[str]:
    name = profile.short_name
    queries: list[str] = []
    cities = []
    for a in profile.addresses:
        if a.get("city"):
            cities.append(a["city"])
    if name:
        for city in dict.fromkeys(cities[:3]):
            queries.append(f'"{name}" "{city}"')
        state = (profile.current_address or {}).get("region") or profile.region or ""
        if state:
            queries.append(f'"{name}" "{US_STATE_NAMES.get(state.upper(), state)}"')
        if not cities and not state:
            queries.append(f'"{name}"')
    for email in profile.emails:
        queries.append(f'"{email}"')
    for phone in profile.phones:
        fmts = phone_formats(phone)
        if fmts:
            queries.append(f'"{fmts[0]}"')
    for u in profile.get("usernames", []):
        if u:
            queries.append(f'"{u}"')
    for alias in profile.get("aliases", [])[:2]:
        if alias and cities:
            queries.append(f'"{alias}" "{cities[0]}"')
    return list(dict.fromkeys(queries))[:limit]


def run_search_scan(session: Session, profile: Profile, provider: SearchProvider, *, now: datetime | None = None,
                    delay: float = 1.0) -> ScanRun:
    now = now or utcnow()
    session.commit()  # don't hold a write lock during network calls
    terms = profile_terms(profile)
    seen: dict[str, SearchResult] = {}
    errors = []
    queries = build_queries(profile)
    for i, q in enumerate(queries):
        try:
            for r in provider.search(q):
                seen.setdefault(r.url.split("#")[0], r)
        except Exception as exc:
            errors.append(f"{q}: {exc}")
            log.info("Search query failed: %s", exc)
        if delay and i < len(queries) - 1:
            time.sleep(delay)
    new = total = 0
    for url, r in seen.items():
        score, matched = score_text(f"{r.title}\n{r.snippet}\n{url}", terms)
        if score < MIN_SCORE:
            continue
        broker = find_broker_for_url(session, url)
        host = (urlparse(url).hostname or "").lower()
        source = broker.slug if broker else host
        _, created = upsert_finding(
            session, profile, kind=FindingKind.SEARCH, source=source[:80], key=url, now=now, url=url,
            title=r.title[:300], snippet=r.snippet[:1000], matched=matched, score=score, broker=broker,
            check_state="found",
        )
        total += 1
        new += int(created)
    run = ScanRun(profile=profile, kind="search", started_at=now, finished_at=utcnow(),
                  status="error" if errors and not seen else "done",
                  summary={"provider": provider.name, "queries": len(queries), "results": len(seen),
                           "findings": total, "new": new, "errors": errors[:5]})
    session.add(run)
    return run
