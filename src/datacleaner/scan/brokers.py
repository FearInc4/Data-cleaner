"""Check people-search sites directly for a listing.

Many people-search sites sit behind bot protection. When we're blocked we say
so (state ``blocked``) and give the person a one-click link to look
themselves; we never guess.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..brokers import render_search_url, search_values_for
from ..jurisdictions import broker_serves
from ..mail.parse import html_to_text
from ..models import Broker, Finding, FindingKind, FindingStatus, Profile, ScanRun, utcnow
from .findings import upsert_finding
from .matcher import profile_terms, score_text

log = logging.getLogger(__name__)

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
BLOCK_MARKERS = re.compile(
    r"(cf-challenge|challenge-platform|just a moment\.\.\.|attention required|captcha|px-captcha|datadome|access denied|are you a robot|verify you are human)",
    re.I,
)
# People-search sites repeat the searched name and city on their "nothing found" pages,
# so these phrases are checked before any name/location match.
NO_RESULTS = re.compile(
    r"\b(no (exact )?(results|records|matches|people|persons|one) (were |was )?(found|for|match(ed|es|ing)?)"
    r"|we (could not|couldn't|were unable to|weren't able to) find"
    r"|(could not|couldn't|can't|cannot) find (anyone|anybody|any (results|records|matches|people))"
    r"|(did not|didn't) (return|match|produce) any"
    r"|your search (returned|produced) no"
    r"|we found (0|zero|no) (results|records|matches|people)"
    r"|0 (results|records|matches|people) (found|for|match))",
    re.I,
)


@dataclass
class CheckResult:
    state: str  # found, not_found, blocked, error
    url: str
    score: float = 0.0
    matched: list[str] | None = None
    detail: str = ""


def check_listing(client: httpx.Client, url: str, profile: Profile) -> CheckResult:
    try:
        resp = client.get(url)
    except httpx.HTTPError as exc:
        return CheckResult("error", url, detail=str(exc)[:200])
    body = resp.text if resp.content else ""
    if resp.status_code in (401, 403, 429, 503):
        return CheckResult("blocked", url, detail=f"HTTP {resp.status_code}")
    if resp.status_code == 404:
        return CheckResult("not_found", url)
    if resp.status_code >= 400:
        return CheckResult("error", url, detail=f"HTTP {resp.status_code}")
    text = html_to_text(body)
    if NO_RESULTS.search(text):
        return CheckResult("not_found", url)
    score, matched = score_text(text, profile_terms(profile))
    # A real hit wins even if the page also embeds a CAPTCHA widget somewhere.
    if "name" in matched and ({"city", "state", "phone", "email", "birth_year"} & set(matched)):
        return CheckResult("found", url, score=score, matched=matched)
    if BLOCK_MARKERS.search(body[:20000]):
        return CheckResult("blocked", url, detail="bot check")
    if "name" not in matched:
        return CheckResult("not_found", url)
    # Name alone (no location) is a weak signal; surface it but scored low.
    return CheckResult("found", url, score=min(score, 0.4), matched=matched, detail="name only")


def check_brokers(session: Session, profile: Profile, *, client: httpx.Client | None = None,
                  broker_ids: list[int] | None = None, now: datetime | None = None, delay: float = 1.5) -> ScanRun:
    now = now or utcnow()
    # Finish any open transaction first: the network phase below can take minutes and
    # must not hold SQLite's write lock (that would freeze every other page).
    session.commit()
    q = select(Broker).where(Broker.active.is_(True), Broker.search_url.is_not(None))
    if broker_ids:
        q = q.where(Broker.id.in_(broker_ids))
    brokers = [b for b in session.scalars(q) if broker_serves(b.regions, profile.country)]
    values = search_values_for(profile)
    own_client = client is None
    client = client or httpx.Client(timeout=25, follow_redirects=True, headers=BROWSER_HEADERS)
    counts = {"found": 0, "not_found": 0, "blocked": 0, "error": 0, "skipped": 0, "removed": 0}
    results: list[tuple[Broker, str, CheckResult]] = []
    try:
        for i, broker in enumerate(brokers):
            url = render_search_url(broker.search_url or "", values)
            if not url:
                counts["skipped"] += 1
                continue
            results.append((broker, url, check_listing(client, url, profile)))
            if delay and i < len(brokers) - 1:
                time.sleep(delay)
    finally:
        if own_client:
            client.close()

    # Write phase: quick, no network.
    for broker, url, result in results:
        counts[result.state] += 1
        existing = session.scalars(
            select(Finding).where(Finding.profile_id == profile.id, Finding.kind == FindingKind.LISTING,
                                  Finding.broker_id == broker.id)
        ).first()
        if result.state == "not_found":
            if existing and existing.check_state == "found" and existing.status in (FindingStatus.NEW, FindingStatus.REMOVAL_REQUESTED):
                existing.status = FindingStatus.REMOVED
                existing.check_state = "not_found"
                existing.last_seen = now
                counts["removed"] += 1
            elif existing:
                existing.check_state = "not_found"
                existing.last_seen = now
        elif result.state in ("found", "blocked"):
            upsert_finding(
                session, profile, kind=FindingKind.LISTING, source=broker.slug, key=broker.slug, now=now,
                url=url, title=f"{broker.name} search results", score=result.score, matched=result.matched or [],
                broker=broker, check_state=result.state,
                snippet=None if result.state == "found" else "This site blocks automated checks. Open the link to look yourself.",
            )
    run = ScanRun(profile=profile, kind="brokers", started_at=now, finished_at=utcnow(), status="done",
                  summary={"checked": len(brokers), **counts})
    session.add(run)
    return run
