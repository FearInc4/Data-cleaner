"""Build a phone blocklist from the FTC's public Do Not Call complaint data.

Data: https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data
API:  https://api.ftc.gov/v0/dnc-complaints (free key from https://api.data.gov/signup/)

Numbers are as reported by consumers and unverified; spoofed caller IDs mean a
number can belong to an innocent person. Blocklists are therefore built from
numbers with several independent reports, and the "who called me" lookup says
how many reports a number has rather than labelling it.
"""

from __future__ import annotations

import csv
import io
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SpamNumber

log = logging.getLogger(__name__)
API_URL = "https://api.ftc.gov/v0/dnc-complaints"


@dataclass
class Complaint:
    number: str
    reported: str | None
    state: str | None
    subject: str | None
    robocall: bool


def normalize_number(raw: str | None) -> str | None:
    d = re.sub(r"\D", "", raw or "")
    if len(d) == 11 and d.startswith("1"):
        d = d[1:]
    return d if len(d) == 10 else None


def _get(attrs: dict, *names: str):
    for n in names:
        for variant in (n, n.replace("-", "_"), n.replace("_", "-"), n.title().replace("-", "_")):
            if variant in attrs and attrs[variant] not in (None, ""):
                return attrs[variant]
    return None


def parse_api_page(payload: dict) -> list[Complaint]:
    out = []
    for item in payload.get("data", []) or []:
        attrs = item.get("attributes", item) if isinstance(item, dict) else {}
        num = normalize_number(_get(attrs, "company-phone-number"))
        if not num:
            continue
        robo = str(_get(attrs, "recorded-message-or-robocall") or "").strip().upper()
        out.append(Complaint(
            number=num,
            reported=str(_get(attrs, "created-date") or "")[:10] or None,
            state=_get(attrs, "consumer-state"),
            subject=_get(attrs, "subject"),
            robocall=robo in ("Y", "YES", "TRUE"),
        ))
    return out


def parse_csv(data: bytes | str) -> list[Complaint]:
    text = data.decode("utf-8-sig", errors="replace") if isinstance(data, bytes) else data
    reader = csv.DictReader(io.StringIO(text))
    out = []
    for row in reader:
        norm = {re.sub(r"[^a-z]", "", k.lower()): v for k, v in row.items() if k}
        num = normalize_number(norm.get("companyphonenumber"))
        if not num:
            continue
        out.append(Complaint(
            number=num,
            reported=(norm.get("createddate") or "")[:10] or None,
            state=norm.get("consumerstate") or None,
            subject=norm.get("subject") or None,
            robocall=(norm.get("recordedmessageorrobocall") or "").strip().upper() in ("Y", "YES"),
        ))
    return out


def fetch_api(api_key: str, *, state: str | None = None, area_code: str | None = None, days: int = 30,
              max_pages: int = 40, client: httpx.Client | None = None) -> list[Complaint]:
    own = client is None
    client = client or httpx.Client(timeout=30)
    since = (date.today() - timedelta(days=days)).strftime("%Y-%m-%d 00:00:00")
    out: list[Complaint] = []
    try:
        for page in range(max_pages):
            params = {"api_key": api_key, "items_per_page": 50, "offset": page * 50,
                      "created_date_from": f'"{since}"', "sort_by": "created_date", "sort_order": "DESC"}
            if state:
                params["state"] = f'"{state}"'
            if area_code:
                params["area_code"] = area_code
            resp = client.get(API_URL, params=params)
            resp.raise_for_status()
            batch = parse_api_page(resp.json())
            out.extend(batch)
            if len(batch) < 50:
                break
    finally:
        if own:
            client.close()
    return out


def ingest(session: Session, complaints: Iterable[Complaint]) -> int:
    agg: dict[str, SpamNumber] = {}
    for c in complaints:
        row = agg.get(c.number) or session.get(SpamNumber, c.number)
        if row is None:
            row = SpamNumber(number=c.number, reports=0, robocall_reports=0, subjects=[], states=[])
            session.add(row)
        agg[c.number] = row
        row.reports = (row.reports or 0) + 1
        row.robocall_reports = (row.robocall_reports or 0) + int(c.robocall)
        if c.reported and (not row.last_reported or c.reported > row.last_reported):
            row.last_reported = c.reported
        if c.subject and c.subject not in (row.subjects or []):
            row.subjects = (row.subjects or [])[:9] + [c.subject]
        if c.state and c.state not in (row.states or []):
            row.states = (row.states or [])[:19] + [c.state]
    session.flush()
    return len(agg)


def top_numbers(session: Session, *, min_reports: int = 3, limit: int = 1000, state: str | None = None) -> list[SpamNumber]:
    rows = session.scalars(
        select(SpamNumber).where(SpamNumber.reports >= min_reports).order_by(SpamNumber.reports.desc()).limit(limit * 3)
    ).all()
    if state:
        rows = [r for r in rows if state in (r.states or [])]
    return list(rows[:limit])


def lookup(session: Session, number: str) -> SpamNumber | None:
    n = normalize_number(number)
    return session.get(SpamNumber, n) if n else None


def to_vcard(numbers: list[str], *, per_contact: int = 200, name: str = "Spam Blocklist") -> str:
    """One or more vCards holding many numbers each. Import, then block the contact(s)."""
    cards = []
    for i in range(0, len(numbers), per_contact):
        chunk = numbers[i:i + per_contact]
        label = name if len(numbers) <= per_contact else f"{name} {i // per_contact + 1}"
        lines = ["BEGIN:VCARD", "VERSION:3.0", f"FN:{label}", f"N:{label};;;;", "NOTE:Generated by Data Cleaner from FTC Do Not Call complaint data."]
        lines += [f"TEL;TYPE=VOICE:+1{n}" for n in chunk]
        lines.append("END:VCARD")
        cards.append("\r\n".join(lines))
    return "\r\n".join(cards) + "\r\n"
