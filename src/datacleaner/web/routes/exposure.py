"""Find my data (web + broker scans) and breach/paste monitoring."""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...breach.passwords import pwned_count
from ...breach.providers import advice_for, providers_from_settings, run_breach_check
from ...db import session_scope
from ...models import Finding, FindingKind, FindingStatus, Profile, ScanRun, User, utcnow
from ...removal import engine
from ...scan.brokers import check_brokers
from ...scan.search import provider_from_settings, run_search_scan
from ...settings import Settings
from ..deps import current_user, flash, get_db, redirect, render, selected_profile

log = logging.getLogger(__name__)
router = APIRouter()
_running: set[tuple[int, str]] = set()
_running_lock = threading.Lock()


def _start_background(profile_id: int, kind: str, fn) -> bool:
    key = (profile_id, kind)
    with _running_lock:
        if key in _running:
            return False
        _running.add(key)

    def worker():
        try:
            with session_scope() as s:
                p = s.get(Profile, profile_id)
                if p:
                    fn(s, p)
        except Exception:
            log.exception("Background %s scan failed", kind)
        finally:
            with _running_lock:
                _running.discard(key)

    threading.Thread(target=worker, daemon=True, name=f"scan-{kind}-{profile_id}").start()
    return True


def _running_kinds(profile_id: int) -> set[str]:
    with _running_lock:
        return {k for pid, k in _running if pid == profile_id}


def _latest_runs(db: Session, profile_id: int) -> dict[str, ScanRun]:
    out: dict[str, ScanRun] = {}
    for run in db.scalars(select(ScanRun).where(ScanRun.profile_id == profile_id).order_by(ScanRun.started_at.desc()).limit(30)):
        out.setdefault(run.kind, run)
    return out


# --- exposure scan -----------------------------------------------------------------

@router.get("/scan")
def scan_page(request: Request, profile_id: int | None = None, show: str = "active", db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    profile = selected_profile(request, db, profile_id)
    if not profile:
        return redirect("/profiles/new")
    stmt = select(Finding).where(Finding.profile_id == profile.id, Finding.kind.in_([FindingKind.LISTING, FindingKind.SEARCH]))
    if show == "active":
        stmt = stmt.where(Finding.status.in_([FindingStatus.NEW, FindingStatus.REMOVAL_REQUESTED]))
    findings = db.scalars(stmt.order_by(Finding.score.desc(), Finding.last_seen.desc())).all()
    listings = [f for f in findings if f.kind == FindingKind.LISTING]
    results = [f for f in findings if f.kind == FindingKind.SEARCH]
    settings = Settings(db)
    return render(request, db, "scan.html", profile=profile, listings=listings, results=results, show=show,
                  runs=_latest_runs(db, profile.id), running=_running_kinds(profile.id),
                  has_search=bool(settings.searxng_url or settings.brave_api_key))


@router.post("/scan/run")
def scan_run(request: Request, profile_id: int = Form(...), kind: str = Form(...), db: Session = Depends(get_db),
             user: User = Depends(current_user)):
    settings = Settings(db)
    if kind == "search":
        provider = provider_from_settings(settings)
        if not provider:
            flash(request, "Add a SearXNG URL or Brave Search API key in Settings to scan search engines.", "error")
            return redirect("/settings")
        started = _start_background(profile_id, "search", lambda s, p: run_search_scan(s, p, provider_from_settings(Settings(s))))
    elif kind == "brokers":
        started = _start_background(profile_id, "brokers", lambda s, p: check_brokers(s, p))
    else:
        raise HTTPException(400)
    flash(request, "Scan started. This page refreshes on its own." if started else "That scan is already running.", "info")
    return redirect(f"/scan?profile_id={profile_id}")


@router.post("/findings/{finding_id}")
def finding_action(finding_id: int, request: Request, action: str = Form(...), back: str = Form("/scan"),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404)
    now = utcnow()
    if action == "remove":
        if not f.broker:
            flash(request, "This site isn't in the broker catalog. Add it under Brokers → Add a broker, or contact the site directly.", "warn")
            return redirect(back if back.startswith("/") else "/scan")
        listing = f.url if f.kind == FindingKind.LISTING and f.check_state == "found" else (f.url if f.kind == FindingKind.SEARCH else None)
        req, created = engine.create_request(db, f.profile, f.broker, now=now, listing_url=listing)
        f.status = FindingStatus.REMOVAL_REQUESTED
        flash(request, "Removal request created." if created else "There's already an open request for this broker; listing URL added.", "success")
        return redirect(f"/requests/{req.id}")
    if action == "dismiss":
        f.status = FindingStatus.DISMISSED
    elif action == "removed":
        f.status = FindingStatus.REMOVED
    elif action == "resolved":
        f.status = FindingStatus.RESOLVED
    elif action == "reopen":
        f.status = FindingStatus.NEW
    return redirect(back if back.startswith("/") else "/scan")


# --- breaches ------------------------------------------------------------------------

@router.get("/breaches")
def breaches_page(request: Request, profile_id: int | None = None, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    profile = selected_profile(request, db, profile_id)
    if not profile:
        return redirect("/profiles/new")
    findings = db.scalars(select(Finding).where(
        Finding.profile_id == profile.id, Finding.kind.in_([FindingKind.BREACH, FindingKind.PASTE, FindingKind.CODE]),
    ).order_by(Finding.occurred_on.desc().nulls_last(), Finding.first_seen.desc())).all()
    all_classes = sorted({c for f in findings for c in (f.data_classes or [])})
    providers = [p.name for p in providers_from_settings(Settings(db))]
    return render(request, db, "breaches.html", profile=profile, findings=findings, advice=advice_for(all_classes),
                  all_classes=all_classes, runs=_latest_runs(db, profile.id), running=_running_kinds(profile.id),
                  providers=providers)


@router.post("/breaches/run")
def breaches_run(request: Request, profile_id: int = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not providers_from_settings(Settings(db)):
        flash(request, "Turn on at least one breach provider in Settings.", "error")
        return redirect("/settings")
    started = _start_background(profile_id, "breach",
                                lambda s, p: run_breach_check(s, p, providers_from_settings(Settings(s))))
    flash(request, "Breach check started." if started else "A breach check is already running.", "info")
    return redirect(f"/breaches?profile_id={profile_id}")


@router.post("/breaches/password")
def password_check(request: Request, password: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        count = pwned_count(password)
    except Exception as exc:
        flash(request, f"Couldn't reach Pwned Passwords: {exc}", "error")
        return redirect("/breaches#password")
    finally:
        password = ""  # noqa: F841 - drop the reference promptly
    if count:
        flash(request, f"That password appears {count:,} times in known breaches. Stop using it everywhere.", "error")
    else:
        flash(request, "That password wasn't found in known breaches. That doesn't make it strong, but it hasn't leaked.", "success")
    return redirect("/breaches#password")
