from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...mail.transport import describe
from ...models import MailingSender, SpamNumber, User, utcnow
from ...settings import Settings
from ...spam import dnc, unsubscribe
from ...spam.checklist import items_for
from ..deps import current_user, flash, get_db, redirect, render, selected_profile

router = APIRouter(prefix="/spam")


def _done(settings: Settings) -> set[str]:
    try:
        return set(json.loads(settings.get("checklist_done") or "[]"))
    except (ValueError, TypeError):
        return set()


@router.get("")
def spam_page(request: Request, number: str = "", db: Session = Depends(get_db), user: User = Depends(current_user)):
    profile = selected_profile(request, db, None)
    settings = Settings(db)
    items = items_for(profile.country if profile else "US", profile.region if profile else None)
    state = (profile.current_address or {}).get("region") if profile else None
    top = dnc.top_numbers(db, min_reports=2, limit=25)
    total_numbers = db.scalar(select(func.count()).select_from(SpamNumber)) or 0
    lookup = dnc.lookup(db, number) if number else None
    senders = db.scalars(select(MailingSender).order_by(MailingSender.status, MailingSender.messages.desc()).limit(300)).all()
    return render(request, db, "spam.html", profile=profile, items=items, done=_done(settings), top=top,
                  total_numbers=total_numbers, number=number, lookup=lookup, looked_up=bool(number),
                  senders=senders, has_key=bool(settings.datagov_api_key), has_imap=describe(db)["can_read"], state=state)


@router.post("/checklist")
def checklist_toggle(request: Request, item_id: str = Form(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    settings = Settings(db)
    done = _done(settings)
    done.symmetric_difference_update({item_id})
    settings.set("checklist_done", json.dumps(sorted(done)))
    return redirect("/spam#checklist")


@router.post("/dnc/fetch")
def dnc_fetch(request: Request, state: str = Form(""), area_code: str = Form(""), days: int = Form(30),
              db: Session = Depends(get_db), user: User = Depends(current_user)):
    settings = Settings(db)
    if not settings.datagov_api_key:
        flash(request, "Add a free api.data.gov key in Settings, or upload an FTC CSV instead.", "error")
        return redirect("/spam#calls")
    try:
        complaints = dnc.fetch_api(settings.datagov_api_key, state=state.strip().upper() or None,
                                   area_code=area_code.strip() or None, days=max(1, min(days, 365)))
    except Exception as exc:
        flash(request, f"FTC API error: {exc}", "error")
        return redirect("/spam#calls")
    n = dnc.ingest(db, complaints)
    flash(request, f"Loaded {len(complaints)} complaints covering {n} numbers.", "success")
    return redirect("/spam#calls")


@router.post("/dnc/upload")
async def dnc_upload(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    data = await file.read()
    complaints = dnc.parse_csv(data)
    n = dnc.ingest(db, complaints)
    flash(request, f"Loaded {len(complaints)} complaints covering {n} numbers.", "success")
    return redirect("/spam#calls")


@router.get("/blocklist.vcf")
def blocklist(min_reports: int = 3, limit: int = 1000, state: str = "", db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    rows = dnc.top_numbers(db, min_reports=max(1, min_reports), limit=max(1, min(limit, 5000)), state=state.upper() or None)
    vcf = dnc.to_vcard([r.number for r in rows])
    return Response(vcf, media_type="text/vcard", headers={"Content-Disposition": 'attachment; filename="spam-blocklist.vcf"'})


@router.post("/unsubscribe/scan")
def unsub_scan(request: Request, days: int = Form(60), db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        n = unsubscribe.scan_inbox(db, days=max(1, min(days, 365)))
    except Exception as exc:
        flash(request, f"Inbox scan failed: {exc}", "error")
        return redirect("/spam#unsubscribe")
    flash(request, f"Found {n} senders with unsubscribe links.", "success")
    return redirect("/spam#unsubscribe")


@router.post("/unsubscribe")
async def unsub_selected(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    form = await request.form()
    action = form.get("action", "unsubscribe")
    ids = [int(v) for v in form.getlist("sender_id") if str(v).isdigit()]
    now = utcnow()
    results: dict[str, int] = {}
    for sid in ids:
        sender = db.get(MailingSender, sid)
        if not sender:
            continue
        if action == "keep":
            sender.status = "kept"
            results["kept"] = results.get("kept", 0) + 1
            continue
        outcome = unsubscribe.unsubscribe(db, sender, now=now)
        results[outcome] = results.get(outcome, 0) + 1
    if results:
        flash(request, ", ".join(f"{v} {k}" for k, v in results.items()), "success")
    return redirect("/spam#unsubscribe")
