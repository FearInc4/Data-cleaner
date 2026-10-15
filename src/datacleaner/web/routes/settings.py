from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ... import app_state, oauth
from ...mail.aliases import make_alias
from ...mail.inbox import ImapSource
from ...mail.smtp import MailNotConfigured, SmtpMailer
from ...mail.transport import describe
from ...models import User
from ...scheduler import TickDeps, tick
from ...settings import DEFS, Settings
from ..deps import current_user, flash, get_db, redirect, render

router = APIRouter(prefix="/settings")

SECRET_PLACEHOLDER = "••••••••"


@router.get("")
def settings_page(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = Settings(db)
    cfg = app_state.get_config()
    groups: dict[str, list] = {}
    for d in DEFS:
        value = s.get(d.key)
        if d.kind == "secret":
            value = SECRET_PLACEHOLDER if value else ""
        groups.setdefault(d.group, []).append((d, value))
    base_url = cfg.base_url or str(request.base_url).rstrip("/")
    apps = [{
        "provider": p,
        "configured": bool(oauth.credentials(p, s, cfg)),
        "from_env": bool(getattr(cfg, f"{p.key}_client_id", None)),
        "redirect_uri": oauth.redirect_uri(base_url, p),
    } for p in oauth.PROVIDERS.values()]
    mail = describe(db)
    sample = None
    if mail["email"]:
        sample = make_alias(mail["email"], "spokeo", 1, mode=s.alias_mode or "plus", catchall_domain=s.alias_domain or None)
    return render(request, db, "settings.html", groups=groups, last_tick=s.get("last_tick_at"), mail=mail, apps=apps,
                  providers=[a["provider"] for a in apps if a["configured"]], sample_alias=sample, base_url=base_url,
                  base_url_configured=bool(cfg.base_url))


@router.post("")
async def settings_save(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    form = await request.form()
    s = Settings(db)
    for d in DEFS:
        if d.kind == "bool":
            s.set(d.key, form.get(d.key) in ("on", "true", "1"))
            continue
        if d.key not in form:
            continue
        raw = str(form.get(d.key) or "").strip()
        if d.kind == "secret":
            if raw == SECRET_PLACEHOLDER:
                continue  # unchanged
            s.set(d.key, raw)
        elif d.kind == "int":
            try:
                s.set(d.key, int(raw))
            except ValueError:
                flash(request, f"{d.label} must be a number.", "error")
        elif d.kind == "choice":
            if raw in d.choices:
                s.set(d.key, raw)
        else:
            s.set(d.key, raw)
    if form.get("imap_username") and not s.get("imap_password") and s.get("smtp_password") \
            and form.get("imap_username") == s.get("smtp_username"):
        s.set("imap_password", s.get("smtp_password"))
    flash(request, "Settings saved.", "success")
    return redirect("/settings")


@router.post("/test-smtp")
def test_smtp(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        SmtpMailer.from_settings(Settings(db)).check()
        flash(request, "SMTP login worked.", "success")
    except MailNotConfigured as exc:
        flash(request, str(exc), "error")
    except Exception as exc:
        flash(request, f"SMTP failed: {exc}", "error")
    return redirect("/settings")


@router.post("/test-imap")
def test_imap(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    src = ImapSource.from_settings(Settings(db))
    if not src:
        flash(request, "Fill in IMAP host and username first.", "error")
        return redirect("/settings")
    try:
        src.check()
        flash(request, "IMAP login worked.", "success")
    except Exception as exc:
        flash(request, f"IMAP failed: {exc}", "error")
    return redirect("/settings")


@router.post("/tick")
def run_tick(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    db.commit()
    # Scans can take minutes; they run on their own schedule or from the scan pages.
    report = tick(deps=TickDeps(run_scans=False))
    parts = []
    for name, value in report.steps.items():
        if isinstance(value, dict):
            nonzero = {k: v for k, v in value.items() if v}
            if nonzero:
                parts.append(f"{name}: " + ", ".join(f"{k}={v}" for k, v in nonzero.items()))
        elif value:
            parts.append(f"{name}: {value}")
    flash(request, "Scheduler ran. " + ("; ".join(parts) if parts else "Nothing was due."), "success")
    for e in report.errors:
        flash(request, e, "error")
    back = urlparse(request.headers.get("referer") or "/").path or "/"
    return redirect(back if back.startswith("/") else "/")
