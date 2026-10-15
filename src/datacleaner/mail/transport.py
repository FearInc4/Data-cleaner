"""Pick how mail goes out and comes in: a connected Gmail/Microsoft account, or SMTP/IMAP."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import oauth
from ..app_state import get_config
from ..models import MailAccount
from ..settings import Settings
from .aliases import make_alias


class MailNotConfigured(RuntimeError):
    pass


def active_account(session: Session) -> MailAccount | None:
    settings = Settings(session)
    acc_id = settings.get("mail_account_id")
    if acc_id:
        acc = session.get(MailAccount, int(acc_id))
        if acc:
            return acc
    return session.scalars(select(MailAccount).order_by(MailAccount.id)).first()


def _creds(session: Session, provider_key: str) -> oauth.ClientCreds | None:
    return oauth.credentials(oauth.get_provider(provider_key), Settings(session), get_config())


def sender_address(session: Session) -> str | None:
    acc = active_account(session)
    if acc:
        return acc.email
    return Settings(session).from_address or None


def describe(session: Session) -> dict:
    acc = active_account(session)
    s = Settings(session)
    if acc:
        return {"kind": acc.provider, "email": acc.email, "status": acc.status, "error": acc.last_error, "account": acc,
                "can_send": acc.status == "ok", "can_read": acc.status == "ok"}
    return {"kind": "smtp" if s.smtp_host else None, "email": s.from_address or None, "status": "ok", "error": None,
            "account": None, "can_send": bool(s.smtp_host and s.from_address), "can_read": bool(s.imap_host)}


def get_mailer(session: Session):
    from .smtp import SmtpMailer

    acc = active_account(session)
    if acc:
        from .oauth_mail import GmailMailer, GraphMailer, MailAuthError, TokenSource

        if acc.status != "ok":
            raise MailAuthError(acc.last_error or "Reconnect your mailbox on the Settings page.")
        tokens = TokenSource(session, acc, _creds(session, acc.provider))
        return GmailMailer(tokens) if acc.provider == "google" else GraphMailer(tokens)
    settings = Settings(session)
    if not settings.smtp_host or not settings.from_address:
        raise MailNotConfigured("Connect Gmail/Outlook or set up SMTP on the Settings page")
    return SmtpMailer.from_settings(settings)


def get_source(session: Session):
    from .inbox import ImapSource

    acc = active_account(session)
    if acc:
        from .oauth_mail import GmailSource, GraphSource, TokenSource

        if acc.status != "ok":
            return None
        tokens = TokenSource(session, acc, _creds(session, acc.provider))
        return GmailSource(tokens) if acc.provider == "google" else GraphSource(tokens)
    return ImapSource.from_settings(Settings(session))


def alias_for(session: Session, broker_slug: str, profile) -> str | None:
    s = Settings(session)
    base = sender_address(session) or profile.contact_email
    return make_alias(base, broker_slug, profile.id, mode=s.alias_mode or "plus", catchall_domain=s.alias_domain or None)
