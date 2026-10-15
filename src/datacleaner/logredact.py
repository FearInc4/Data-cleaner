"""Keep personal data and credentials out of log files.

Logs end up in `docker logs`, journald, and bug reports. Exceptions from HTTP
libraries embed request URLs (which can contain an email address), and the
access log records query strings (OAuth codes, phone numbers typed into the
lookup box). This filter scrubs those before anything is written.
"""

from __future__ import annotations

import logging
import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OAuth codes, state, tokens, API keys in query strings or form bodies
    (re.compile(r"(?i)\b(code|state|token|access_token|refresh_token|id_token|api_key|key|password|client_secret)=([^&\s\"']+)"), r"\1=[redacted]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [redacted]"),
    (re.compile(r"(?i)(hibp-api-key|x-subscription-token|authorization)[\"']?\s*[:=]\s*[\"']?[^\s\"',}]+"), r"\1: [redacted]"),
    # Email addresses (also URL-encoded @)
    (re.compile(r"[A-Za-z0-9._%+'-]+(@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[email]"),
]

_PHONE_CANDIDATE = re.compile(r"(?<![\w.:-])\+?\(?\d[\d\s()%-]{8,}\d(?![\w.:])")
_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _phone_repl(m: re.Match[str]) -> str:
    raw = m.group(0)
    digits = sum(c.isdigit() for c in raw)
    if 10 <= digits <= 15 and not _DATE_LIKE.match(raw):
        return "[number]"
    return raw


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return _PHONE_CANDIDATE.sub(_phone_repl, text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access" and isinstance(record.args, tuple) and not record.exc_info:
            # uvicorn's access formatter unpacks these args (client, method, path, version, status),
            # so scrub each one in place instead of flattening the message.
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
            return True
        try:
            message = record.getMessage()
        except Exception:  # malformed format args; leave untouched
            return True
        cleaned = redact(message)
        if record.exc_info and record.exc_info[1] is not None:
            # Render the traceback now so it can be scrubbed too.
            formatted = logging.Formatter().formatException(record.exc_info)
            cleaned = cleaned + "\n" + redact(formatted)
            record.exc_info = None
            record.exc_text = None
        record.msg = cleaned
        record.args = ()
        return True


_FILTER = RedactingFilter()


def install() -> None:
    """Attach the filter to every handler that exists now (root + uvicorn)."""
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if _FILTER not in handler.filters:
                handler.addFilter(_FILTER)
