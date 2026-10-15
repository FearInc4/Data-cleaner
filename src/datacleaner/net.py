"""Outbound HTTP safety for URLs that come from strangers.

Links in emails (verification links, one-click unsubscribe), search results
and imported registries are attacker-controlled. Fetching one must never reach
the local network, the Docker network, or cloud metadata endpoints (SSRF).

``public_client()`` re-checks every hop of a redirect chain. DNS rebinding
between our check and the connection is still theoretically possible; the
remaining exposure is a blind GET/POST, which is acceptable for these uses.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlparse

import httpx

Resolver = Callable[[str], list[str]]


def _system_resolve(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


# Tests swap this out; production resolves with the system resolver.
RESOLVER: Resolver = _system_resolve

_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet")


class UnsafeURL(ValueError):
    pass


def _ip_is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_public_url(url: str, *, require_https: bool = True, resolve: bool = True) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in (("https",) if require_https else ("https", "http")):
        raise UnsafeURL(f"refusing non-{'https' if require_https else 'http(s)'} URL")
    if parsed.username or parsed.password:
        raise UnsafeURL("refusing URL with embedded credentials")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeURL(f"refusing local host {host!r}")
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False
    if is_literal:
        if not _ip_is_public(host):
            raise UnsafeURL(f"refusing private address {host}")
        return
    if "." not in host:
        raise UnsafeURL(f"refusing single-label host {host!r}")
    if resolve:
        try:
            addrs = RESOLVER(host)
        except OSError as exc:
            raise UnsafeURL(f"cannot resolve {host}") from exc
        if not addrs or not all(_ip_is_public(a) for a in addrs):
            raise UnsafeURL(f"{host} resolves to a private address")


def is_public_url(url: str, *, require_https: bool = True, resolve: bool = True) -> bool:
    try:
        check_public_url(url, require_https=require_https, resolve=resolve)
        return True
    except UnsafeURL:
        return False


def public_client(*, timeout: float = 20, follow_redirects: bool = True, max_redirects: int = 5,
                  transport: httpx.BaseTransport | None = None, require_https: bool = True,
                  headers: dict | None = None) -> httpx.Client:
    """An httpx client that refuses to talk to non-public hosts, including after redirects."""

    def guard(request: httpx.Request) -> None:
        check_public_url(str(request.url), require_https=require_https)

    return httpx.Client(timeout=timeout, follow_redirects=follow_redirects, max_redirects=max_redirects,
                        event_hooks={"request": [guard]}, transport=transport,
                        headers=headers or {"User-Agent": "Mozilla/5.0 (DataCleaner)"})
