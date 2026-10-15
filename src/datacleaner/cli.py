"""Command line: `datacleaner serve | tick | import-registry | check-catalog | assist`."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _init():
    from . import app_state

    return app_state.init()


def cmd_serve(args) -> int:
    import uvicorn

    from .config import Config
    from .web.app import create_app

    config = Config()
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.no_scheduler:
        config.scheduler_enabled = False
    app = create_app(config)
    if config.host not in ("127.0.0.1", "localhost", "::1"):
        logging.getLogger(__name__).warning(
            "Listening on %s. Anyone who can reach this address sees the login page. "
            "Put it behind HTTPS (reverse proxy / Tailscale) and set DATACLEANER_SECURE_COOKIES=1.", config.host)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info", proxy_headers=True,
                forwarded_allow_ips=config.trusted_proxies)
    return 0


def cmd_tick(args) -> int:
    _init()
    from .scheduler import TickDeps, tick

    report = tick(deps=TickDeps(run_scans=not args.no_scans))
    print(json.dumps({"steps": report.steps, "errors": report.errors}, default=str, indent=2))
    return 1 if report.errors else 0


def cmd_import(args) -> int:
    _init()
    from .brokers.registry_import import import_registry_csv
    from .db import session_scope

    with session_scope() as session:
        result = import_registry_csv(session, Path(args.file).read_bytes(), args.registry)
    print(f"created={result.created} updated={result.updated} skipped={result.skipped}")
    for e in result.errors:
        print("error:", e, file=sys.stderr)
    return 1 if result.errors else 0


def cmd_check_catalog(args) -> int:
    from .brokers import load_catalog

    specs = load_catalog()
    print(f"{len(specs)} catalog entries OK")
    return 0


def cmd_assist(args) -> int:
    _init()
    from .assist.formfill import run_assisted, values_for
    from .db import session_scope
    from .models import RemovalRequest, utcnow
    from .removal import engine

    with session_scope() as session:
        req = session.get(RemovalRequest, args.request_id)
        if not req or not req.broker.opt_out_url:
            print("No such request, or the broker has no opt-out form", file=sys.stderr)
            return 1
        url, values = req.broker.opt_out_url, values_for(req.profile, req.listing_url, email=engine.ensure_alias(session, req))
    result = run_assisted(url, values, headless=False)
    print(f"Filled {result['filled']} field(s).")
    answer = input("Did you submit the form? [y/N] ").strip().lower()
    if answer == "y":
        with session_scope() as session:
            engine.mark_submitted(session, session.get(RemovalRequest, args.request_id), now=utcnow(), note="Submitted via assisted browser")
        print("Marked as submitted; follow-ups scheduled.")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from . import logredact

    logredact.install()
    parser = argparse.ArgumentParser(prog="datacleaner", description="Find and remove your personal data from the internet.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the web app (default http://127.0.0.1:25326)")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--no-scheduler", action="store_true", help="don't run the background scheduler in-process")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("tick", help="run one scheduler pass (for cron/systemd timers)")
    p.add_argument("--no-scans", action="store_true", help="skip exposure scans and breach checks")
    p.set_defaults(fn=cmd_tick)

    p = sub.add_parser("import-registry", help="import a state data broker registry CSV")
    p.add_argument("registry", choices=["CA", "VT", "TX", "OR", "PRC"])
    p.add_argument("file")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("check-catalog", help="validate the bundled broker catalog")
    p.set_defaults(fn=cmd_check_catalog)

    p = sub.add_parser("assist", help="open a request's opt-out form pre-filled in a browser")
    p.add_argument("request_id", type=int)
    p.set_defaults(fn=cmd_assist)

    args = parser.parse_args(argv)
    from .app_state import DataDirError

    try:
        return args.fn(args)
    except DataDirError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
