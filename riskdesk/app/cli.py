"""Command line entry points.

    python -m app.cli init                    create the database
    python -m app.cli check                   test every configured connector
    python -m app.cli sync wiz                pull from one source
    python -m app.cli sync all                pull from every configured source
    python -m app.cli demo                    load synthetic data for all three
    python -m app.cli expire                  lapse decisions past their expiry
    python -m app.cli reset --demo-only       clear demo rows (or everything)
    python -m app.cli wiz-introspect --type VulnerabilityFinding
    python -m app.cli serve                   run the web app

`expire` is the one to put on a schedule. Run it nightly so an acceptance that
nobody renewed stops suppressing its findings the day after it lapses.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from .db import SessionLocal, init_db  # noqa: E402

SOURCES = ("wiz", "falcon", "github")


def cmd_init(_args):
    init_db()
    print("Database ready.")


def cmd_check(_args):
    from .sync import get_connector
    failures = 0
    for name in SOURCES:
        c = get_connector(name)
        if not c.configured():
            print(f"  {name:8s} not configured")
            continue
        ok, message = c.check()
        print(f"  {name:8s} {'ok  ' if ok else 'FAIL'} {message}")
        failures += 0 if ok else 1
    return 1 if failures else 0


def cmd_sync(args):
    from .sync import get_connector, run_sync
    targets = SOURCES if args.source == "all" else [args.source]
    rc = 0
    for name in targets:
        if args.source == "all" and not args.demo and not get_connector(name).configured():
            print(f"  {name:8s} skipped (not configured)")
            continue
        result = run_sync(name, demo=args.demo, limit=args.limit, actor=args.actor)
        status = result["status"]
        if status == "ok":
            print(f"  {name:8s} ok    {result['findings']:>6} findings  "
                  f"{result['new']:>5} new  {result['closed']:>5} closed  "
                  f"{result['assets']:>4} assets")
        else:
            print(f"  {name:8s} FAIL  {result['error']}")
            rc = 1
    return rc


def cmd_demo(args):
    init_db()
    args.source, args.demo, args.limit, args.actor = "all", True, None, "cli"
    rc = cmd_sync(args)
    print("\nDemo data loaded. Everything above is synthetic -- do not report it.")
    return rc


def cmd_expire(_args):
    from .adjudication import expire_lapsed
    db = SessionLocal()
    try:
        n = expire_lapsed(db, actor="scheduler")
        print(f"Lapsed {n} decision(s). Their findings are back at full weight.")
    finally:
        db.close()


def cmd_reset(args):
    from .models import (
        Adjudication, AdjudicationApplication, Asset, AuditEvent, Finding,
        SyncRun, Vuln,
    )
    db = SessionLocal()
    try:
        if args.demo_only:
            rows = db.query(Finding).filter(Finding.raw.contains('"demo": true')).all()
            ids = [r.id for r in rows]
            if not ids:
                print("No demo rows found.")
                return
            db.query(AdjudicationApplication).filter(
                AdjudicationApplication.finding_id.in_(ids)).delete(synchronize_session=False)
            db.query(Finding).filter(Finding.id.in_(ids)).delete(synchronize_session=False)
            db.commit()
            print(f"Removed {len(ids)} demo findings. Assets and decisions were left alone.")
            return

        confirm = input("This deletes every finding, asset and decision. Type DELETE to confirm: ")
        if confirm != "DELETE":
            print("Cancelled.")
            return
        for model in (AdjudicationApplication, Adjudication, Finding, Vuln, Asset,
                      AuditEvent, SyncRun):
            db.query(model).delete()
        db.commit()
        print("Database cleared.")
    finally:
        db.close()


def cmd_wiz_introspect(args):
    from .connectors.wiz import WizConnector
    c = WizConnector()
    if not c.configured():
        print("Wiz is not configured. Set WIZ_CLIENT_ID, WIZ_CLIENT_SECRET and WIZ_API_URL.")
        return 1
    fields = c.introspect(args.type)
    if not fields:
        print(f"No type named {args.type} in this tenant's schema.")
        return 1
    print(f"{args.type} exposes {len(fields)} fields:\n")
    for f in fields:
        print(f"  {f}")
    print("\nCompare these against VULN_FINDINGS_QUERY in app/connectors/wiz.py "
          "and edit it if a name has drifted.")


def cmd_serve(args):
    import uvicorn
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)


def main(argv=None):
    p = argparse.ArgumentParser(prog="riskdesk", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    sub.add_parser("expire").set_defaults(fn=cmd_expire)

    s = sub.add_parser("sync")
    s.add_argument("source", choices=[*SOURCES, "all"])
    s.add_argument("--demo", action="store_true", help="use synthetic data")
    s.add_argument("--limit", type=int, default=None, help="stop after N findings")
    s.add_argument("--actor", default="cli")
    s.set_defaults(fn=cmd_sync)

    sub.add_parser("demo").set_defaults(fn=cmd_demo)

    r = sub.add_parser("reset")
    r.add_argument("--demo-only", action="store_true", help="remove only synthetic rows")
    r.set_defaults(fn=cmd_reset)

    w = sub.add_parser("wiz-introspect")
    w.add_argument("--type", default="VulnerabilityFinding")
    w.set_defaults(fn=cmd_wiz_introspect)

    v = sub.add_parser("serve")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8080)
    v.add_argument("--reload", action="store_true")
    v.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
