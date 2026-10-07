"""Command-line interface: `ninja` / `ninjasignal`.

    ninja surging
    ninja predict qilin
    ninja groups
    ninja recent --limit 20 --sector Healthcare
    ninja report
    ninja risk --sector Healthcare

Every command takes --json for raw output and --base to point at a mirror.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .client import Client, NinjaSignalError


def _table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "(no results)"
    cols = [c for c in cols if any(c in r for r in rows)]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    line = "  ".join(c.upper().ljust(widths[c]) for c in cols)
    out = [line, "  ".join("-" * widths[c] for c in cols)]
    for r in rows:
        out.append("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))
    return "\n".join(out)


def _emit(data, as_json: bool, cols: list[str] | None = None):
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif isinstance(data, list) and cols:
        print(_table(data, cols))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ninja", description="Ninja Labz predictive threat-intel client.")
    p.add_argument("--version", action="version", version=f"ninjasignal {__version__}")
    p.add_argument("--base", help="feed host (default https://ninjalabz.io)")
    p.add_argument("--json", action="store_true", help="raw JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("groups", help="active ransomware groups")
    sub.add_parser("surging", help="groups accelerating right now")
    sub.add_parser("report", help="latest monthly stats")
    sp = sub.add_parser("predict", help="predictions for a group")
    sp.add_argument("group")
    sr = sub.add_parser("recent", help="recent claimed victims")
    sr.add_argument("--limit", type=int, default=25)
    sr.add_argument("--group"); sr.add_argument("--sector"); sr.add_argument("--country")
    sk = sub.add_parser("risk", help="exposure concentration (descriptive, not a forecast)")
    sk.add_argument("--sector"); sk.add_argument("--country")

    a = p.parse_args(argv)
    nl = Client(base=a.base) if a.base else Client()
    try:
        if a.cmd == "groups":
            _emit(nl.groups(), a.json, ["name", "victims", "top_sector", "top_country", "origin", "sanctioned"])
        elif a.cmd == "surging":
            _emit(nl.surging(), a.json, ["subject", "confidence", "statement"])
        elif a.cmd == "report":
            _emit(nl.latest_month(), a.json)
        elif a.cmd == "predict":
            preds = nl.predict(a.group)
            _emit(preds or [{"note": f"no current prediction for {a.group!r}"}], a.json,
                  ["type", "subject", "confidence", "statement"])
        elif a.cmd == "recent":
            _emit(nl.recent(limit=a.limit, group=a.group, sector=a.sector, country=a.country),
                  a.json, ["date", "group", "victim", "sector", "country"])
        elif a.cmd == "risk":
            _emit(nl.risk(sector=a.sector, country=a.country), a.json,
                  None if (a.sector or a.country) else None)
    except NinjaSignalError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
