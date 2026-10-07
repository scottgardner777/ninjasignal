"""Quickstart — live against the public Ninja Labz feeds.

    python examples/quickstart.py
"""
import ninjasignal as ns


def main():
    print("== Surging now ==")
    for p in ns.surging()[:5]:
        print(f"  {p['subject']:<16} conf {p['confidence']:<4} {p['statement'][:80]}")

    print("\n== Most-tracked groups ==")
    for g in sorted(ns.groups(), key=lambda g: g.get("victims", 0), reverse=True)[:5]:
        flag = " [SANCTIONED]" if g.get("sanctioned") else ""
        print(f"  {g['name']:<16} {g.get('victims', 0):>5} victims  top: {g.get('top_sector')}{flag}")

    print("\n== Latest recent victims ==")
    for v in ns.recent(limit=5):
        print(f"  {v['date']}  {v['group']:<14} {v.get('sector', '?'):<16} {v.get('country', '?')}")

    print("\n== Healthcare exposure (descriptive) ==")
    print(" ", ns.risk(sector="Healthcare"))


if __name__ == "__main__":
    main()
