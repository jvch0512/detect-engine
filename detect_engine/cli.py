from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from . import engine, navigator
from .rules import LEVELS, load_rules


def _read_events(path: str):
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"warning: skipping invalid JSON on line {n}: {exc}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detect-engine", description="Run Sigma-style rules against JSONL events.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="evaluate events against rules")
    r.add_argument("--rules", required=True, help="rule file or directory")
    r.add_argument("--events", required=True, help="JSONL file or '-' for stdin")
    r.add_argument("--min-level", choices=LEVELS, default="informational")
    r.add_argument("--format", choices=["text", "json"], default="text")
    r.add_argument("--navigator", help="write an ATT&CK Navigator layer of the alerts to this path")

    v = sub.add_parser("validate", help="validate rules and list ATT&CK coverage")
    v.add_argument("--rules", required=True)
    v.add_argument("--navigator", help="write coverage layer to this path")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    rules = load_rules(args.rules)

    if args.cmd == "validate":
        cov = Counter(t for r in rules for t in r.techniques)
        print(f"{len(rules)} rules OK, {len(cov)} ATT&CK techniques covered")
        for t, n in sorted(cov.items()):
            print(f"  {t}: {n} rule(s)")
        if args.navigator:
            open(args.navigator, "w", encoding="utf-8").write(navigator.dumps(cov, "rule coverage"))
        return 0

    floor = LEVELS.index(args.min_level)
    alerts = [a for a in engine.run(rules, _read_events(args.events)) if LEVELS.index(a.level) >= floor]

    if args.format == "json":
        print(json.dumps([a.as_dict() for a in alerts], indent=2))
    else:
        for a in alerts:
            extra = f" [{a.group} x{a.count}]" if a.group else ""
            print(f"{a.timestamp:<22} {a.level.upper():<9} {a.rule_id:<22} {a.title}{extra}  ({', '.join(a.techniques)})")
        print(f"\n{len(alerts)} alert(s)")
    if args.navigator:
        counts = Counter(t for a in alerts for t in a.techniques)
        open(args.navigator, "w", encoding="utf-8").write(navigator.dumps(counts, "alerts"))
    return 1 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
