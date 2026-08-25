#!/usr/bin/env python3
"""
Execute runner-mode rules against live data.

The query narrows the search server-side; rule() makes the final call in Python.
This is how allowlists, ratios and any logic Query DSL cannot express get
applied - reviewable in a diff instead of buried in a JSON blob.

Also doubles as the validation harness: --all runs every rule, including the
monitor-mode ones, so you can prove a deployed monitor and its Python logic
agree on the same data.

  python3 tools/run_detections.py
  python3 tools/run_detections.py --all --window 60
"""

import argparse
import sys
from pathlib import Path
from typing import Any

from _http import session as requests

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detections import all_rules  # noqa: E402
from detections.base import Rule  # noqa: E402


def fetch(base: str, rule: Rule, window: int, size: int) -> list[dict[str, Any]]:
    body = {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    rule.query,
                    {"range": {"@timestamp": {"gte": f"now-{window}m"}}},
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
    }
    r = requests.post(f"{base}/{rule.index}/_search", json=body, timeout=30)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return [h["_source"] for h in r.json()["hits"]["hits"]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--window", type=int, default=None,
                    help="override each rule's window, in minutes")
    ap.add_argument("--all", action="store_true",
                    help="run monitor-mode rules too, not just runner-mode")
    ap.add_argument("--size", type=int, default=500)
    args = ap.parse_args()
    base = args.url.rstrip("/")

    total_alerts = 0
    for rule in all_rules():
        if not args.all and rule.mode != "runner":
            continue

        window = args.window or rule.window_minutes
        candidates = fetch(base, rule, window, args.size)
        alerts = [e for e in candidates if rule.rule(e)]
        total_alerts += len(alerts)

        flag = f"  [BLOCKED {rule.blocked_by}]" if rule.blocked_by else ""
        print(f"\n{rule.id}  {rule.severity}  "
              f"candidates={len(candidates)} alerts={len(alerts)}{flag}")

        seen: set[str] = set()
        for event in alerts:
            key = rule.dedup_key(event)
            if key in seen:
                continue
            seen.add(key)
            ts = event.get("@timestamp", "?")
            print(f"    {ts}  {rule.alert_title(event)}")

        if not candidates and rule.blocked_by:
            print(f"    zero candidates - consistent with FINDINGS "
                  f"{rule.blocked_by}: {rule.blocked_reason}")

    print(f"\ntotal alerts: {total_alerts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
