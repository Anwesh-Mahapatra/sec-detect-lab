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

ZERO ALERTS IS NOT A PASS ON ITS OWN
------------------------------------
Zero can mean "nothing happened" or "nothing is arriving", and every rule here
returns zero in both cases. Absence rules (fires_on="absence") run first and
decide which one you are looking at. If the canary heartbeat is missing, every
other result in the run is inconclusive and is labelled as such rather than
being reported as clean.

Three outcomes, deliberately distinguished, because they need different
responses at 3am:

  heartbeat present            results mean what they say
  heartbeat absent             the transport is broken - results are unusable
  search failed outright       OpenSearch itself is unreachable - nothing ran

The second and third are not the same thing. A missing heartbeat means the
cluster answered and had no canary in it. A failed search means the cluster
never answered, so no rule was evaluated at all.

Exit codes:
  0  clean - every rule evaluated, no alerts
  1  alerts fired
  2  usage error (argparse)
  3  inconclusive - a canary is missing or OpenSearch could not be queried
"""

import argparse
import time
from pathlib import Path
from typing import Any

import requests as _requests_mod

from _http import session as requests
from detections import all_rules
from detections.base import Rule

DEFAULT_STATE = Path.home() / ".cache" / "sec-detect-lab" / "canary.state"

EXIT_CLEAN = 0
EXIT_ALERTS = 1
EXIT_INCONCLUSIVE = 3


class SearchUnavailable(Exception):
    """OpenSearch could not be queried at all - distinct from an empty result."""


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
    try:
        r = requests.post(f"{base}/{rule.index}/_search", json=body, timeout=30)
    except _requests_mod.RequestException as exc:
        # Never let this collapse into "no events". An unreachable cluster is a
        # different failure from an empty one and gets a different exit code.
        raise SearchUnavailable(str(exc)) from exc
    if r.status_code == 404:
        return []
    if r.status_code >= 500:
        raise SearchUnavailable(f"HTTP {r.status_code} from {rule.index}/_search")
    r.raise_for_status()
    return [h["_source"] for h in r.json()["hits"]["hits"]]


def state_age_minutes(path: Path) -> float | None:
    """Minutes since tools/canary.py last reported a successful beat."""
    try:
        return (time.time() - path.stat().st_mtime) / 60.0
    except OSError:
        return None


def diagnose_absence(state_file: Path, window: int) -> tuple[str, str]:
    """
    Tell a stopped generator apart from a stopped transport.

    Both look identical in the index - no heartbeat - but they need opposite
    responses: restart a cron, or go debug Fluent Bit/Kafka/Cribl. canary.py
    touches the state file before the pipeline is involved, so its age isolates
    which half of the loop is broken.
    """
    age = state_age_minutes(state_file)
    if age is None:
        return ("GENERATOR",
                f"no state file at {state_file} - tools/canary.py has never "
                f"completed a beat on this host. Start it before trusting any "
                f"result: uv run python tools/canary.py")
    if age > window:
        return ("GENERATOR",
                f"generator last beat {age:.1f}m ago, outside the {window}m "
                f"window - the cron/timer running tools/canary.py is stopped. "
                f"The transport may be perfectly healthy; nothing is feeding it.")
    return ("TRANSPORT",
            f"generator beat {age:.1f}m ago but nothing reached OpenSearch - "
            f"the audit transport is broken between the apiserver and the "
            f"index. Check Fluent Bit, Kafka lag, then Cribl.")


def evaluate(base: str, rule: Rule, window: int, size: int) -> tuple[list, list]:
    candidates = fetch(base, rule, window, size)
    matched = [e for e in candidates if rule.rule(e)]
    return candidates, matched


def report_presence(rule: Rule, candidates: list, matched: list) -> None:
    flag = f"  [BLOCKED {rule.blocked_by}]" if rule.blocked_by else ""
    print(f"\n{rule.id}  {rule.severity}  "
          f"candidates={len(candidates)} alerts={len(matched)}{flag}")

    seen: set[str] = set()
    for event in matched:
        key = rule.dedup_key(event)
        if key in seen:
            continue
        seen.add(key)
        print(f"    {event.get('@timestamp', '?')}  {rule.alert_title(event)}")

    if not candidates and rule.blocked_by:
        print(f"    zero candidates - consistent with FINDINGS "
              f"{rule.blocked_by}: {rule.blocked_reason}")


def report_absence(rule: Rule, matched: list, window: int,
                   state_file: Path) -> bool:
    """Report one absence rule. Returns True if it is firing (heartbeat gone)."""
    healthy = len(matched) >= rule.threshold
    print(f"\n{rule.id}  {rule.severity}  "
          f"heartbeats={len(matched)} in {window}m  "
          f"(need >={rule.threshold})  [{'OK' if healthy else 'FIRING'}]")

    if healthy:
        newest = max(matched, key=lambda e: e.get("@timestamp", ""))
        print(f"    last seen {newest.get('@timestamp', '?')}  "
              f"{rule.alert_title(newest)}")
        return False

    kind, detail = diagnose_absence(state_file, window)
    print(f"    ALERT  {rule.title}")
    print(f"    cause  {kind}: {detail}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--window", type=int, default=None,
                    help="override each rule's window, in minutes")
    ap.add_argument("--all", action="store_true",
                    help="run monitor-mode rules too, not just runner-mode")
    ap.add_argument("--size", type=int, default=500)
    ap.add_argument("--state-file", type=Path, default=DEFAULT_STATE,
                    help="canary.py heartbeat state file")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    rules = [r for r in all_rules() if args.all or r.mode == "runner"]
    absence = [r for r in rules if r.fires_on == "absence"]
    presence = [r for r in rules if r.fires_on != "absence"]

    # Absence rules first: whether the pipeline is delivering at all decides
    # how to read everything printed after it.
    inconclusive = False
    for rule in absence:
        window = args.window or rule.window_minutes
        try:
            _, matched = evaluate(base, rule, window, args.size)
        except SearchUnavailable as exc:
            print(f"\n{rule.id}  {rule.severity}  [CANNOT EVALUATE]")
            print(f"    OpenSearch is unreachable: {exc}")
            inconclusive = True
            continue
        if report_absence(rule, matched, window, args.state_file):
            inconclusive = True

    total_alerts = 0
    for rule in presence:
        window = args.window or rule.window_minutes
        try:
            candidates, matched = evaluate(base, rule, window, args.size)
        except SearchUnavailable as exc:
            print(f"\n{rule.id}  {rule.severity}  [CANNOT EVALUATE]")
            print(f"    OpenSearch is unreachable: {exc}")
            inconclusive = True
            continue
        total_alerts += len(matched)
        report_presence(rule, candidates, matched)

    print(f"\ntotal alerts: {total_alerts}")

    if inconclusive:
        print(
            "\n"
            "!! INCONCLUSIVE - the results above are NOT a pass.\n"
            "   A pipeline heartbeat is missing or OpenSearch could not be\n"
            "   queried, so 'zero alerts' here means 'nothing arrived to look\n"
            "   at', not 'nothing happened'. Resolve the cause above and\n"
            "   re-run before drawing any conclusion from these numbers."
        )
        return EXIT_INCONCLUSIVE

    return EXIT_ALERTS if total_alerts else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
