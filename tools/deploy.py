#!/usr/bin/env python3
"""
Deploy rules to OpenSearch as Alerting monitors.

Idempotent: matches existing monitors by rule id, updates in place, creates only
what is missing. Safe to run on every merge to main.

Only mode="monitor" rules deploy. Runner-mode rules carry Python logic the query
cannot express - they execute via tools/run_detections.py on a schedule instead.
Blocked rules never deploy; a monitor that structurally cannot fire is worse
than no monitor, because it looks like coverage.

  python3 tools/deploy.py --dry-run
  python3 tools/deploy.py --url http://localhost:9200
"""

import argparse
import json
from typing import Any

from _http import session as requests
from detections import all_rules
from detections.base import Rule

SEVERITY_TO_OS = {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3", "LOW": "4", "INFO": "5"}
MONITOR_API = "/_plugins/_alerting/monitors"


def build_monitor(rule: Rule) -> dict[str, Any]:
    """Render a rule into the OpenSearch Alerting monitor schema."""
    windowed_query = {
        "bool": {
            "filter": [
                rule.query,
                {"range": {"@timestamp": {"gte": f"now-{rule.window_minutes}m"}}},
            ]
        }
    }
    return {
        "type": "monitor",
        "name": rule.id,
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": rule.window_minutes, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": [rule.index],
                "query": {"size": 0, "query": windowed_query},
            }
        }],
        "triggers": [{
            "query_level_trigger": {
                "name": rule.title,
                "severity": SEVERITY_TO_OS.get(rule.severity, "3"),
                "condition": {
                    "script": {
                        "source": f"ctx.results[0].hits.total.value >= {rule.threshold}",
                        "lang": "painless",
                    }
                },
                "actions": [],
            }
        }],
    }


def find_existing(base: str, name: str) -> str | None:
    body = {"query": {"bool": {"filter": [{"term": {"monitor.name.keyword": name}}]}}}
    r = requests.post(f"{base}{MONITOR_API}/_search", json=body, timeout=60)
    # 404 here means the alerting config index does not exist yet, i.e. no
    # monitors have ever been created. That is a clean slate, not an error.
    if r.status_code == 404:
        return None
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0]["_id"] if hits else None


def deployable(rule: Rule) -> tuple[bool, str]:
    if rule.blocked_by:
        return False, f"blocked by FINDINGS {rule.blocked_by}"
    if rule.mode != "monitor":
        return False, "runner mode - executes via run_detections.py"
    return True, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    created = updated = skipped = 0
    for rule in all_rules():
        ok, why = deployable(rule)
        if not ok:
            print(f"SKIP    {rule.id:<32} {why}")
            skipped += 1
            continue

        monitor = build_monitor(rule)
        if args.dry_run:
            print(f"DRY-RUN {rule.id:<32} {rule.severity}")
            print(json.dumps(monitor, indent=2))
            continue

        existing = find_existing(base, rule.id)
        if existing:
            r = requests.put(f"{base}{MONITOR_API}/{existing}", json=monitor, timeout=15)
            r.raise_for_status()
            print(f"UPDATE  {rule.id:<32} {existing}")
            updated += 1
        else:
            r = requests.post(f"{base}{MONITOR_API}", json=monitor, timeout=15)
            r.raise_for_status()
            print(f"CREATE  {rule.id:<32} {r.json().get('_id')}")
            created += 1

    print(f"\ncreated={created} updated={updated} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
