#!/usr/bin/env python3
"""
Bulk-load every rule's fixtures into OpenSearch as real documents.

This is what turns the unit tests into integration tests: the same event that
proves rule() works in Python gets indexed, so validate_queries.py can prove the
Query DSL prefilter finds it too. A rule whose Python logic and query disagree
is the classic silent failure - it passes tests and alerts on nothing.

  python3 tools/load_fixtures.py --url http://localhost:9200
"""

import argparse
import json
from datetime import datetime, timezone

from _http import session as requests
from detections import all_rules


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--index", default="logs-k8s-audit")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = []
    count = 0

    for rule in all_rules():
        for i, case in enumerate(rule.tests):
            doc = dict(case.event)
            # Fixtures are timeless; queries filter on a window. Stamp them now.
            doc.setdefault("@timestamp", now)
            doc["_fixture"] = {
                "rule_id": rule.id,
                "case": case.name,
                "expect": case.expect,
            }
            lines.append(json.dumps({"index": {"_id": f"{rule.id}-{i}"}}))
            lines.append(json.dumps(doc))
            count += 1

    payload = "\n".join(lines) + "\n"
    r = requests.post(
        f"{base}/{args.index}/_bulk?refresh=true",
        data=payload,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=60,
    )
    r.raise_for_status()
    body = r.json()

    if body.get("errors"):
        failed = [i for i in body["items"] if i.get("index", {}).get("error")]
        for item in failed[:10]:
            print("FAILED", json.dumps(item["index"]["error"]))
        print(f"\n{len(failed)}/{count} documents rejected")
        return 1

    print(f"loaded {count} fixture documents into {args.index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
