#!/usr/bin/env python3
"""
Prove each rule's Query DSL agrees with its Python logic, against real OpenSearch.

Unit tests prove rule() is correct. They say nothing about whether the query
prefilter actually retrieves the events rule() would fire on. If the query is
narrower than the logic, the rule passes every test and alerts on nothing - the
exact silent failure this whole lab exists to document.

Run after load_fixtures.py. For each rule:
  every true-positive fixture must be returned by the query
  the query must not drown in false-positive fixtures it should have excluded

  python3 tools/validate_queries.py --url http://localhost:9200
"""

import argparse

from _http import session as requests
from detections import all_rules
from detections.base import Rule


def ids_matching(base: str, rule: Rule) -> set[str]:
    body = {
        "size": 200,
        "query": {"bool": {"filter": [
            rule.query,
            {"term": {"_fixture.rule_id": rule.id}},
        ]}},
        "_source": ["_fixture"],
    }
    r = requests.post(f"{base}/{rule.index}/_search", json=body, timeout=30)
    r.raise_for_status()
    return {h["_id"] for h in r.json()["hits"]["hits"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    failures: list[str] = []

    for rule in all_rules():
        retrieved = ids_matching(base, rule)
        expected_tp = {f"{rule.id}-{i}" for i, c in enumerate(rule.tests) if c.expect}
        expected_fp = {f"{rule.id}-{i}" for i, c in enumerate(rule.tests) if not c.expect}

        missed = expected_tp - retrieved
        leaked = expected_fp & retrieved

        status = "OK"
        if missed:
            status = "FAIL"
            for doc_id in sorted(missed):
                idx = int(doc_id.rsplit("-", 1)[1])
                failures.append(
                    f"{rule.id}: query does NOT retrieve true positive "
                    f"'{rule.tests[idx].name}' - the rule can never fire on it"
                )

        # Leakage is tolerated when rule() is the deliberate second stage.
        note = ""
        if leaked and rule.mode == "monitor":
            status = "FAIL"
            for doc_id in sorted(leaked):
                idx = int(doc_id.rsplit("-", 1)[1])
                failures.append(
                    f"{rule.id}: monitor-mode query retrieves false positive "
                    f"'{rule.tests[idx].name}' - deployed monitor will over-alert"
                )
        elif leaked:
            note = f"  ({len(leaked)} filtered by rule() as designed)"

        print(f"{status:<5} {rule.id:<32} tp={len(expected_tp)} "
              f"retrieved={len(retrieved)}{note}")

    if failures:
        print("\n" + "\n".join(f"  - {f}" for f in failures))
        print(f"\n{len(failures)} query/logic mismatches")
        return 1

    print("\nall queries agree with their Python logic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
