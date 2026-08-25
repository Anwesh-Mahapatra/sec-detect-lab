#!/usr/bin/env python3
"""
Refresh the index mapping snapshot that CI validates rule fields against.

Run this whenever the Cribl normalization pipeline changes shape, then commit
the diff. The diff itself is the useful artefact: it shows exactly which fields
appeared or vanished, and any rule referencing a vanished field fails CI on the
same commit rather than silently returning zero forever.

  python3 tools/snapshot_mapping.py
"""

import argparse
import json
from pathlib import Path

from _http import session as requests

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "index_mapping.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9200")
    ap.add_argument("--index", default="logs-k8s-audit")
    args = ap.parse_args()

    r = requests.get(f"{args.url.rstrip('/')}/{args.index}/_mapping", timeout=15)
    r.raise_for_status()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(r.json(), indent=2, sort_keys=True) + "\n")

    props = next(iter(r.json().values()))["mappings"].get("properties", {})
    print(f"wrote {OUT}  ({len(props)} top-level fields)")
    print("review the diff before committing - a removed field means a rule broke")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
