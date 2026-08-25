# Detection as code

Rules are Python functions. Every rule ships with its own tests. Nothing merges
without passing them, and nothing deploys without merging.

## The loop

```
write rule in VS Code
  └─▶ git push
       └─▶ CI gate 1   unit tests, metadata, schema contract      (~2 s, no OpenSearch)
            └─▶ CI gate 2   real OpenSearch, fixtures loaded,
                            every query proven to retrieve its
                            own true positives                    (~90 s)
                 └─▶ merge to main
                      └─▶ auto-deploy as OpenSearch monitors
```

## Why a Python function and not a YAML rule

A YAML rule can only express what its schema anticipated. The moment a detection
needs an allowlist, a ratio, a lookup or "unless the user agent is X", YAML rules
grow a bolt-on expression language that nobody can unit-test.

A Python function has no such ceiling, and it is testable in milliseconds. This
is the Panther model, and it is why every rule here carries fixtures instead of
a promise that someone eyeballed it.

## Anatomy of a rule

| Piece | What it does |
|---|---|
| `rule(event)` | The detection. Takes one OCSF event, returns `True` to alert. |
| `query` | Query DSL prefilter so OpenSearch narrows the data, not Python. |
| `mode` | `monitor` = query is sufficient, deploys natively. `runner` = Python adds logic the query cannot express. |
| `tests` | Fixtures. At least one true positive **and** one false positive, enforced by CI. |
| `blocked_by` | This rule is correct and cannot fire, because the pipeline never delivers the event. |

## `blocked_by` is the part that matters

Most detection repos contain rules nobody has ever seen fire. They look like
coverage. They are not.

`T1078_IMPERSONATED_READ` is committed in a deliberately broken state. Its logic
is right; the audit policy drops the event before it ever reaches Kafka
(`FINDINGS.md` A3). CI asserts it stays broken, and `deploy.py` refuses to ship
it — because a monitor that structurally cannot fire is worse than an absent one.

When A3 is fixed, that test fails loudly and forces a human to re-validate,
rather than letting everyone assume it was working all along.

## What CI actually enforces

**Gate 1 — logic**
- unique rule ids, owner, runbook, valid severity, well-formed MITRE technique
- at least one true positive and one false positive fixture
- every fixture produces the expected verdict
- the rule survives malformed events instead of taking the run down
- **every field in the query exists in the index mapping** — this is the check
  that catches a field the pipeline silently stopped producing

**Gate 2 — reality**
- spins up real OpenSearch, applies the production index template
- loads every fixture as a real document
- proves each query retrieves its own true positives
- proves monitor-mode queries do not retrieve their own false positives
- renders and deploys every monitor

## Adding a rule

1. Copy `detections/t1552_sa_denied_secrets.py`
2. Change the id, metadata and `rule()` logic
3. Write fixtures **before** the logic — including the one that should not fire
4. `python3 -m pytest tests/ -v`
5. `python3 tools/run_detections.py --all --window 1440` against live data
6. Open a PR

## Commands

```bash
pytest tests/ -v                                  # gate 1, no cluster needed
python3 tools/snapshot_mapping.py                 # refresh the schema contract
python3 tools/load_fixtures.py                    # fixtures into OpenSearch
python3 tools/validate_queries.py                 # query vs logic agreement
python3 tools/run_detections.py --all --window 60 # hunt over live data
python3 tools/deploy.py --dry-run                 # inspect rendered monitors
python3 tools/deploy.py                           # sync to OpenSearch
```

## Current rules

| Rule | MITRE | Severity | Mode | Status |
|---|---|---|---|---|
| `T1552_SA_DENIED_SECRETS` | T1552 | HIGH | monitor | validated on live traffic |
| `T1609_CONTAINER_EXEC` | T1609 | HIGH | runner | validated on live traffic |
| `T1078_IMPERSONATED_READ` | T1078.004 | MEDIUM | monitor | **blocked by A3** |

## Known limitation

OpenSearch has no sequence operator — there is no equivalent to YARA-L's `match`
block or Elastic EQL's `sequence`. "A then B within 5 minutes" is not expressible.

Threshold-over-a-window covers most of it: use a bucket-level monitor keyed on
`actor.user.name`. True ordered correlation needs the `runner` mode, holding
state across executions. Not built yet.
