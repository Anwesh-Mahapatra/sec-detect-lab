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
| `fires_on` | `presence` = alert when matches >= threshold (every attack rule). `absence` = alert when matches < threshold (canaries). |
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
4. `uv run pytest tests/ -v`
5. `uv run python tools/run_detections.py --all --window 1440` against live data
6. Open a PR

## Commands

Dependencies and the interpreter are pinned by `pyproject.toml` + `uv.lock`. `uv run` builds the environment on first use, so there is no activate step and no dependence on the host's Python.

```bash
uv sync                                                  # one-time: create .venv from the lockfile
uv run pytest tests/ -v                                  # gate 1, no cluster needed
uv run python tools/canary.py                            # one pipeline heartbeat (cron: */5)
uv run python tools/snapshot_mapping.py                  # refresh the schema contract
uv run python tools/load_fixtures.py                     # fixtures into OpenSearch
uv run python tools/validate_queries.py                  # query vs logic agreement
uv run python tools/run_detections.py --all --window 60  # hunt over live data
uv run python tools/deploy.py --dry-run                  # inspect rendered monitors
uv run python tools/deploy.py                            # sync to OpenSearch
```

## Current rules

| Rule | MITRE | Severity | Mode | Status |
|---|---|---|---|---|
| `T1552_SA_DENIED_SECRETS` | T1552 | HIGH | monitor | validated on live traffic |
| `T1609_CONTAINER_EXEC` | T1609 | HIGH | runner | validated on live traffic |
| `T1078_IMPERSONATED_READ` | T1078.004 | MEDIUM | monitor | **blocked by A3** |
| `PIPELINE_CANARY` | T1562.008 | HIGH | runner | absence rule — validated on live traffic |

## Zero alerts is not a pass

A clean run is ambiguous. Zero alerts means either "no attacks occurred" or
"nothing is arriving", and every rule in this repo returns zero in both cases.
`PIPELINE_CANARY` is what makes zero readable.

`tools/canary.py` writes a uniquely named configmap into the `detection-canary`
namespace every 5 minutes. That write is guaranteed to be audited, so its
arrival proves the transport is alive end to end. The rule alerts on its
**absence** — inverted logic versus every other rule here.

```bash
uv run python tools/canary.py     # one beat; run from cron every 5 minutes
*/5 * * * * cd /path/to/sec-detect-lab && uv run python tools/canary.py
```

`run_detections.py` evaluates absence rules first, because whether the pipeline
is delivering at all decides how to read everything printed after it. Exit codes:

| Code | Meaning |
|---|---|
| `0` | clean — every rule evaluated, no alerts |
| `1` | alerts fired |
| `2` | usage error (argparse) |
| `3` | inconclusive — a canary is missing, or OpenSearch could not be queried |

`2` is left to argparse deliberately: a mistyped flag must never be readable as
"pipeline dead".

### Limitation 1 — a missing heartbeat is not the same as a failed search

These look similar and are not:

| Output | What actually happened | Response |
|---|---|---|
| `PIPELINE_CANARY ... [FIRING]` | The cluster answered, and had no canary in it. The **transport** is broken. | walk Fluent Bit → Kafka → Cribl |
| `[CANNOT EVALUATE]` | The cluster never answered. **No rule ran at all.** | OpenSearch itself is down |

Collapsing them would let a total OpenSearch outage masquerade as a pipeline
gap, and send you debugging Kafka while the database is simply off. Both exit
`3`, but they print differently and mean different things.

### Limitation 2 — a dead generator looks exactly like a dead pipeline

From the index alone, "`canary.py` stopped running" and "the transport stopped
delivering" are the same observation: no heartbeat. They need opposite
responses — restart a cron, versus go debug the pipeline.

`canary.py` therefore touches a state file (`~/.cache/sec-detect-lab/canary.state`)
on every successful beat, **before the pipeline is involved**. Its mtime
separates the two:

| State file age | Diagnosis printed | Meaning |
|---|---|---|
| within the window | `TRANSPORT` | the generator beat, but nothing landed — the pipeline is broken |
| older than the window, or missing | `GENERATOR` | nothing is feeding the pipeline; it may be perfectly healthy |

Without the state file both cases print the same thing, and half of all canary
alerts send you to the wrong system. Full triage: `docs/runbooks/pipeline_canary.md`.

### Do not run `load_fixtures.py` against a live index

The canary's own fixtures are valid-looking heartbeats. Loaded into the index
the canary watches, they satisfy it — the rule reports `OK` on documents that
never traversed the pipeline, which is precisely the false confidence it exists
to prevent. `load_fixtures.py` is for the throwaway cluster CI builds.

If it has already happened, the fixtures are tagged and removable:

```bash
curl -s -X POST 'localhost:9200/logs-k8s-audit/_delete_by_query?refresh=true' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"_fixture"}}}'
```

### Why the canary is a configmap write, not something harder to silence

The audit policy is first-match-wins. A configmap write falls through to the
generic `verbs: [create, update, patch, delete] → Metadata` rule near the
bottom. An RBAC write would match an earlier rule that sits *above* the two
`level: None` drops, and would therefore be strictly harder to silence — which
is exactly why it is the wrong choice. **A canary must not ride a more
privileged path than the traffic it vouches for**, or it can stay green while
the general write path has gone blind. Reads are not an option at all: the
policy drops them (FINDINGS A3).

The cost of that choice, stated: the canary goes dark if its identity is ever
moved into `system:nodes` or `system:serviceaccounts:kube-system`, because the
generic write rule sits below those drops. That produces a false alarm, never
false confidence — the safe direction — and it makes the canary sensitive to
the policy-ordering regressions in FINDINGS A1.

## Known limitation

OpenSearch has no sequence operator — there is no equivalent to YARA-L's `match`
block or Elastic EQL's `sequence`. "A then B within 5 minutes" is not expressible.

Threshold-over-a-window covers most of it: use a bucket-level monitor keyed on
`actor.user.name`. True ordered correlation needs the `runner` mode, holding
state across executions. Not built yet.
