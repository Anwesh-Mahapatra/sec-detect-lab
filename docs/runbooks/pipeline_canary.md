# PIPELINE_CANARY — detection pipeline heartbeat missing

**Severity:** HIGH · **MITRE:** T1562.008 · **Mode:** runner · **Fires on:** absence

This rule fires because something did **not** arrive. Every other rule in this
repo fires because something did.

## What it means

`tools/canary.py` writes a uniquely named configmap into the `detection-canary`
namespace every 5 minutes. That write is guaranteed to be audited, so its
arrival in OpenSearch proves the whole transport is alive:

```
apiserver → /var/log/k3s-audit/audit.log → Fluent Bit → Kafka → Cribl → OpenSearch
```

No heartbeat inside the window means that chain is broken. **Every other
detection result from the same run is inconclusive, not clean** — they returned
zero because nothing arrived to evaluate, not because nothing happened.

## First: which half is broken?

`run_detections.py` already tells you, using the state file that `canary.py`
touches *before* the pipeline is involved. Read the `cause` line:

| `cause` | Meaning | Where to look |
|---|---|---|
| `GENERATOR` | `canary.py` is not running. The transport may be perfectly healthy — nothing is feeding it. | the cron/systemd timer |
| `TRANSPORT` | The generator beat recently, but nothing reached the index. | Fluent Bit → Kafka → Cribl |

Do not skip this. The two need opposite responses, and they are indistinguishable
from the index alone.

## GENERATOR — the heartbeat was never written

```bash
uv run python tools/canary.py            # does a manual beat work?
crontab -l | grep canary                 # is it scheduled?
```

If the manual beat fails, the problem is kubectl or the apiserver, not
detection. If the manual beat succeeds, the schedule is dead — restart it and
re-run the detections.

## TRANSPORT — the write happened but never landed

Walk the chain in order. The first counter that has stopped moving is the break.

```bash
# 1. did it reach disk? (root-only)
sudo tail -5 /var/log/k3s-audit/audit.log | grep detection-canary

# 2. is Fluent Bit reading and shipping? port 2020 is not published
docker run --rm --network sec-detect-lab_secnet curlimages/curl:latest \
  -s http://fluent-bit:2020/api/v1/metrics

# 3. is Kafka still receiving, and is Cribl still consuming?
docker exec kafka kafka-get-offsets --bootstrap-server kafka:29092 \
  --topic logs.k8s-audit
docker exec kafka kafka-consumer-groups --bootstrap-server kafka:29092 \
  --describe --group cribl-logpipe

# 4. is Cribl alive and writing?
docker compose ps cribl
curl -s localhost:9200/logs-k8s-audit/_stats/indexing | \
  python3 -c "import sys,json;print(json.load(sys.stdin)['_all']['primaries']['indexing'])"
```

Common causes, most likely first:

- **Cribl lost its config.** It lives in a Docker volume, not in the repo. A
  `docker compose down -v` wipes it and every container still reports healthy.
- **Consumer lag climbing.** Cribl is up but not keeping pace, or its Kafka
  input is disabled.
- **Fluent Bit position DB confusion after log rotation.** See FINDINGS C9.
- **Bulk rejections dropped silently.** `index_failed` climbing with nothing
  logged — FINDINGS B13.

## If the run said `CANNOT EVALUATE` instead

That is **not** this rule firing. It means the `_search` call failed, so
OpenSearch itself is unreachable and no rule was evaluated at all — the cluster
never answered, rather than answering with no canary in it.

```bash
docker compose ps opensearch
curl -s localhost:9200/_cluster/health
```

## Resolving

The canary self-heals: once the transport recovers, the next beat lands and the
rule stops firing. There is nothing to acknowledge or clear. Re-run
`uv run python tools/run_detections.py --all` and confirm exit code 0.

Leftover configmaps from runs that died between create and delete are harmless
and collected by `uv run python tools/canary.py --sweep`.

## Why this rule can never be an OpenSearch monitor

`deploy.py` renders `ctx.results[0].hits.total.value >= threshold`. For an
absence rule that is inverted — it would fire whenever the pipeline is healthy
and go quiet exactly when it breaks. `deploy.py` refuses `fires_on="absence"`
rules explicitly. There is also a deeper reason: a monitor that must fire when
its own query returns nothing depends on the alerting plugin inside the very
cluster whose ingest is in question.
