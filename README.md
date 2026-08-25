# sec-detect-lab

A single-node detection-engineering lab: real k3s API audit logs flowing through a production-shaped pipeline into OpenSearch, normalised to OCSF along the way.

The point of the lab is not the pipeline. It is **silent detection failures** — the places where every component reports healthy while the data is wrong, missing, or misleading. See [`FINDINGS.md`](FINDINGS.md) for a full audit of exactly that.

## Pipeline

```
k3s apiserver ─▶ /var/log/k3s-audit/audit.log
   └─▶ fluent-bit                         tail, Parser json
        └─▶ kafka                         logs.k8s-audit, 3 partitions, rf=1
             └─▶ cribl                    input pipeline masks secrets at the source
                  ├─▶ minio-cold-tier     raw clone, compliance + replay
                  └─▶ k8s-normalize       OCSF 1.3.0, api_activity class 6003
                       └─▶ OpenSearch     logs-k8s-audit
```

Kafka sits between collection and processing so that an OpenSearch outage buffers rather than drops. MinIO holds an unnormalised clone so the raw event survives any downstream schema mistake.

## Layout

| Path | What it is |
|---|---|
| `docker-compose.yml` | Kafka (KRaft), MinIO, OpenSearch, Fluent Bit, Cribl Stream |
| `fluent-bit/fluent-bit.conf` | Edge collector — k8s audit + host syslog to two Kafka topics |
| `k3s/audit-policy.yaml` | The live audit policy the apiserver is running |
| `k3s/config.yaml` | k3s `kube-apiserver-arg` audit flags |
| `cribl/` | Exported Cribl config — inputs, outputs, routes, both pipelines |
| `opensearch/` | Index template as it currently exists |
| `FINDINGS.md` | Gap audit: 33 findings graded by impact, verified against the running stack |
| `test.sh` | Attack-path drill — impersonation, exec, secret reads, RBAC writes, denial |
| `sample.json` | One representative k8s audit event |
| `notes*.txt` | Phase notes — OpenSearch internals, Fluent Bit/Kafka durability, PII strategy |
| `drill-questions.txt` | Interview-style drills with worked answers |
| `pyproject.toml` · `uv.lock` | Python deps and interpreter, pinned. `uv sync --locked` reproduces the exact set locally and in CI, and fails if the two drift apart |

## Running it

```bash
docker compose up -d
docker compose ps -a          # all Up; the two init jobs should show Exited (0)
```

| Service | Where |
|---|---|
| OpenSearch | http://localhost:9200 |
| Cribl Stream UI | http://localhost:19000 |
| MinIO console | http://localhost:9001 |
| Kafka | localhost:9092 |

k3s audit logging is enabled outside compose, via `/etc/rancher/k3s/config.yaml` — see `k3s/config.yaml`. Fluent Bit bind-mounts `/var/log/k3s-audit` read-only.

## Checking whether it is actually working

Container health tells you almost nothing here — that is the lab's whole thesis. The counters that do:

```bash
# what the apiserver emitted (resets on apiserver restart)
kubectl get --raw /metrics | grep apiserver_audit_event_total

# what hit disk
wc -l /var/log/k3s-audit/audit.log

# what Fluent Bit read vs shipped
curl -s fluent-bit:2020/api/v1/metrics

# consumer lag
docker exec kafka kafka-consumer-groups --bootstrap-server kafka:29092 \
  --describe --group cribl-logpipe

# what landed, and what silently failed to
curl -s localhost:9200/logs-k8s-audit/_stats/indexing
```

`FINDINGS.md` sets out the invariants these should satisfy and which two are worth alarming on.

## Caveats

Lab only. Security plugins are disabled on OpenSearch, Kafka is PLAINTEXT, replication factor is 1, and MinIO runs on its default credentials. None of that is safe outside an isolated host. Cribl's encrypted output key is redacted in `cribl/outputs.yml` and needs regenerating locally.
