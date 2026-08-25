# Silent Detection Failures — pipeline gap audit

**Audited:** 2026-08-23, 21:39–21:49 UTC · **Cluster:** k3s v1.36, single node · **Index:** `logs-k8s-audit`, 37,634 docs · **Ground truth:** `audit.log`, 38,842 events

Every container reports `Up`, OpenSearch is green, Kafka lag is zero, and Fluent Bit reports `dropped_records: 0`. This document records the places where that health signal is lying.

Findings were verified by querying the running cluster, the live audit policy, Fluent Bit's runtime metrics, Kafka consumer-group state, and the OpenSearch index directly — not by reading configuration alone. Where config and observed data disagreed, the disagreement is the finding.

---

## Correction to the assumed topology

The pipeline was described as `Fluent Bit → Kafka → Cribl → Fluent Bit → OpenSearch`. **There is no second Fluent Bit.** Cribl writes directly to the OpenSearch bulk API.

```
k3s apiserver ─▶ /var/log/k3s-audit/audit.log
   └─▶ fluent-bit                         tail, Parser json
        └─▶ kafka                         logs.k8s-audit, 3 partitions, rf=1
             └─▶ cribl                    input pipeline: pre_processing_… (masks secrets)
                  ├─▶ route minio-cold-tier              pipeline: passthru, final:false  ─▶ MinIO
                  └─▶ route k8s_audit_logs_opensearch    pipeline: k8s-normalize
                       └─▶ OpenSearch _bulk              elastic output, direct
```

Reference: `cribl/outputs.yml:71-73` → `http://opensearch:9200/_bulk`.

This matters for loss analysis: there is no Fluent Bit retry or buffer layer protecting the OpenSearch write. The only thing between Cribl and permanent loss is Cribl's own persistent queue plus the bulk-error settings in **B13**.

---

## Reconciliation snapshot (live, 21:49 UTC)

| Stage | Count | How to read it |
|---|---:|---|
| apiserver emitted | 30,807 | Process-lifetime counter, resets on apiserver restart. Apiserver up since Aug 16; log spans from Aug 14, so it is legitimately lower than the file. |
| `audit.log` lines | 38,842 | What actually hit disk. The authoritative denominator. |
| Fluent Bit `tail.0` offset | = file size | Read to EOF, so nothing is stuck. But records emitted < lines read. |
| Kafka end offset | 38,823 | **19 short of the file.** Four of those are provably the oversized RBAC events in A4. |
| OpenSearch docs | 37,634 | Gap vs Kafka is mostly the deliberate `watch` drop (A6). |
| OpenSearch `index_failed` | 0 | No bulk rejections yet. This is the one counter that would reveal B13. |

---

## Class A — makes an attack invisible

These produce no usable record at all. Nothing downstream can recover them.

### A1. The noise-suppression rules sit below the resource rules, so they suppress nothing — and blind everything else

**Where:** `k3s/audit-policy.yaml:25-28` — `level: None` for `system:nodes`, `system:serviceaccounts:kube-system`, `system:apiserver`, `system:kube-scheduler`, `system:kube-controller-manager`

Kubernetes matches rules top-down, first match wins. Rules 1–3 (exec, secrets, RBAC) are resource-scoped with **no user filter** and sit above rules 4–5. The comment "Drop internal chatter - this is 95% of the volume" is false in both directions.

**Direction 1, the noise:** 29,292 of 38,842 events (75.4%) come from identities rules 4–5 claim to drop. Every one lands on a resource matched by rules 1–3.

**Direction 2, the blind spot — the real problem:** for anything *outside* rules 1–3, those identities are `level: None`. An attacker holding any kube-system service account token, or the node credential, can create pods, daemonsets, deployments, CRDs and admission webhooks with zero audit records. The exemption is granted by group membership, and `system:serviceaccounts:kube-system` is auto-assigned to every SA in that namespace.

```
# 29,292 events from "excluded" identities — all on rule 1-3 resources
secrets                9230     clusterroles          4742
clusterrolebindings    4724     rolebindings          4646
roles                  4624     serviceaccounts/token 1326
<nothing else — because everything else is level: None>
```

**Check:** the absence in that list is the finding. There is no pod, deployment, configmap or webhook row for these identities — not because they never touch them, but because those events are never written.

### A2. `deletecollection` is missing from the write-verb rule, so mass deletion is unlogged

**Where:** `k3s/audit-policy.yaml:31-32` — `verbs: ["create","update","patch","delete"]`

`deletecollection` is a distinct audit verb and matches no rule, so it defaults to not-logged. 30 `deletecollection` events exist; all 30 are on `secrets`, `roles`, `rolebindings` — they survived only because rules 2–3 matched them by resource.

`kubectl delete pods --all`, `kubectl delete deployments --all`, and most pointedly `kubectl delete events --all` as anti-forensics are all invisible. Namespace teardown also drives `deletecollection` across every resource type in the namespace; you see the namespace `delete` and none of the contents.

```
# verb distribution across all 38,842 events
watch 36850 · create 1430 · get 300 · list 124
patch 56 · update 38 · deletecollection 30 · delete 10

# every deletecollection, by resource — nothing outside rules 2-3
secrets 10 · rolebindings 10 · roles 10
```

**Check:** `kubectl -n scratch delete configmaps --all`, then grep the audit log for `deletecollection` on configmaps. Currently returns nothing.

### A3. The blanket read-drop takes pods/log, configmaps, nodes/proxy — and all denied reads

**Where:** `k3s/audit-policy.yaml:35-36` — `level: None` / `verbs: ["get","list","watch"]`

This is not a pods rule, it is a verb rule, and it drops considerably more than pods reads. Confirmed silent on: `pods/log` (log reads routinely expose credentials printed by apps), `configmaps` reads, `nodes/proxy` (the kubelet API path), `events` reads, and CRD reads.

**The sharpest consequence is denials.** A forbidden `get`/`list` on any resource outside rules 1–3 is not logged at all. In 38,842 events there are exactly **2** `forbid` decisions. Permission-probing against pods, configmaps or nodes leaves no trace.

**Impersonation is caught in the same net.** The impersonation call in `test.sh:7` (`--as=… get pods`) produced *zero* audit events. The only two impersonated events in the entire log are the `list secrets` denials, which survived via rule 2:

```
system:admin ──as──▶ system:serviceaccount:ocsf-proof-9461:default  list secrets  forbid
system:admin ──as──▶ system:serviceaccount:gap-test-0187:default   list secrets  forbid
(that is the complete set — 2 of 38,842)
```

**Check:** `kubectl --as=system:serviceaccount:default:default get pods`, then diff the audit log. No new line appears. The `test.sh` comment "impersonation (never validated)" is now validated: it is not captured for reads.

### A4. Fluent Bit silently discards every audit line over 32 KB — and those are the RBAC enumeration events

**Where:** `fluent-bit/fluent-bit.conf:38` — `Skip_Long_Lines On`, with `Buffer_Max_Size` unset (defaults to `32k`)

Four lines in the audit log exceed 32 KB. All four are `level: RequestResponse`, `verb: list` on `clusterroles` and `clusterrolebindings` — cluster-wide RBAC enumeration, the canonical first move after landing a credential. They are large precisely *because* they carry the full response object, which is the reason RequestResponse was set in the first place.

All four are absent from OpenSearch. Fluent Bit reports the loss nowhere: `dropped_records: 0`, `errors: 0`, `retries_failed: 0`. The tail DB offset equals the file size, so it looks like a clean full read.

```
95a1e005-…90dc  102,142 B  list clusterroles         OpenSearch hits: 0
e529b83c-…67b3   63,416 B  list clusterrolebindings  OpenSearch hits: 0
f7cda29c-…0f55  102,143 B  list clusterroles         OpenSearch hits: 0
144805c0-…f6cc   63,417 B  list clusterrolebindings  OpenSearch hits: 0
```

They never reached Kafka either, so the MinIO cold tier cannot replay them. This loss is unrecoverable at every downstream stage.

**Check:** `awk 'length($0)>32768' audit.log` to get the auditIDs, then query `auditID.keyword` in OpenSearch. Zero hits for all four. This also directly violates the stated contract at `fluent-bit.conf:4`, "never silently drop".

### A5. Cribl deletes `requestObject` and `responseObject`, so the RequestResponse policy level buys nothing

**Where:** `cribl/pipelines/k8s-normalize/conf.yml:52-131` — the `out` object never copies them, then line 130 wipes every non-underscore field

Policy rule 3 logs all RBAC resources at `RequestResponse` (21,075 events at the expensive level) specifically to capture what a role or binding grants. The pipeline then discards it. In OpenSearch a `patch clusterrolebindings` (4 in the log) is a content-free row: you can see that a binding changed, never that it changed to `cluster-admin`.

**One correction in the policy's favour:** rule 1 is a different case. `pods/exec` events carry *no* request or response object even at RequestResponse — the exec command lives in `requestURI`, which the pipeline does keep. So rule 1's expensive level is unnecessary rather than wasted; rule 3's is genuinely lost.

```
audit.log  pods/exec  RequestResponse  reqObj=False respObj=False
           requestURI: /api/v1/namespaces/default/pods/test/exec
                       ?command=%2Fbin%2Fsh&container=test&tty=true   ← the signal is here

audit.log  clusterroles  RequestResponse  reqObj=False respObj=True   ← discarded by Cribl
```

**Check:** the raw object survives in the MinIO cold tier (the clone happens before `k8s-normalize`), so this is recoverable by replay but not queryable. See C8 for how far back that replay actually reaches.

### A6. The `watch` drop is unconditional, so a hostile watch on secrets is discarded with the controller noise

**Where:** `cribl/pipelines/k8s-normalize/conf.yml:7-10` — `drop` where `verb == 'watch'`

36,850 of 38,842 events (94.9%) are `watch`. Dropping them is the right instinct given A1 floods the log with controller traffic, but the filter keys on verb alone. An attacker running `kubectl get secrets --watch -A` — a live feed of every secret in the cluster — is dropped by the same rule that drops traefik's reconcile loop.

This also resolves an open item: watch events are not merely mis-timestamped in OpenSearch, they are **not there at all**. The six that exist predate the drop function (`conf.yml` mtime 21:18:33Z; those docs are 21:06–21:08).

**Check:** `{"term":{"api.operation.keyword":"watch"}}` returns 6, all before 21:18:33Z, none after. The `watch:2` entry in the VERB map at `conf.yml:33` is now dead code.

### A7. Metadata level on writes hides everything that makes a write dangerous

**Where:** `k3s/audit-policy.yaml:31-32` — `level: Metadata` for all create/update/patch/delete

Metadata records that an object was written, never what was in it. In this cluster:

- **Pod creation** (3 events) — no `privileged`, `hostPID`, `hostNetwork`, `hostPath`, no image. A pod mounting the host root filesystem is byte-identical to an nginx pod.
- **Admission webhook writes** — you would see that a `ValidatingWebhookConfiguration` was patched, not that it now points at an attacker endpoint or carries a `namespaceSelector` bypass.
- **CRD writes** (8 events) — no schema, no scope.
- **CSR create/approve** — the CN and O fields decide whether a signed cert lands in `system:masters`. Not captured.
- **`subjectaccessreviews`** (8 events) — permission enumeration is logged, but *what* was probed lives in the request body. You get "someone ran can-i" with no subject.

**Judgment call, and a trap:** the obvious fix is raising these to RequestResponse. Do **not** do that for `serviceaccounts/token` — the TokenRequest response body contains the live JWT, and you would be writing usable bearer tokens into Kafka, MinIO and OpenSearch. Metadata is the correct level there; the right targets are pods, webhooks, CRDs and CSRs.

---

## Class B — makes data wrong or misleading

The record exists but does not say what a rule author would assume. These produce confidently wrong answers rather than empty ones.

### B1. `_time` is mapped as float32 and drifts by ~58 seconds

**Where:** no index template mapping, so dynamic mapping picks `float` for a JSON number with a decimal. Set at `cribl/pipelines/k8s-normalize/conf.yml:132` — `__e._time = endMs / 1000`

A 32-bit float cannot hold a 13-significant-digit epoch. Two events 600 ms apart both index to the identical value. `_source` looks perfectly correct — only the indexed value is wrong, so this survives eyeball review.

```
_source _time  = 1787521478.308  →  21:44:38.308
indexed _time  = 1787521536.0    →  21:45:36      drift +57.7 s

_source _time  = 1787521478.908  →  21:44:38.908
indexed _time  = 1787521536.0    →  21:45:36      drift +57.1 s
                 ↑ two distinct events, one indexed value
```

**Check:** search with `"docvalue_fields":["_time"]` and compare against `_source._time`. The OCSF `time`/`start_time`/`end_time` fields are integers, map to `long`, and are exact — so only `_time` is affected. It happens to be Cribl's canonical time field and a natural choice for a dashboard.

### B2. There is no mapping at all — the only template sets replica count

**Where:** template `logs-lab`, pattern `logs-*`, contents: `number_of_replicas: 0`. No `mappings` block, no component templates, no legacy templates. See `opensearch/index-template-logs-lab.json`.

All 261 leaf fields were inferred from whichever document arrived first. This is the root cause of B1, B10, B11 and the latent `ignore_above` exposure in B12, and it means field types are decided by accident and then frozen.

**Check:** `GET /_index_template` and `GET /_component_template` — both effectively empty. Field count is 261 against the default 1000 limit, so no immediate pressure, but `unmapped.user_extra.*` is an unbounded key space (5 keys today; an OIDC authenticator emits arbitrary claims).

### B3. The index holds two incompatible schemas; 99.9% of it is un-normalized

Any detection written against OCSF field names matches 51 documents out of 37,634. The raw documents carry `verb`, `objectRef.*`, `user.username`, `sourceIPs` and no OCSF fields whatsoever. There is no overlap: no document has both.

```
docs with verb           (raw k8s)   37,583   Aug 14 17:19 → Aug 23 20:31
docs with api.operation  (OCSF)          51   Aug 23 21:06 → 21:44
docs with both                            0
docs with neither                         0
```

**Check:** two `exists` queries. Worth deciding deliberately whether to reindex the 37,583 or start a clean index behind an alias — see Q2.

### B4. `severity_id` is not merely binary — it is inverted

**Where:** `cribl/pipelines/k8s-normalize/conf.yml:66-67` — `statusId === 2 ? 2 : 1`

Because severity derives purely from HTTP status, a *successful* attack always ranks below a *failed* typo. Two real documents from this audit, 600 ms apart:

```
kubectl get secrets -A            (every secret in the cluster)
  status 200 → status_id 1 → severity_id 1  "Informational"

kubectl get secret does-not-exist (a typo)
  status 404 → status_id 2 → severity_id 2  "Low"
```

The same inversion applies to the 1,326 successful token mints, the successful `patch clusterrolebindings`, and every successful exec — all Informational. Sorting a triage queue by severity puts noise on top.

**Check:** aggregate `severity_id` over the normalized docs — 49 at 1, 2 at 2, and the two at 2 are both benign denials.

### B5. Counting rows inflates every number by ~90%

**Where:** `omitStages` excludes only `RequestReceived`, so `ResponseStarted` is retained for every long-running request.

18,406 auditIDs have two rows, 2,030 have one. 20,436 logical requests are represented as 38,842 rows.

It lands hardest on the highest-value signal. There are **2** exec sessions in the index, stored as **4** rows, split across two encodings so no single query finds both (B7):

```
b63ddd96…  ResponseStarted  activity_id 2   21:11:08.201
b63ddd96…  ResponseComplete activity_id 2   21:11:08.234
f845b657…  ResponseStarted  activity_id 99  21:23:11.253
f845b657…  ResponseComplete activity_id 99  21:23:11.288
           2 sessions · 4 rows · 2 encodings
```

**Check:** `"cardinality":{"field":"metadata.correlation_uid.keyword"}` returns 48 against 51 rows. `metadata.uid` is correctly built as `auditID:stage` for exactly this purpose — it just is not used as the document ID (B14).

### B6. Three more `activity_id` collisions

**Where:** `cribl/pipelines/k8s-normalize/conf.yml:33-34` — the VERB map

- **`4` = `delete` and `deletecollection`.** In the normalized docs: 6 deletecollections and 2 deletes, indistinguishable. Deleting one rolebinding and deleting every rolebinding in a namespace are the same number.
- **`2` = `get`, `list`, `watch`.** A targeted `get secret/db-creds` and a cluster-wide `list secrets` are the same activity. Recoverable only via the `resources[0].name === type` guard the code comment describes.
- **`1` = every create.** Confirmed at scale: 1,326 `serviceaccounts/token` mints, filed identically to creating a configmap.

**Check:** `terms` agg on `activity_id` nested under `resources.type.keyword`. Note `VERB.deletecollection` is nearly dead code anyway — A2 means those events mostly do not exist.

### B7. Both exec encodings coexist and nothing marks which generation a document belongs to

`activity_id` 2 and 99 are both present for `pods/exec`. The remediation problem is that there is no version marker to select on. `metadata.version` is hardcoded `'1.3.0'` at `conf.yml:97` — the OCSF schema version, constant across all generations, not a pipeline generation.

The index contains at least three generations: raw (pre-20:31), normalized-without-watch-drop (21:06–21:18), normalized-with-watch-drop (21:18+).

**Check:** the only way to separate them today is `@timestamp` ranges cross-referenced against config file mtimes in the Cribl container. Not a durable basis for a detection rule.

### B8. `unmapped.authz_reason` is empty for 100% of `system:masters` activity

The RBAC authorizer returns a reason string; the superuser path returns an empty string. Since `system:admin` is in `system:masters`, the field is blank for the most privileged actor in the cluster.

```
system:masters      reason empty/missing   21,249   reason populated       0
non-masters         reason empty/missing      917   reason populated  16,666
```

A rule like `authz_reason: *ClusterRoleBinding*` — a reasonable way to find who granted what — structurally cannot match admin activity.

**Check:** the marker documents from this audit show `"authz_reason": ""` for a `system:admin` secret list.

### B9. The exec command is URL-encoded, and the analyzer makes it unsearchable

The one place the exec command survives (A5) is `requestURI`, and it arrives percent-encoded. The standard analyzer splits on `%`, gluing the encoded slash onto the adjacent token: `%2Fbin%2Fsh` becomes `2fbin`, `2fsh`. Nothing in the pipeline decodes it.

```
tokens: api · v1 · namespaces · default · pods · test · exec
        command · 2fbin · 2fsh · container · test · stdin · true

match_phrase requestURI:"/bin/sh"   →  0 hits
match_phrase requestURI:"bin"       →  0 hits
match_phrase requestURI:"2fbin"     →  12 hits   ← the events are there
```

**Check:** the `_analyze` API against `http_request.url.url_string` reproduces this without touching data. Any rule hunting for shell paths in exec calls returns clean and finds nothing.

### B10. `status_code` is a string while `api.response.code` is a number

**Where:** `conf.yml:63` — `String(rs.code)` vs `conf.yml:88` — `rs.code`

Two representations of the same value with different types. `status_code` maps to text+keyword, so a range query over it compares lexicographically rather than numerically — `"99" > "500"`. Use `api.response.code` for anything numeric; `status_code` is safe only for exact term matches.

### B11. `src_endpoint.ip` is text, not the `ip` type — CIDR queries are impossible

Consequence of B2. You cannot ask "which requests came from outside the pod CIDR", one of the few network-level questions this dataset can answer (three distinct source IPs today: `127.0.0.1`, `10.42.0.14`, `10.42.0.8`).

**Check:** `{"term":{"src_endpoint.ip":"10.42.0.0/16"}}` — CIDR notation is only interpreted on a field of type `ip`; on text it is a literal string match and returns nothing.

### B12. Four fields are absent rather than empty, so equality filters silently exclude rows

- **`actor.user.domain`** (`conf.yml:75`) — set only for service accounts. Absent for every human user, so any query grouping by domain drops human activity entirely.
- **`src_endpoint.ip`** (`conf.yml:81`) — when `sourceIPs` is empty the code emits `{name:'unknown'}`, so the `ip` key is missing rather than null.
- **`unmapped.authz_decision`** — missing on 4 `ResponseStarted` events (status subresources). A filter on `decision: "allow"` excludes them.
- **`unmapped.original_user` / `invoked_by`** (`conf.yml:78,112`) — `undefined` unless impersonating, which is correct, but means `invoked_by` exists on 2 documents total.

**On `ignore_above`:** real but not currently firing. `authz_reason` maxes at 185 chars and `requestURI` at 215, both under the 256 default. The failure mode when it does trigger is quiet in a specific way: the document still indexes and `match` still works, but the `.keyword` subfield is skipped, so `term` queries and `terms` aggregations miss exactly the longest values. RBAC reason strings grow with role and binding names.

### B13. Per-document bulk failures are dropped and not logged

**Where:** `cribl/outputs.yml:68` — `retryPartialErrors: false`; `cribl/outputs.yml:15` — `failedRequestLoggingMode: none`

OpenSearch returns HTTP 200 for a bulk request in which individual documents failed — a mapping conflict, or an `es_rejected_execution_exception` under load. The `responseRetrySettings` block handles HTTP-level status codes only; per-document errors inside a 200 are governed by `retryPartialErrors`, which is off. Those documents are discarded, and the second setting ensures nothing is written about it.

Cribl is even configured to *ask* for the error detail — `filter_path: errors,items.*.error,…` at `outputs.yml:60-62` — and then does nothing with it.

Given B2 (everything dynamically mapped), a mapping conflict is a realistic trigger: one document with an unexpected type for an existing field is enough.

**Check:** `GET /logs-k8s-audit/_stats/indexing` → `index_failed`. Currently **0**, and the write threadpool shows `rejected: 0` — so this has not fired yet. That counter is the only existing surface for it.

### B14. No document ID, so replay and retry produce duplicates

**Where:** `cribl/outputs.yml:66-67` — `includeDocId: false`, `writeAction: create`

With no `_id`, `create` auto-generates one, so it behaves as an append. Any Cribl retry after a timeout that actually succeeded, or any Kafka consumer-group offset reset (`fromBeginning: true` at `cribl/inputs.yml:12`), writes duplicate documents that nothing can collapse.

The ingredient for idempotency already exists and is unused: `metadata.uid` is built as `auditID + ':' + stage` at `conf.yml:99`, with the comment "unique per row" — exactly a document ID.

**Check:** compare `_count` against `cardinality` of `metadata.uid.keyword`. Equal today, because no replay has happened yet.

### B15. Microsecond precision is preserved in the comment, not in the index

**Where:** `conf.yml:101` — `original_time: __e.stageTimestamp,  // full microsecond precision, kept as string`

The intent is right and the `_source` value does keep all six digits. But dynamic mapping typed the field as `date`, and OpenSearch dates are millisecond-resolution, so the indexed value is truncated. Sorting or aggregating on `metadata.original_time` gives millisecond granularity, and events within the same millisecond become unorderable. Recoverable per document, not queryable.

**Check:** mapping shows `metadata.original_time: date`. To keep the stated behaviour it needs to be `keyword`, or a second field.

---

## Class C — untidy

Real, but nothing here makes an attack invisible or an answer wrong today.

**C1. Kafka partitioning is 90% skewed onto one partition.** Three partitions exist so Cribl worker threads can process in parallel. They cannot — the Fluent Bit Kafka output sets no `Message_Key`.
`partition 0 · 2,014 | partition 1 · 34,925 | partition 2 · 1,882`

**C2. `logs.host-syslog` has a producer and no consumer.** Fluent Bit has shipped 453,121 syslog records (63.7 MB on disk). Cribl's Kafka input subscribes only to `logs.k8s-audit` (`cribl/inputs.yml:9-10`). Write-only, ages out at the broker default of 7 days.

**C3. No per-topic retention bytes cap.** `kafka-configs --describe` on `logs.k8s-audit` returns no dynamic config, so only the 168-hour broker default applies. "Bounded retention" is time-bounded, not size-bounded.

**C4. Cribl cannot alert — notifications are license-blocked.** `warn conf:notifications | notifications are prohibited by the current license`. Its logs are otherwise clean: 3 errors in 24h, all `rest:expression | API Error` from UI preview work, none from the pipeline.

**C5. Prototype-chain lookups in the two dispatch maps.** `conf.yml:40,42` — `HIGH_RISK_SUB[o.subresource]` and `VERB[__e.verb]` are plain-object lookups. A value of `constructor` or `toString` returns an inherited function (truthy), so `activity_id` would become a function. Unreachable in practice because both values come from the apiserver's fixed vocabulary.

**C6. The secret mask is redundant on the OpenSearch path, load-bearing on the MinIO path.** `cribl/pipelines/pre_processing_…/conf.yml:14-19`. `k8s-normalize` deletes those fields anyway (A5). Keep it for MinIO — but its scope is `objectRef.resource == 'secrets'` only, so a pod spec with credentials in `env` reaches MinIO unmasked.

**C7. Dead code.** `VERB.watch` (dropped two functions earlier), `VERB.deletecollection` (A2). The `statusId = 0` branch at `conf.yml:47` is also unreachable, but its comment says so and explains why it is kept — the right call.

**C8. The cold tier is not yet a replay source.** MinIO holds 117 objects, 120 KiB, oldest 20:29 today (route enabled at `route.yml` mtime 20:29:02Z). It cannot replay anything before that, and structurally cannot recover the A4 losses.

**C9. Log rotation is configured but untested.** `audit-log-maxsize=100` MB with `maxbackup=10`; the file is at 42 MB and has never rotated (`files_rotated: 0` for `tail.0`). Fluent Bit's default `Rotate_Wait` is 5 seconds — if it is behind by more than that when k3s renames the file, the tail of the old file is lost. The syslog input has exercised rotation; the audit input has not.

**C10. OCSF fields absent beyond `dst_endpoint`.** Confirmed absent: `dst_endpoint.*`, `actor.session`, `actor.process`, `resources.uid`, `cloud.provider`. `objectRef.uid` exists in the raw events and would populate `resources.uid` — the cheapest of these to add, and useful because it survives object recreation under the same name.

---

## Class D — the tooling itself

The pipeline is not the only thing that can fail silently. So can the tooling
that queries it, tests it, and vouches for it: a rule that behaves differently
on two machines is the same class of defect as a mapping that indexes the wrong
type, and a control defeated by its own test harness is worse than both.

### D1. `_search` returns chunked gzip, and one host's urllib3 hangs on it forever

**Where:** `tools/_http.py` — every tool routes through a session that sets
`Accept-Encoding: identity`.

OpenSearch compresses `_search` responses and streams them without a length,
which is the specific shape that hung. Other endpoints do not, which is why the
bug looked intermittent:

```
logs-k8s-audit/_search?size=200  →  content-encoding: gzip   transfer-encoding: chunked   ← no Content-Length
_cluster/state                   →  content-encoding: gzip   content-length: 10469
_nodes/stats                     →  content-encoding: gzip   content-length: 4348
logs-k8s-audit/_mapping          →  content-encoding: gzip   content-length: 703
```

`_search` is the hot path — `run_detections.py`, `validate_queries.py` and
`deploy.py` all call it — so the affected shape is the one the detections
depend on. On the affected machine the read never returned; identity encoding
returned in milliseconds.

**It did not reproduce on any PyPI build.** Measured against this cluster,
2,117 live documents, `size=200` and `size=2000` (multi-MB):

| Python | urllib3 | `identity` | `gzip` (chunked) |
|---|---|---|---|
| 3.12 | 2.7.0 | 0.039 s | 0.048 s |
| 3.14 | 2.0.7 | 0.032 s | 0.033 s |
| 3.13 | 2.0.7 | — | 0.238 s (2000 hits) |
| 3.14 | 2.0.7 | — | 0.239 s (2000 hits) |

So the trigger is **not** "Python 3.14" and **not** "urllib3 2.0.7" — both are
fine from PyPI. It is that host's *packaging* of urllib3 (Debian's patched
build), which was never isolated further.

**Why the workaround is retained even though the bug will not occur.** The
project now pins Python 3.12 and resolves urllib3 from PyPI through `uv.lock`,
so the affected interpreter and the affected package build are both excluded by
construction. That is the real fix. The header is kept anyway for two reasons:
non-reproduction is not proof of absence, since the root cause was never
identified — only the conditions under which it failed to appear; and the
tools remain runnable as `python3 tools/run_detections.py` outside uv, which is
the exact invocation that hit the bug. The cost of being wrong is a detection
run that hangs forever with no error. The cost of the workaround is one request
header on responses of a few hundred KB.

**The skew itself was the finding.** CI ran 3.12 and never saw this; one laptop
ran 3.14 and saw it every time. A detection pipeline that disagrees with itself
across two machines is indistinguishable from one that works, right up until it
matters. `.python-version` + `uv.lock` + `uv sync --locked` in CI remove the
class, not just this instance.

**Check:** with a live cluster, compare the two encodings against `_search` —
a hang under `gzip` that clears under `identity` is this bug returning:

```bash
uv run python - <<'PY'
import time, requests
for enc in ("identity", "gzip"):
    s = requests.Session(); s.headers.update({"Accept-Encoding": enc})
    t = time.time()
    r = s.post("http://localhost:9200/logs-k8s-audit/_search",
               json={"size": 200, "query": {"match_all": {}}}, timeout=20)
    print(enc, len(r.json()["hits"]["hits"]), f"{time.time()-t:.3f}s")
PY
```

### D2. Test fixtures loaded into a live index register as genuine heartbeats

**Where:** `tools/load_fixtures.py` writes every rule's fixtures into
`rule.index`, which defaults to the production index `logs-k8s-audit`.
`PIPELINE_CANARY`'s true-positive fixtures are, by construction, valid-looking
heartbeats.

The canary exists to prove the pipeline is delivering. Loading its own fixtures
into the index it watches satisfies it with documents that never traversed the
pipeline at all. **The control that proves the pipeline is alive is defeated by
the tooling that tests it** — and it fails green, so nothing surfaces.

Observed while validating the canary against the running stack: of 20 fixture
documents loaded, **5 landed in the `detection-canary` namespace** and counted
as heartbeats. The rule reported `OK` on a pipeline that was, at that moment,
not being measured at all.

```
loaded 20 fixture documents into logs-k8s-audit
  canary docs that are FIXTURES: 5      <- indistinguishable from real beats
deleted fixture docs: 20 | failures: 0
```

**Presence and absence rules fail in opposite directions from the same cause.**
This is the part worth internalising, because it inverts the usual intuition
about which failure you will notice:

| Cause | Presence rule (every attack rule) | Absence rule (the canary) |
|---|---|---|
| Fixtures loaded into the live index | fires on fixture true-positives — a **loud** false alert you investigate and dismiss | goes quiet — a **silent** false all-clear you never look at |
| Query references a field the pipeline stopped producing | retrieves nothing, never fires — silent false negative | retrieves nothing, fires **forever** — loud false positive |

So the same broken field that makes a detection quietly stop working makes a
canary scream, and the same pollution that makes a detection scream makes a
canary quietly lie. Neither rule type is safe on its own; they fail in
complementary directions, which is the argument for running both.

A practical consequence: `tools/validate_queries.py` matters *more* for an
absence rule than a presence one. For a presence rule a broken query is a
silent gap; for an absence rule it is a pager that never stops.

**Check:** fixtures are tagged, so pollution is detectable and reversible.

```bash
curl -s localhost:9200/logs-k8s-audit/_count -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"_fixture"}}}'          # pass = 0

curl -s -X POST 'localhost:9200/logs-k8s-audit/_delete_by_query?refresh=true' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"_fixture"}}}'          # remove them
```

`load_fixtures.py` is meant for the throwaway cluster CI builds, where the index
holds nothing else. Pointing it at a live index is the mistake; the tagging is
what makes that mistake recoverable rather than permanent.

---

## Hypotheses killed — verified fine

Recorded so they do not get re-investigated.

- **The policy on disk is the running policy.** File mtime Aug 14 22:48 IST, apiserver started Aug 16 04:03 IST. No drift.
- **`Date.parse` handles k8s microsecond timestamps correctly.** `Date.parse("…T21:06:42.622780Z")` returns a clean epoch, truncating to milliseconds. No `NaN`, no offset. Verified on V8 directly. This was flagged as a suspected edge case; it is not one.
- **The pipeline is live end-to-end.** A marker read landed in OpenSearch within 10 seconds. An apparent multi-hour stall on first inspection was a timezone artifact — the host renders IST, every container and OpenSearch render UTC.
- **No apiserver-side audit loss.** `audit-log-mode` is unset, so it defaults to `blocking` — no batch buffer to overflow. `apiserver_audit_requests_rejected_total` is 0.
- **No OpenSearch bulk rejections.** `index_failed: 0`, write threadpool `rejected: 0`. B13 is latent, not active.
- **`ignore_above` is not currently truncating anything.** Max lengths: `authz_reason` 185, `requestURI` 215, both under 256.
- **`sourceIPs` is length 1 on all 38,842 events.** Nothing is being discarded today.

---

## Documented tradeoffs — re-assessed

| Position | Verdict | Reasoning |
|---|---|---|
| `severity_id` is binary, carries no resource sensitivity | **Re-file** | Not just absent signal — actively inverted. Successful secret enumeration ranks below a 404 (B4). |
| `sourceIPs[0]` only, rest discarded | **Re-file** | Index `[0]` is the *least* trustworthy element. Kubernetes builds the array from `X-Forwarded-For` first, then the real TCP peer last — so `[0]` is client-settable and the trustworthy value is the one dropped. Harmless today (all arrays length 1), but backwards by default. |
| Watch events stamped at `stageTimestamp`, potentially minutes late | **Re-file** | True but moot for OpenSearch — watches are dropped entirely (A6). Still applies to MinIO. Observed `duration` on watch ResponseComplete: 493,002 ms. `duration` means "session length" on one row and "time to first byte" on the other row of the same request. |
| `serviceaccounts/token` files as generic Create | **Agree** | Confirmed, 1,326 events. Metadata level also hides `expirationSeconds` and `boundObjectRef` — and raising the level would write live JWTs into three systems. Keep the level; fix the classification. |
| No `dst_endpoint` | **Agree** | Low value on a single-node cluster with one API server. `resources.uid` is a better use of the same effort (C10). |
| Index holds both exec encodings (2 and 99) | **Agree** | Confirmed. The gap is that nothing marks generation (B7). The 99 promotion itself is a good call and stays valid OCSF. |
| Policy drops pods reads and pods/log | **Agree, incomplete** | Confirmed — but it is a verb rule, not a pods rule, and it also takes configmaps, `nodes/proxy`, events, CRD reads and all denied reads (A3). |
| `resources.name` falls back to the resource plural | **Agree** | Documented in the code comment, and the guard described (`name !== type`) is correct. Verified against a real cluster-wide list. |

---

## Minimum reconciliation, from what is already running

No new infrastructure needed.

```
1  kubectl get --raw /metrics | grep apiserver_audit_event_total
2  wc -l /var/log/k3s-audit/audit.log
3  curl fluent-bit:2020/api/v1/metrics    → input.tail.0.records, output.kafka.0.proc_records
4  kafka-consumer-groups --describe --group cribl-logpipe   → sum LOG-END-OFFSET, LAG
5  curl localhost:9200/logs-k8s-audit/_stats/indexing       → index_total, index_failed

invariant 1   (2) − oversized lines  ==  (3).tail.0.records
              this is the only place A4 is visible — and Fluent Bit
              never compares these two numbers itself
invariant 2   (3).kafka.0.proc_records  ==  (4) log-end-offset delta
invariant 3   (4) delta − watch events  ==  (5) index_total delta
```

Caveats: counter **1** resets on apiserver restart, so it is a rate check rather than a total. Counter **3** resets on Fluent Bit restart while the tail DB offset persists — that combination is what made this look like an 89% data loss on first inspection when it was not.

**If you only watch two things:** `index_failed > 0` (the sole surface for B13), and the gap between `audit.log` line count and `tail.0.records` growing (the sole surface for A4).

---

## Fix these three first

### 1 — Raise Fluent Bit's line buffer above the largest audit event

`fluent-bit/fluent-bit.conf`, the `k8s.audit` input. `Buffer_Max_Size` is unset and defaults to 32 KB while real events reach 102 KB. The only finding where data is destroyed with no recovery path anywhere downstream, and it lands on RBAC enumeration specifically.

```bash
# 1. pick an oversized event that is currently missing
awk 'length($0)>32768' /var/log/k3s-audit/audit.log | head -1 \
  | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["auditID"])'

# 2. after the change, force a re-read (reset the tail DB offset) and query
GET logs-k8s-audit/_count  {"query":{"term":{"metadata.correlation_uid.keyword":"<id>"}}}

# pass = 1 hit. all four are currently 0.
```

### 2 — Reorder the audit policy and add `deletecollection`

Two edits to `k3s/audit-policy.yaml`: add `deletecollection` to the verb list at line 32, and resolve the rule-ordering problem at lines 25–28. The second half needs a decision — see Q1.

```bash
# deletecollection coverage
kubectl -n scratch delete configmaps --all
grep '"verb":"deletecollection"' audit.log | grep configmaps
# pass = a line exists. currently zero.

# noise suppression actually suppressing
# re-run the excluded-identity count; 29,292 should fall toward 0
```

### 3 — Put an explicit index template in place before more data lands

Every hour without one adds documents under accidental types. Minimum set: `src_endpoint.ip` → `ip`, `_time` → `double` or dropped, `metadata.original_time` → `keyword`, `unmapped.authz_reason` with a raised `ignore_above`, and `unmapped.user_extra` set to `dynamic: false` to cap the key space. Closes B1, B2, B11, B15 and the latent half of B12.

```bash
# CIDR query — only works on a real ip-typed field
GET logs-k8s-audit/_search  {"query":{"term":{"src_endpoint.ip":"10.42.0.0/16"}}}
# pass = returns the 10.42.0.14 and 10.42.0.8 events. currently returns nothing.

# float drift gone
GET logs-k8s-audit/_search  {"docvalue_fields":["_time"],"size":1}
# pass = indexed _time matches _source._time. currently off by ~58 s.
```

---

## Open judgment calls

**Q1 — How to fix the policy ordering without going blind on kube-system.** Moving rules 4–5 above rules 1–3 kills the 75% noise, but a compromised kube-system service account or node credential reading secrets goes dark — losing the 9,230 secrets events and all RBAC events from those identities. That trades a real detection for a volume reduction.

The alternative is to keep the ordering and insert narrow `level: None` rules above rules 1–3 naming only the specific noisy principals: `system:kube-controller-manager`, `system:apiserver`, `system:k3s-supervisor`, `system:serviceaccount:kube-system:traefik`. That preserves detection for every identity not explicitly excused, at the cost of a list to maintain. Note `system:k3s-supervisor` (9,412 events) is not in the current exclusion list at all — the policy was written for generic k8s, not k3s.

**Q2 — What to do with the 37,583 raw documents.** Reindex them through the normalize logic, or leave them and start a clean index behind an alias. Reindexing gives one queryable history; a clean index is faster and honest about the fact that the old data was captured under different rules. Either way B3 needs a decision before detections are written.

**Q3 — Whether the watch drop should be resource-scoped.** Dropping 94.9% of volume is defensible. Dropping a hostile `watch` on secrets along with it is not. If A1 is fixed first, most of the watch volume disappears at the source and the Cribl drop can become much narrower — or unnecessary. The order in which A1 and A6 are tackled changes the right shape of the fix.

---

*Verified live against k3s v1.36 and OpenSearch 2.19.0 on 2026-08-23, 21:39–21:49 UTC. No configuration was modified. Two marker events were generated by read-only kubectl calls for end-to-end tracing.*
