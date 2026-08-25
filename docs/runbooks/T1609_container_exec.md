# Runbook — Interactive session opened into a container

**Rule:** `T1609_CONTAINER_EXEC` · Severity HIGH · MITRE T1609

## What fired
Someone ran exec, attach or port-forward against a live pod. This bypasses image
scanning, admission control and GitOps review entirely.

## Triage — 5 minutes
1. Who: `actor.user.name`. A human during an incident is expected; a service
   account almost never is.
2. What was run: check `http_request.url.url_string`. Note it is percent-encoded
   (`%2Fbin%2Fsh`), so search for `2fbin` — see FINDINGS B9.
3. Correlate: did the same identity read secrets or write RBAC within 30 minutes?

## Benign causes
- On-call debugging with a change ticket open
- CI job that shells in to run migrations — if so, add it to `EXEC_ALLOWLIST`
  in the rule with a dated justification

## Escalate if
- The identity is a service account not on the allowlist
- The pod is in `kube-system` or runs privileged
- Exec is followed by a token create or a rolebinding write

## Contain
Delete the pod, rotate any secret it mounted, revoke the service account token.
