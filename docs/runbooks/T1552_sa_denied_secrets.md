# Runbook — Service account denied access to secrets

**Rule:** `T1552_SA_DENIED_SECRETS` · Severity HIGH · MITRE T1552

## What fired
A Kubernetes service account received a 403 reading or listing secrets.

## Triage — 5 minutes
1. Identify the workload behind the identity:
   `kubectl -n <ns> get pods -o json | jq '.items[] | select(.spec.serviceAccountName=="<sa>") | .metadata.name'`
2. Check what else that identity did in the last hour:
   DQL — `actor.user.name: "<sa>" and @timestamp >= now-1h`
3. Was the target namespace `kube-system`? Treat as escalation attempt, not misconfig.

## Benign causes
- Newly deployed workload whose RBAC has not been applied yet
- Helm chart expecting a secret that was renamed
- Operator polling for an optional secret

## Escalate if
- The same identity also shows `pods/exec`, `serviceaccounts/token` create, or RBAC writes
- The source IP is outside the pod CIDR
- The denial repeats across multiple namespaces

## Contain
`kubectl -n <ns> delete rolebinding <binding>` then cordon the node and snapshot the pod.
