# Runbook — Impersonated identity reading cluster resources

**Rule:** `T1078_IMPERSONATED_READ` · Severity MEDIUM · MITRE T1078.004

> **This rule is BLOCKED.** It cannot fire for most resource types. The audit
> policy drops unclaimed `get/list/watch`, so impersonated reads of pods,
> configmaps and pods/log never reach the log. See FINDINGS A3.
> Until A3 is fixed, absence of this alert means nothing.

## What fires today
Only impersonated reads of resources with their own audit-policy rule —
secrets, serviceaccounts/token, RBAC objects.

## Triage
1. `actor.invoked_by` is the real principal. `actor.user.name` is who they borrowed.
2. Legitimate: an operator running `kubectl auth can-i --as=` to debug RBAC.
3. Suspicious: impersonation from a workload identity, or from an unfamiliar IP.

## Escalate if
- The impersonating principal is itself a service account
- The impersonated identity has more privilege than the caller normally uses
- It precedes RBAC writes or token creation
