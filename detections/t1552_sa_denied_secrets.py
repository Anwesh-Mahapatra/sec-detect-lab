"""
T1552 - Unsecured Credentials

A Kubernetes service account is refused access to secrets. Legitimate workloads
are granted the secret access they need at deploy time; a service account being
told "forbidden" is either a misconfiguration or a compromised pod probing for
credentials it was never given.

Status: VALIDATED. Fires on real traffic from test.sh.
"""

from detections.base import Rule, TestCase, deep_get_first, get

SA_PREFIX = "system:serviceaccount:"


class SaDeniedSecrets(Rule):
    id = "T1552_SA_DENIED_SECRETS"
    title = "Service account denied access to secrets"
    severity = "HIGH"
    owner = "detection-eng"
    description = (
        "A service account received a 403 attempting to read or list secrets. "
        "Indicates credential access probing from a workload identity."
    )
    runbook = "docs/runbooks/T1552_sa_denied_secrets.md"
    mitre = ["T1552", "T1078.004"]

    mode = "monitor"
    window_minutes = 10
    threshold = 1

    # OpenSearch does the filtering; rule() below re-checks it precisely.
    query = {
        "bool": {
            "filter": [
                {"term": {"status_id": 2}},
                {"term": {"resources.type": "secrets"}},
                {"prefix": {"actor.user.name": SA_PREFIX}},
            ]
        }
    }

    def rule(self, event):
        if get(event, "status_id") != 2:
            return False
        if deep_get_first(event, "resources.type") != "secrets":
            return False
        actor = get(event, "actor.user.name", "")
        return isinstance(actor, str) and actor.startswith(SA_PREFIX)

    def alert_title(self, event):
        actor = get(event, "actor.user.name", "unknown")
        ns = deep_get_first(event, "resources.namespace", "unknown")
        verb = get(event, "api.operation", "unknown")
        return f"Service account {actor} denied '{verb}' on secrets in {ns}"

    tests = [
        TestCase(
            name="denied list from a non-kube-system service account",
            expect=True,
            event={
                "status_id": 2,
                "status_code": "403",
                "api": {"operation": "list"},
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"}},
                "resources": [{"type": "secrets", "name": "secrets",
                               "namespace": "kube-system"}],
            },
        ),
        TestCase(
            name="successful read by the same service account is not this rule",
            expect=False,
            event={
                "status_id": 1,
                "api": {"operation": "get"},
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"}},
                "resources": [{"type": "secrets", "name": "gs"}],
            },
        ),
        TestCase(
            name="human admin denied - not a workload identity, different playbook",
            expect=False,
            event={
                "status_id": 2,
                "api": {"operation": "list"},
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "secrets", "name": "secrets"}],
            },
        ),
        TestCase(
            name="denied on configmaps, not secrets",
            expect=False,
            event={
                "status_id": 2,
                "api": {"operation": "list"},
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"}},
                "resources": [{"type": "configmaps", "name": "configmaps"}],
            },
        ),
        TestCase(
            name="malformed event with no resources block does not crash",
            expect=False,
            event={
                "status_id": 2,
                "actor": {"user": {"name": "system:serviceaccount:x:y"}},
            },
        ),
    ]
