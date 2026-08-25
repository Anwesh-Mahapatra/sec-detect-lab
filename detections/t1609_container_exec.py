"""
T1609 - Container Administration Command

Someone opened a shell, attached to, or port-forwarded into a running container.
This is the single highest-signal action in a Kubernetes cluster: it bypasses
every image scan, admission controller and GitOps review in the pipeline.

Runs in "runner" mode. The query alone would alert on every exec, including the
CI service account that is supposed to do it. The allowlist lives in Python
where it can be reviewed, diffed and tested - not buried in a Query DSL blob.

Status: VALIDATED. Fires on real traffic from test.sh.
"""

from detections.base import Rule, TestCase, deep_get_first, get

INTERACTIVE_SUBRESOURCES = {"pods/exec", "pods/attach", "pods/portforward"}

# Identities permitted to exec. Every entry needs a dated justification.
EXEC_ALLOWLIST = {
    # "system:serviceaccount:ci:deploy-bot",  # 2026-08-24, ticket SEC-118
}


class ContainerExec(Rule):
    id = "T1609_CONTAINER_EXEC"
    title = "Interactive session opened into a container"
    severity = "HIGH"
    owner = "detection-eng"
    description = (
        "exec, attach or port-forward against a running pod by an identity "
        "outside the exec allowlist."
    )
    runbook = "docs/runbooks/T1609_container_exec.md"
    mitre = ["T1609", "T1610"]

    mode = "runner"
    window_minutes = 5
    threshold = 1

    query = {
        "bool": {
            "filter": [
                {"term": {"activity_id": 99}},
                {"terms": {"resources.type": sorted(INTERACTIVE_SUBRESOURCES)}},
            ]
        }
    }

    def rule(self, event):
        if deep_get_first(event, "resources.type") not in INTERACTIVE_SUBRESOURCES:
            return False
        actor = get(event, "actor.user.name", "")
        if actor in EXEC_ALLOWLIST:
            return False
        return True

    def alert_title(self, event):
        actor = get(event, "actor.user.name", "unknown")
        pod = deep_get_first(event, "resources.name", "unknown")
        kind = deep_get_first(event, "resources.type", "pods/exec").split("/")[-1]
        return f"{actor} opened {kind} on pod {pod}"

    tests = [
        TestCase(
            name="admin execs into a pod",
            expect=True,
            event={
                "activity_id": 99,
                "status_id": 1,
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "pods/exec", "name": "gp"}],
            },
        ),
        TestCase(
            name="port-forward counts as interactive access",
            expect=True,
            event={
                "activity_id": 99,
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "pods/portforward", "name": "gp"}],
            },
        ),
        TestCase(
            name="ordinary pod read is not a shell",
            expect=False,
            event={
                "activity_id": 2,
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "pods", "name": "gp"}],
            },
        ),
        TestCase(
            name="pods/log is a read, not an interactive session",
            expect=False,
            event={
                "activity_id": 2,
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "pods/log", "name": "gp"}],
            },
        ),
    ]
