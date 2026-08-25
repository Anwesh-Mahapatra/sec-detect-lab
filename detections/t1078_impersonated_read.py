"""
T1078.004 - Valid Accounts: Cloud Accounts

An identity used `--as` to borrow a service account's permissions and then read
cluster resources. Impersonation is how an operator with cluster-admin quietly
tests what a workload identity can reach - and how an attacker with a stolen
kubeconfig does the same thing.

STATUS: PARTIALLY BLOCKED - fires only on protected resource types.

The audit policy's final rule drops every get/list/watch that no earlier rule
claimed. An impersonated read of pods, configmaps or pods/log is therefore never
written to audit.log at all. Nothing downstream can recover it.

Verified 2026-08-24: test.sh ran `kubectl --as=system:serviceaccount:...
get pods`. The event does not exist in audit.log, Kafka or OpenSearch.

This file is deliberately committed in its broken state. The test below asserts
it stays broken. When FINDINGS A3 is fixed, that test fails loudly and forces
someone to re-validate the rule instead of assuming it was working all along.
"""

from detections.base import Rule, TestCase, deep_get_first, get

# Reads that carry no protecting rule in the audit policy and are dropped.
UNLOGGED_READ_TYPES = {"pods", "pods/log", "configmaps", "nodes/proxy", "events"}


class ImpersonatedRead(Rule):
    id = "T1078_IMPERSONATED_READ"
    title = "Impersonated identity reading cluster resources"
    severity = "MEDIUM"
    owner = "detection-eng"
    description = (
        "A principal used impersonation to read resources as another identity. "
        "Expected from operators during debugging; suspicious from a workload "
        "or an unfamiliar source IP."
    )
    runbook = "docs/runbooks/T1078_impersonated_read.md"
    mitre = ["T1078.004"]

    mode = "monitor"
    window_minutes = 15
    threshold = 1

    blocked_by = "A3-partial"
    blocked_reason = (
        "Fires on secrets, RBAC and token reads, which have their own audit "
        "rules. Impersonated reads of pods, pods/log and configmaps are "
        "dropped by the policy and never arrive. Coverage is partial, and "
        "absence of this alert does not mean absence of impersonation."
    )

    query = {
        "bool": {
            "filter": [
                {"term": {"unmapped.impersonated": True}},
                {"term": {"activity_id": 2}},
            ]
        }
    }

    def rule(self, event):
        if not get(event, "unmapped.impersonated"):
            return False
        return get(event, "activity_id") == 2

    def alert_title(self, event):
        real = get(event, "actor.invoked_by", "unknown")
        assumed = get(event, "actor.user.name", "unknown")
        res = deep_get_first(event, "resources.type", "unknown")
        return f"{real} read {res} while impersonating {assumed}"

    tests = [
        TestCase(
            name="impersonated read on a protected type still reaches us",
            expect=True,
            event={
                "activity_id": 2,
                "status_id": 2,
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"},
                          "invoked_by": "system:admin"},
                "resources": [{"type": "secrets", "name": "secrets"}],
                "unmapped": {"impersonated": True},
            },
        ),
        TestCase(
            name="non-impersonated read is normal traffic",
            expect=False,
            event={
                "activity_id": 2,
                "actor": {"user": {"name": "system:admin"}},
                "resources": [{"type": "secrets"}],
                "unmapped": {"impersonated": False},
            },
        ),
        TestCase(
            name="impersonated write is a different rule",
            expect=False,
            event={
                "activity_id": 1,
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"}},
                "resources": [{"type": "roles"}],
                "unmapped": {"impersonated": True},
            },
        ),
        # The gap fixture. This is the event test.sh generates and the pipeline
        # never delivers. The logic handles it correctly - the plumbing does not.
        TestCase(
            name="GAP A3 - impersonated pod read, correct logic, never ingested",
            expect=True,
            event={
                "activity_id": 2,
                "status_id": 1,
                "actor": {"user": {"name": "system:serviceaccount:gap-test:default"},
                          "invoked_by": "system:admin"},
                "resources": [{"type": "pods", "name": "pods"}],
                "unmapped": {"impersonated": True},
            },
        ),
    ]
