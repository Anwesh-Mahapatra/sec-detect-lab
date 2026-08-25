"""
Base contract for every detection in this repo.

A detection is a Python class. The detection logic lives in `rule()`, a plain
Python function that takes one OCSF event (a dict) and returns True if it should
alert. That is the Panther model, and it is why every rule here is unit-testable
without OpenSearch running.

Two extra pieces exist because OpenSearch is not a streaming engine:

  query  - a Query DSL prefilter so OpenSearch does the heavy lifting instead of
           Python pulling the whole index.
  mode   - "monitor" if `query` alone is sufficient (deployable as a native
           OpenSearch Alerting monitor), "runner" if `rule()` adds logic the
           query cannot express (runs on a schedule instead).

`blocked_by` is the honest part: a rule that is correct but structurally cannot
fire because the pipeline never delivers the event. CI asserts it stays broken
until the referenced FINDINGS.md gap is fixed.
"""

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class TestCase:
    """One fixture. `expect` is what rule() must return for this event."""
    name: str
    event: dict[str, Any]
    expect: bool


class Rule:
    # --- identity -----------------------------------------------------------
    id: str = ""                     # stable, never reused
    title: str = ""                  # human name shown on the alert
    severity: str = "MEDIUM"         # INFO | LOW | MEDIUM | HIGH | CRITICAL
    owner: str = ""                  # who gets paged
    description: str = ""
    runbook: str = ""                # URL or path to response steps

    # --- coverage -----------------------------------------------------------
    mitre: list[str] = []            # e.g. ["T1552.007"]
    references: list[str] = []

    # --- execution ----------------------------------------------------------
    index: str = "logs-k8s-audit"
    mode: str = "monitor"            # "monitor" | "runner"
    window_minutes: int = 5
    threshold: int = 1               # alert when hits >= threshold
    query: dict[str, Any] = {}       # OpenSearch Query DSL prefilter

    # --- validation gap -----------------------------------------------------
    blocked_by: str | None = None    # FINDINGS.md id, e.g. "A3"
    blocked_reason: str = ""

    # --- tests --------------------------------------------------------------
    tests: list[TestCase] = []

    # --- logic --------------------------------------------------------------
    def rule(self, event: dict[str, Any]) -> bool:
        """Return True if this event should alert. Override in every rule."""
        raise NotImplementedError

    def alert_title(self, event: dict[str, Any]) -> str:
        """Alert headline. Override to include the actor, resource, etc."""
        return self.title

    def dedup_key(self, event: dict[str, Any]) -> str:
        """Events sharing this key collapse into one alert."""
        return f"{self.id}:{get(event, 'actor.user.name', 'unknown')}"


def get(event: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Safe dotted lookup. `get(e, "actor.user.name")` instead of
    e["actor"]["user"]["name"] blowing up on a missing key.

    Lists are indexed numerically: "resources.0.type".
    """
    node: Any = event
    for part in path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if node is None:
            return default
    return node


def deep_get_first(event: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Like get(), but `resources.type` transparently means `resources.0.type`.
    OCSF puts resources in a list; rule authors should not have to care.
    """
    direct = get(event, path, None)
    if direct is not None:
        return direct
    head, _, tail = path.partition(".")
    node = event.get(head)
    if isinstance(node, list) and node and tail:
        return get(node[0], tail, default)
    return default
