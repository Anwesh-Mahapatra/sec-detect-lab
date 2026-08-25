"""
The CI gate. Every rule must clear all of these before it can merge.

Nothing here needs OpenSearch running - that is the point. Detection logic is a
Python function over a dict, so it tests in milliseconds on a laptop and in CI.
The one test that does care about OpenSearch reads a checked-in mapping snapshot
instead of a live cluster.
"""

import json
import re
from pathlib import Path

import pytest

from detections import all_rules
from detections.base import Rule

RULES = all_rules()
RULE_IDS = [r.id for r in RULES]
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
MAPPING_SNAPSHOT = Path(__file__).parent / "fixtures" / "index_mapping.json"


def pytest_generate_tests(metafunc):
    if "rule" in metafunc.fixturenames:
        metafunc.parametrize("rule", RULES, ids=RULE_IDS)


# ---------------------------------------------------------------------------
# 1. Metadata - an alert nobody can action is worse than no alert
# ---------------------------------------------------------------------------

def test_rule_ids_are_unique():
    assert len(RULE_IDS) == len(set(RULE_IDS)), "duplicate rule id"


def test_metadata_is_complete(rule: Rule):
    assert rule.id, "rule needs a stable id"
    assert rule.title, f"{rule.id}: needs a human-readable title"
    assert rule.description, f"{rule.id}: needs a description"
    assert rule.owner, f"{rule.id}: needs an owner to page"
    assert rule.runbook, f"{rule.id}: needs a runbook path"
    assert rule.severity in VALID_SEVERITIES, f"{rule.id}: bad severity"
    assert rule.mode in {"monitor", "runner"}, f"{rule.id}: bad mode"


def test_mitre_technique_is_well_formed(rule: Rule):
    assert rule.mitre, f"{rule.id}: needs at least one MITRE technique"
    for t in rule.mitre:
        assert MITRE_PATTERN.match(t), f"{rule.id}: '{t}' is not a technique id"


# ---------------------------------------------------------------------------
# 2. Fixtures - the rule must actually do what it claims
# ---------------------------------------------------------------------------

def test_has_both_a_true_and_a_false_positive(rule: Rule):
    """
    A rule with only true positives has never been shown to discriminate.
    A rule with only false positives never fires. Both are required.
    """
    expects = {t.expect for t in rule.tests}
    assert True in expects, f"{rule.id}: no true-positive fixture"
    assert False in expects, f"{rule.id}: no false-positive fixture"


def test_fixtures_produce_the_expected_verdict(rule: Rule):
    for case in rule.tests:
        got = rule.rule(case.event)
        assert isinstance(got, bool), f"{rule.id}/{case.name}: rule() must return bool"
        assert got == case.expect, (
            f"{rule.id} :: '{case.name}'\n"
            f"  expected rule() -> {case.expect}, got {got}"
        )


def test_rule_survives_a_garbage_event(rule: Rule):
    """
    Real pipelines deliver truncated and malformed events. A rule that raises
    takes the whole detection run down with it.
    """
    for junk in [{}, {"actor": None}, {"resources": []}, {"resources": "not-a-list"}]:
        try:
            rule.rule(junk)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"{rule.id}: crashed on {junk!r} -> {type(exc).__name__}: {exc}")


def test_alert_title_renders_for_every_true_positive(rule: Rule):
    for case in rule.tests:
        if case.expect:
            title = rule.alert_title(case.event)
            assert isinstance(title, str) and title.strip()


# ---------------------------------------------------------------------------
# 3. Schema contract - the check that catches silent field drift
# ---------------------------------------------------------------------------

def _fields_in_query(node) -> set[str]:
    """Pull every field name referenced anywhere in a Query DSL dict."""
    leaf_ops = {"term", "terms", "prefix", "match", "match_phrase", "range",
                "wildcard", "regexp", "exists"}
    found: set[str] = set()
    if isinstance(node, dict):
        for key, val in node.items():
            if key in leaf_ops and isinstance(val, dict):
                if key == "exists":
                    found.add(val.get("field", ""))
                else:
                    found.update(val.keys())
            else:
                found |= _fields_in_query(val)
    elif isinstance(node, list):
        for item in node:
            found |= _fields_in_query(item)
    return {f for f in found if f}


def _flatten_mapping(props: dict, prefix: str = "") -> set[str]:
    out: set[str] = set()
    for name, body in props.items():
        path = f"{prefix}{name}"
        if "properties" in body:
            out |= _flatten_mapping(body["properties"], f"{path}.")
        else:
            out.add(path)
    return out


@pytest.fixture(scope="session")
def indexed_fields() -> set[str]:
    if not MAPPING_SNAPSHOT.exists():
        pytest.skip("no mapping snapshot - run tools/snapshot_mapping.py")
    raw = json.loads(MAPPING_SNAPSHOT.read_text())
    idx = next(iter(raw.values()))
    return _flatten_mapping(idx["mappings"].get("properties", {}))


def test_query_only_references_fields_that_exist(rule: Rule, indexed_fields):
    """
    The bug class this exists for: a rule referencing a field the pipeline
    stopped producing. The query stays valid, returns zero, and looks healthy
    forever. This is FINDINGS B3 caught at merge time instead of never.
    """
    referenced = _fields_in_query(rule.query)
    unknown = {f for f in referenced if f.split(".keyword")[0] not in indexed_fields}
    assert not unknown, (
        f"{rule.id}: query references fields absent from the index mapping: "
        f"{sorted(unknown)}"
    )


# ---------------------------------------------------------------------------
# 4. Validation gaps - blocked rules must stay honestly labelled
# ---------------------------------------------------------------------------

def test_blocked_rules_state_why(rule: Rule):
    if rule.blocked_by:
        assert rule.blocked_reason, (
            f"{rule.id}: blocked_by={rule.blocked_by} but no blocked_reason. "
            "A gap without an explanation is just a broken rule."
        )
        assert any("GAP" in t.name.upper() for t in rule.tests), (
            f"{rule.id}: blocked rules need a fixture named GAP ... showing the "
            "event the pipeline fails to deliver."
        )


def test_blocked_rules_are_reported(capsys):
    blocked = [r for r in RULES if r.blocked_by]
    if blocked:
        lines = [f"  {r.id}  blocked by FINDINGS {r.blocked_by}" for r in blocked]
        print("\nBLOCKED - correct logic, pipeline cannot deliver the event:")
        print("\n".join(lines))
    assert True  # informational, never fails the build
