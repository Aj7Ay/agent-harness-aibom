import pytest

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.policy_yaml import PolicyFileError, evaluate_policy_rules, load_policy_rules


def _bom_with_secret(world_readable: bool) -> dict:
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", world_readable)
    doc.add(secret, "accesses")
    return to_cyclonedx(doc)


# ---- load_policy_rules --------------------------------------------------


def test_loads_a_valid_policy_file():
    text = """
rules:
  - id: SECRET-001
    severity: high
    action: fail
    condition:
      componentClass: secrets_surface
      worldReadable: true
"""
    rules = load_policy_rules(text)
    assert rules == [{
        "id": "SECRET-001",
        "severity": "high",
        "action": "fail",
        "condition": {"componentClass": "secrets_surface", "worldReadable": True},
    }]


def test_action_defaults_to_fail():
    text = "rules:\n  - id: X\n    severity: low\n    condition:\n      foo: bar\n"
    assert load_policy_rules(text)[0]["action"] == "fail"


@pytest.mark.parametrize("text,expected_fragment", [
    ("not: a policy file\n", "'rules:'"),
    ("rules: not-a-list\n", "must be a list"),
    ("rules:\n  - not-a-mapping\n", "expected a mapping"),
    ("rules:\n  - severity: high\n    condition: {a: b}\n", "missing or invalid 'id'"),
    ("rules:\n  - id: X\n    severity: extreme\n    condition: {a: b}\n", "'severity' must be one of"),
    ("rules:\n  - id: X\n    severity: high\n    action: nuke\n    condition: {a: b}\n", "'action' must be one of"),
    ("rules:\n  - id: X\n    severity: high\n", "'condition' must be a non-empty mapping"),
    ("rules:\n  - id: X\n    severity: high\n    condition: {}\n", "'condition' must be a non-empty mapping"),
])
def test_malformed_policy_files_raise_a_specific_error(text, expected_fragment):
    with pytest.raises(PolicyFileError, match=expected_fragment):
        load_policy_rules(text)


def test_malformed_yaml_raises_a_specific_error():
    with pytest.raises(PolicyFileError, match="not valid YAML"):
        load_policy_rules("rules: [unterminated\n")


# ---- evaluate_policy_rules -----------------------------------------------


def test_rule_matches_a_real_finding():
    bom = _bom_with_secret(world_readable=True)
    rules = [{
        "id": "SECRET-001", "severity": "high", "action": "fail",
        "condition": {"componentClass": "secrets_surface", "worldReadable": True},
    }]
    observations = evaluate_policy_rules(bom, rules)
    assert len(observations) == 1
    assert observations[0]["rule"] == "SECRET-001"
    assert observations[0]["action"] == "fail"
    assert any(".env" in ref for ref in observations[0]["components"])


def test_rule_does_not_match_when_condition_is_false():
    bom = _bom_with_secret(world_readable=False)
    rules = [{
        "id": "SECRET-001", "severity": "high", "action": "fail",
        "condition": {"componentClass": "secrets_surface", "worldReadable": True},
    }]
    assert evaluate_policy_rules(bom, rules) == []


def test_rule_without_componentclass_matches_across_all_classes():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    a = Component(component_class="secrets_surface", name="a")
    a.set("worldReadable", True)
    doc.add(a, "accesses")
    b = Component(component_class="memory_store", name="b")
    b.set("worldReadable", True)
    doc.add(b, "accesses")
    bom = to_cyclonedx(doc)

    rules = [{"id": "ANY-WORLD-READABLE", "severity": "high", "action": "fail", "condition": {"worldReadable": True}}]
    observations = evaluate_policy_rules(bom, rules)
    assert len(observations) == 1
    assert len(observations[0]["components"]) == 2


def test_warn_action_is_preserved_not_dropped():
    bom = _bom_with_secret(world_readable=True)
    rules = [{
        "id": "SECRET-WARN", "severity": "low", "action": "warn",
        "condition": {"componentClass": "secrets_surface", "worldReadable": True},
    }]
    observations = evaluate_policy_rules(bom, rules)
    assert observations[0]["action"] == "warn"


def test_multiple_conditions_are_a_logical_and():
    bom = _bom_with_secret(world_readable=True)
    rules = [{
        "id": "IMPOSSIBLE", "severity": "high", "action": "fail",
        "condition": {"componentClass": "secrets_surface", "worldReadable": True, "mode": "0000"},
    }]
    assert evaluate_policy_rules(bom, rules) == []
