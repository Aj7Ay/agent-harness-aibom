"""Policy-as-code: user-supplied YAML rules matched against a document's
own components/services, evaluated independently of security.py's fixed
rule set. Deliberately a narrow, closed-set condition language --
equality checks on a componentClass and named properties only, never a
general expression evaluator -- so a rule stays as explainable as
security.py's own named rules: a reader can see exactly what a rule
checks by reading the YAML, the same "name the exact rule, never an
opaque score" discipline this whole project already applies.

NOT a replacement for security.py's own rules -- `policy` (cli.py) still
runs those unconditionally, on every document. This is an ADDITIONAL,
user-authored rule set for a lab or org's own policy, one that isn't and
shouldn't be baked into this scanner's fixed rule set.
"""

from __future__ import annotations

import yaml

_ALLOWED_ACTIONS = frozenset({"fail", "warn"})
_ALLOWED_SEVERITIES = frozenset({"high", "medium", "low"})


class PolicyFileError(ValueError):
    """A user-supplied policy YAML file is malformed -- callers (cli.py)
    turn this into a clean CLI error message, never a raw traceback."""


def _entries(bom: dict) -> list[dict]:
    return bom.get("components", []) + bom.get("services", [])


def _properties(entry: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in entry.get("properties", [])}


def _coerce(expected: object) -> str:
    """YAML's own `true`/`false` -> this codebase's own string
    convention for a boolean property value (`"True"`/`"False"`, from
    `Component.set()`'s `str(value)` -- see model.py). Anything else (a
    string, a number) compares as its own `str()` form -- the same
    string-equality every harness-aibom: property is already stored and
    compared as everywhere else in this codebase.
    """
    if isinstance(expected, bool):
        return "True" if expected else "False"
    return str(expected)


def load_policy_rules(text: str) -> list[dict]:
    """Parse and validate a policy YAML file's contents. Raises
    `PolicyFileError` with a specific, actionable message for anything
    malformed (not a mapping, an unknown severity/action, a missing
    condition) -- caught once here, at load time, rather than letting a
    `KeyError`/`TypeError` reach the user mid-evaluation as a traceback.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyFileError(f"not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or "rules" not in data:
        raise PolicyFileError("expected a top-level 'rules:' list")
    rules = data["rules"]
    if not isinstance(rules, list):
        raise PolicyFileError("'rules' must be a list")

    validated = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyFileError(f"rules[{i}]: expected a mapping")
        rule_id = rule.get("id")
        severity = rule.get("severity")
        action = rule.get("action", "fail")
        condition = rule.get("condition")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyFileError(f"rules[{i}]: missing or invalid 'id'")
        if severity not in _ALLOWED_SEVERITIES:
            raise PolicyFileError(f"rules[{i}] ({rule_id}): 'severity' must be one of {sorted(_ALLOWED_SEVERITIES)}")
        if action not in _ALLOWED_ACTIONS:
            raise PolicyFileError(f"rules[{i}] ({rule_id}): 'action' must be one of {sorted(_ALLOWED_ACTIONS)}")
        if not isinstance(condition, dict) or not condition:
            raise PolicyFileError(f"rules[{i}] ({rule_id}): 'condition' must be a non-empty mapping")
        validated.append({"id": rule_id, "severity": severity, "action": action, "condition": condition})
    return validated


def evaluate_policy_rules(bom: dict, rules: list[dict]) -> list[dict]:
    """Each matching rule -> `{"rule", "severity", "action", "summary",
    "components"}` -- the same shape security.py's own
    `compute_risk_observations()` returns (plus `action`, which that
    function has no equivalent of), so cli.py's existing print
    formatting can handle both uniformly. A rule with zero matches is
    simply omitted, same "absence isn't noted, presence is" convention
    `compute_risk_observations()` already uses.

    `condition`'s optional `componentClass` key scopes the rule to one
    componentClass; every other key is an equality check against that
    entry's own `harness-aibom:<key>` property (coerced via `_coerce()`).
    All conditions in one rule must match (a logical AND) -- there is no
    OR, no negation, no comparison operator beyond equality, deliberately:
    a rule that needs more than that is exactly the kind of "opaque"
    condition this project's whole risk-observation design has always
    avoided.
    """
    observations = []
    for rule in rules:
        condition = rule["condition"]
        component_class = condition.get("componentClass")
        checks = {k: v for k, v in condition.items() if k != "componentClass"}

        matched_refs = []
        for entry in _entries(bom):
            props = _properties(entry)
            if component_class and props.get("harness-aibom:componentClass") != component_class:
                continue
            if all(props.get(f"harness-aibom:{key}") == _coerce(expected) for key, expected in checks.items()):
                ref = entry.get("bom-ref")
                if ref:
                    matched_refs.append(ref)

        if matched_refs:
            observations.append({
                "rule": rule["id"],
                "severity": rule["severity"],
                "action": rule["action"],
                "summary": f"{len(matched_refs)} component(s) matched policy rule {rule['id']!r}",
                "components": matched_refs,
            })
    return observations
