"""SARIF 2.1.0 output for security.py's own named risk-rule findings --
for GitHub/GitLab/Azure code-scanning UIs, which read this format
directly. Renders exactly `compute_risk_observations()`'s own output --
never a second, independent finding set -- so SARIF output and `policy`'s
CI gate can never disagree about what counts as a finding.

Confirmed against the real, official SARIF 2.1.0 JSON Schema
(schemastore.org's mirror of oasis-tcs/sarif-spec, vendored at
tests/fixtures/sarif-schema-2.1.0.json): `test_sarif.py` validates every
document this module produces, across every real fixture this project
has, against that schema -- the same "validate against the real spec,
not just what looks reasonable" discipline this project already applies
to CycloneDX output (test_cyclonedx_schema.py).
"""

from __future__ import annotations

from . import __version__
from .security import compute_risk_observations

SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

#: severity -> SARIF's own `level` enum (none/note/warning/error). "high"
#: maps to "error" (the level most code-scanning consumers treat as
#: check-failing by default), "medium" to "warning", "low" to "note".
_SEVERITY_TO_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _rule_descriptor(rule: str, summary: str) -> dict:
    return {
        "id": rule,
        "shortDescription": {"text": summary},
        "helpUri": "https://github.com/Aj7Ay/agent-harness-aibom/blob/main/SPEC.md",
    }


def _properties_by_ref(bom: dict) -> dict[str, dict[str, str]]:
    props_by_ref: dict[str, dict[str, str]] = {}
    for entry in bom.get("components", []) + bom.get("services", []):
        ref = entry.get("bom-ref")
        if ref:
            props_by_ref[ref] = {p["name"]: p["value"] for p in entry.get("properties", [])}
    return props_by_ref


def _location_for(ref: str, props: dict[str, str]) -> dict:
    """A real `physicalLocation` (file-based -- what a code-scanning UI
    actually annotates inline in a diff view) when the matched component
    carries a real `relPath`/`path` property to point at; a
    `logicalLocation` naming the bom-ref otherwise (a service, or a
    component with no filesystem location at all, e.g. an MCP server) --
    never a fabricated path.
    """
    rel = props.get("harness-aibom:relPath") or props.get("harness-aibom:path")
    if rel:
        return {"physicalLocation": {"artifactLocation": {"uri": rel}}}
    return {"logicalLocations": [{"fullyQualifiedName": ref}]}


def render_sarif(bom: dict) -> dict:
    """A full SARIF 2.1.0 log, one run, for `bom`'s own
    `compute_risk_observations()` findings. Structurally valid even with
    zero findings -- an empty `results[]` is a real, meaningful SARIF
    document ("this run found nothing"), not an error state.
    """
    observations = compute_risk_observations(bom)
    props_by_ref = _properties_by_ref(bom)

    rules_seen: dict[str, dict] = {}
    results = []
    for o in observations:
        rules_seen.setdefault(o["rule"], _rule_descriptor(o["rule"], o["summary"]))
        for ref in o["components"]:
            results.append({
                "ruleId": o["rule"],
                "level": _SEVERITY_TO_LEVEL.get(o["severity"], "warning"),
                "message": {"text": o["summary"]},
                "locations": [_location_for(ref, props_by_ref.get(ref, {}))],
            })

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-harness-aibom",
                        "informationUri": "https://github.com/Aj7Ay/agent-harness-aibom",
                        "version": __version__,
                        "rules": list(rules_seen.values()),
                    },
                },
                "results": results,
            }
        ],
    }
