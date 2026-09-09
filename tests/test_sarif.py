"""Every SARIF document render_sarif() produces is validated against the
real, official SARIF 2.1.0 JSON Schema (vendored at
tests/fixtures/sarif-schema-2.1.0.json) -- the same "validate against the
real spec, not just what looks reasonable" discipline
test_cyclonedx_schema.py already applies to this project's own canonical
output.
"""

import json
from pathlib import Path

import jsonschema
import pytest

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.sarif import render_sarif

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
SARIF_SCHEMA = json.loads(SCHEMA_PATH.read_text())

EXAMPLES = [
    Path(__file__).parent.parent / "examples" / "hermes-aibom.example.json",
    Path(__file__).parent.parent / "examples" / "openclaw-aibom.example.json",
]


def _validate(doc: dict) -> None:
    jsonschema.validate(instance=doc, schema=SARIF_SCHEMA)


def test_empty_document_produces_schema_valid_sarif_with_no_results():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    sarif = render_sarif(to_cyclonedx(doc))
    _validate(sarif)
    assert sarif["runs"][0]["results"] == []


def test_a_real_finding_produces_schema_valid_sarif_with_a_result():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    secret.set("relPath", ".hermes/.env")
    doc.add(secret, "accesses")
    sarif = render_sarif(to_cyclonedx(doc))
    _validate(sarif)

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "world_readable_secret_high_confidence"
    assert results[0]["level"] == "error"  # high severity -> error
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".hermes/.env"

    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "world_readable_secret_high_confidence" in rule_ids


def test_a_finding_with_no_path_uses_a_logical_location_not_a_fabricated_path():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    server = Component(component_class="mcp_server", name="remote-server")
    server.set("transport", "http")
    server.set("authConfigured", False)
    doc.add(server, "uses")
    sarif = render_sarif(to_cyclonedx(doc))
    _validate(sarif)

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    location = results[0]["locations"][0]
    assert "physicalLocation" not in location
    assert location["logicalLocations"][0]["fullyQualifiedName"] == server.bom_ref


@pytest.mark.parametrize("example_path", EXAMPLES, ids=lambda p: p.name)
def test_real_example_documents_produce_schema_valid_sarif(example_path):
    bom = json.loads(example_path.read_text())
    sarif = render_sarif(bom)
    _validate(sarif)
