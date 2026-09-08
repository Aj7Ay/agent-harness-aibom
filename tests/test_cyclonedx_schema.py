"""Validate real output against the actual CycloneDX 1.6 JSON Schema.

This exists because of a real defect: v0.1.2 gave `model_endpoint` and
`mcp_server` a component `type` of "service", which isn't in CycloneDX's
`type` enum -- this package's own hand-rolled `validate.py` didn't catch
it (it checks structure against this package's own SPEC.md, not the
CycloneDX schema itself), so the defect was invisible until checked
against a real validator. This test is that check, run every time.
"""

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from harness_aibom.collectors.hermes import HermesCollector
from harness_aibom.collectors.openclaw import OpenClawCollector
from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import HarnessDocument

import json
from pathlib import Path

HERMES_HOME = Path(__file__).parent / "fixtures" / "hermes_home"
OPENCLAW_HOME = Path(__file__).parent / "fixtures" / "openclaw_home"

_VALIDATOR = JsonStrictValidator(SchemaVersion.V1_6)


def _assert_schema_valid(bom: dict) -> None:
    error = _VALIDATOR.validate_str(json.dumps(bom))
    assert error is None, f"not valid CycloneDX 1.6: {error}"


def test_hermes_scan_output_is_valid_cyclonedx():
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    _assert_schema_valid(to_cyclonedx(doc))


def test_openclaw_scan_output_is_valid_cyclonedx():
    collector = OpenClawCollector(
        home=OPENCLAW_HOME,
        run=lambda argv: "",
        fetch=lambda url: {"models": []},
        env_dir=OPENCLAW_HOME / "opt-openclaw-does-not-exist",
    )
    doc = HarnessDocument(harness_name="openclaw@test", runtime_kind="openclaw", hostname="test")
    collector.collect(doc)
    _assert_schema_valid(to_cyclonedx(doc))


def test_document_with_no_services_is_still_valid():
    # Regression guard: a harness with no model_endpoint/mcp_server found
    # at all must not emit an empty or malformed "services" key.
    doc = HarnessDocument(harness_name="empty@test", runtime_kind="hermes", hostname="test")
    _assert_schema_valid(to_cyclonedx(doc))


def test_deterministic_output_is_still_valid_cyclonedx():
    # serialNumber and metadata.timestamp are both optional in the real
    # schema -- confirmed here rather than assumed, since getting this
    # wrong would silently break every document once --deterministic is
    # used for the cosign work on the roadmap.
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    _assert_schema_valid(to_cyclonedx(doc, deterministic=True))
