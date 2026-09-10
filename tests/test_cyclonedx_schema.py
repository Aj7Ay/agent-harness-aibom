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
#: v1.0.0: this project's DEFAULT output still declares specVersion "1.6"
#: (opt-in "1.7" via `--spec-version`, see SPEC.md section 32 for the full
#: contract/deprecation policy -- a format bump is its own migration
#: decision, never a side effect of a test change). Confirmed directly
#: (not assumed): every document this project emits also validates
#: cleanly against the real, current CycloneDX 1.7 schema as-is, with no
#: changes needed -- so every test in this file proves that too, for
#: free, the same "highest-yield check in the whole list" a reviewer
#: specifically called this file out as being.
_VALIDATOR_1_7 = JsonStrictValidator(SchemaVersion.V1_7)


def _assert_schema_valid(bom: dict) -> None:
    text = json.dumps(bom)
    error = _VALIDATOR.validate_str(text)
    assert error is None, f"not valid CycloneDX 1.6: {error}"
    error_1_7 = _VALIDATOR_1_7.validate_str(text)
    assert error_1_7 is None, f"not valid against the current CycloneDX 1.7 schema either: {error_1_7}"


def test_hermes_scan_output_is_valid_cyclonedx():
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    _assert_schema_valid(to_cyclonedx(doc))


def test_hermes_scan_output_with_spec_version_1_7_opted_in_is_also_valid():
    # v1.0.0: --spec-version 1.7 -- confirmed directly against the real
    # schema (not assumed) that explicitly declaring specVersion "1.7"
    # still validates cleanly, since this release emits identical content
    # either way (SPEC.md's contract/deprecation policy section).
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    bom = to_cyclonedx(doc, spec_version="1.7")
    assert bom["specVersion"] == "1.7"
    error = _VALIDATOR_1_7.validate_str(json.dumps(bom))
    assert error is None, f"not valid CycloneDX 1.7 with specVersion=1.7 declared: {error}"


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


def test_obfuscated_author_email_never_produces_an_invalid_document():
    # Regression guard, same discipline as this file's own docstring:
    # an independent reviewer found a package's Author-email written as
    # a deliberately-obfuscated non-address ("Jane Doe <jane at example
    # dot com>", a real pattern used to dodge scrapers) reached
    # CycloneDX's native contact.email field unchecked, producing a
    # document that failed strict schema validation (the real schema
    # requires idn-email format there) while this package's own
    # hand-rolled `validate` command reported it valid regardless --
    # exactly the class of gap this file exists to catch.
    from harness_aibom.collectors.deps import _parse_metadata
    from harness_aibom.model import Component

    meta = _parse_metadata("Name: oddpkg\nVersion: 1.0\nAuthor-email: Jane Doe <jane at example dot com>\n\nbody\n")
    dep = Component(component_class="dependency", name=meta.name)
    dep.version = meta.version
    dep.set("supplierName", meta.supplier_name)
    dep.set("supplierEmail", meta.supplier_email)

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(dep, "uses")
    _assert_schema_valid(to_cyclonedx(doc))


def test_declarations_block_is_still_valid_cyclonedx():
    # v0.9.0: cyclonedx.py's self-assessed `declarations` block (real
    # coverage ratios, e.g. "N of N models carry a digest") -- confirmed
    # against the real vendored 1.6 schema, same discipline as every
    # other native field this project emits.
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    bom = to_cyclonedx(doc)
    assert "declarations" in bom  # this fixture has skills, so there's something real to claim
    _assert_schema_valid(bom)


def test_deterministic_output_is_still_valid_cyclonedx():
    # serialNumber and metadata.timestamp are both optional in the real
    # schema -- confirmed here rather than assumed, since getting this
    # wrong would silently break every document once --deterministic is
    # used for the cosign work on the roadmap.
    collector = HermesCollector(home=HERMES_HOME, run=lambda argv: "", fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    _assert_schema_valid(to_cyclonedx(doc, deterministic=True))
