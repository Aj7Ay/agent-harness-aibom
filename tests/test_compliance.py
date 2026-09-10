"""Tests for compliance.py -- evidence mapping, never a compliance claim.

Every control/technique ID asserted below was independently confirmed
against each framework's own real, canonical, fetched source before
compliance.py was written (see compliance.py's own module docstring for
the exact URLs and what was verified there); these tests only check
this project's own mapping/status logic, not the frameworks themselves.
"""

from harness_aibom.compliance import FRAMEWORKS, evaluate_framework
from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument


def _bom_with_dependency(purl="pkg:pypi/pyyaml@5.3") -> dict:
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="pyyaml", version="5.3")
    dep.set("purl", purl)
    doc.add(dep, "uses")
    return to_cyclonedx(doc)


def test_unknown_framework_raises_a_clear_error():
    try:
        evaluate_framework({}, "not-a-real-framework")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "unknown framework" in str(exc)
        assert "nist-ai-rmf" in str(exc)  # names the real, valid options


def test_all_three_frameworks_are_registered():
    assert set(FRAMEWORKS) == {"nist-ai-rmf", "owasp-llm-top10-2025", "mitre-atlas"}


def test_empty_document_yields_not_assessed_for_every_control():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    bom = to_cyclonedx(doc)
    for framework in FRAMEWORKS:
        result = evaluate_framework(bom, framework)
        for m in result["mappings"]:
            assert m["status"] == "not assessed", f"{framework}/{m['controlId']} should be not assessed"
            assert m["evidenceCount"] == 0


def test_nist_ai_rmf_real_control_ids_and_statuses():
    bom = _bom_with_dependency()
    result = evaluate_framework(bom, "nist-ai-rmf")
    by_id = {m["controlId"]: m for m in result["mappings"]}
    assert set(by_id) == {"GOVERN 1.6", "GOVERN 6.1", "MAP 4.1", "MEASURE 2.7"}
    # GOVERN 1.6 (inventory) has evidence -- the document has one component.
    assert by_id["GOVERN 1.6"]["status"] == "evidence collected"
    # GOVERN 6.1 / MAP 4.1 (third-party) have evidence -- there's a real dependency.
    assert by_id["GOVERN 6.1"]["status"] == "partial evidence"
    assert by_id["MAP 4.1"]["status"] == "evidence collected"
    # MEASURE 2.7 (security evaluation) has no evidence -- no risk rule fired.
    assert by_id["MEASURE 2.7"]["status"] == "not assessed"
    assert by_id["MEASURE 2.7"]["evidenceCount"] == 0


def test_owasp_llm_top10_real_ids():
    bom = _bom_with_dependency()
    result = evaluate_framework(bom, "owasp-llm-top10-2025")
    by_id = {m["controlId"]: m for m in result["mappings"]}
    assert by_id["LLM03:2025"]["controlTitle"] == "Supply Chain"
    assert by_id["LLM03:2025"]["status"] == "evidence collected"
    assert by_id["LLM06:2025"]["controlTitle"] == "Excessive Agency"
    assert by_id["LLM02:2025"]["controlTitle"] == "Sensitive Information Disclosure"


def test_mitre_atlas_real_ids():
    bom = _bom_with_dependency()
    result = evaluate_framework(bom, "mitre-atlas")
    by_id = {m["controlId"]: m for m in result["mappings"]}
    assert by_id["AML.T0010"]["controlTitle"] == "AI Supply Chain Compromise"
    assert by_id["AML.T0010"]["status"] == "partial evidence"
    assert by_id["AML.T0055"]["controlTitle"] == "Unsecured Credentials"
    assert by_id["AML.T0007"]["controlTitle"] == "Discover AI Artifacts"
    assert by_id["AML.T0007"]["status"] == "evidence collected"


def test_a_fired_security_rule_upgrades_measure_2_7_to_partial_evidence():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    model = Component(component_class="model", name="qwen3:8b")  # no digest -- fires model_no_digest
    doc.add(model, "uses")
    bom = to_cyclonedx(doc)
    result = evaluate_framework(bom, "nist-ai-rmf")
    by_id = {m["controlId"]: m for m in result["mappings"]}
    assert by_id["MEASURE 2.7"]["status"] == "partial evidence"
    assert by_id["MEASURE 2.7"]["evidenceCount"] >= 1


def test_no_mapping_ever_uses_compliance_or_pass_fail_language():
    bom = _bom_with_dependency()
    for framework in FRAMEWORKS:
        result = evaluate_framework(bom, framework)
        text = str(result).lower()
        for banned in ("compliant", "certified", "\"pass\"", "\"fail\"", "passed the audit"):
            assert banned not in text, f"{framework} leaked banned language: {banned!r}"
        allowed_statuses = {"evidence collected", "partial evidence", "not assessed"}
        for m in result["mappings"]:
            assert m["status"] in allowed_statuses


def test_source_note_names_a_real_fetched_source_per_framework():
    for framework, fw in FRAMEWORKS.items():
        assert fw["source_note"], framework
        assert any(marker in fw["source_note"] for marker in (".org", "github", "nist.gov"))


# ---- v0.10.1: the JSON disclaimer, proven not just added ----------------
#
# compliance.py's own DISCLAIMER constant was added in v0.9.1 specifically
# because `--format json` had none, only the text-mode header did --
# registered in test_docstring_claims.py's own CLAIMS dict so a future
# refactor that quietly drops it from `evaluate_framework()`'s returned
# dict gets caught here, not by another reviewer.


def test_evaluate_framework_json_result_carries_the_disclaimer():
    bom = to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t"))
    for framework in FRAMEWORKS:
        result = evaluate_framework(bom, framework)
        assert "disclaimer" in result
        assert "not a compliance or certification claim" in result["disclaimer"]
        # The disclaimer itself must not trip the same banned-language
        # check every mapping's own text already has to pass -- confirmed
        # real gap fixed in v0.9.1: an earlier draft's negated phrasing
        # ("never 'compliant' or 'pass'") said the right thing but still
        # contained both literal banned words.
        assert "compliant" not in result["disclaimer"].lower()
        assert "pass" not in result["disclaimer"].lower()
