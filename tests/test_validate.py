import copy

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.validate import find_orphan_components, validate_document


def test_valid_document_has_no_errors():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="model", name="qwen3:8b"), "uses")
    assert validate_document(to_cyclonedx(doc)) == []


def test_missing_bom_format_is_flagged():
    errors = validate_document({"specVersion": "1.6", "components": []})
    assert any("bomFormat" in e for e in errors)


# ---- v1.0.0: specVersion must be one of this project's supported values --


def test_valid_spec_versions_are_not_flagged():
    for version in ("1.6", "1.7"):
        doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
        errors = validate_document(to_cyclonedx(doc, spec_version=version))
        assert not any("specVersion" in e for e in errors)


def test_unsupported_spec_version_is_flagged():
    # Confirmed real gap: a real CycloneDX 1.7 schema validator puts no
    # enum on specVersion at all, so it happily accepts a nonsense value
    # here too -- this project's own validate() is the only place that
    # can catch a declared/actual mismatch.
    bad = {"bomFormat": "CycloneDX", "specVersion": "banana", "components": []}
    errors = validate_document(bad)
    assert any("specVersion" in e and "banana" in e for e in errors)


def test_unknown_component_class_is_flagged():
    bad = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "application",
                "name": "x",
                "properties": [{"name": "harness-aibom:componentClass", "value": "not-a-real-class"}],
            }
        ],
    }
    errors = validate_document(bad)
    assert any("unknown componentClass" in e for e in errors)


def test_type_mismatch_is_flagged():
    bad = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "application",  # should be "machine-learning-model" for componentClass "model"
                "name": "qwen3:8b",
                "properties": [{"name": "harness-aibom:componentClass", "value": "model"}],
            }
        ],
    }
    errors = validate_document(bad)
    assert any("expected 'machine-learning-model'" in e for e in errors)


# ---- v0.8.0: referential-integrity / orphan checks -------------------


def _real_document() -> dict:
    """A genuine, non-trivial CycloneDX document via the real collection
    path -- add_child() (not just add()) so a real multi-level
    dependencies[] graph exists to corrupt in the tests below, the same
    "build the real thing, then mutate it" pattern the type-mismatch test
    above already uses at a smaller scale.
    """
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://localhost:11434"), "uses")
    doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")
    doc.add(Component(component_class="skill", name="research").set("sha256", "a" * 64), "loads")
    return to_cyclonedx(doc)


def test_real_document_has_no_referential_integrity_errors():
    assert validate_document(_real_document()) == []


def test_real_document_has_no_orphans():
    assert find_orphan_components(_real_document()) == []


def test_duplicate_bom_ref_is_flagged():
    bom = _real_document()
    bom["components"][1]["bom-ref"] = bom["components"][0]["bom-ref"]  # skill now collides with model
    errors = validate_document(bom)
    assert any("duplicate bom-ref" in e for e in errors)


def test_dangling_dependency_ref_is_flagged():
    bom = _real_document()
    bom["dependencies"].append({"ref": "no-such-ref", "dependsOn": []})
    errors = validate_document(bom)
    assert any("does not match any known bom-ref" in e and "no-such-ref" in e for e in errors)


def test_dangling_depends_on_target_is_flagged():
    bom = _real_document()
    bom["dependencies"][0]["dependsOn"].append("also-no-such-ref")
    errors = validate_document(bom)
    assert any("dependsOn" in e and "also-no-such-ref" in e for e in errors)


def test_malformed_sha256_hash_is_flagged():
    bom = _real_document()
    skill = next(c for c in bom["components"] if c.get("name") == "research")
    skill["hashes"] = [{"alg": "SHA-256", "content": "not-actually-hex"}]
    errors = validate_document(bom)
    assert any("malformed SHA-256 hash" in e for e in errors)


def test_valid_sha256_hash_from_a_real_scan_is_not_flagged():
    # The real hashes[] a skill's own sha256 property produces (v0.2.4)
    # must never itself trip the malformed-hash check -- confirmed
    # against a real 64-char lowercase hex digest, not a hand-typed one.
    bom = _real_document()
    assert not any("malformed SHA-256" in e for e in validate_document(bom))


def test_orphan_component_is_flagged_as_a_warning_not_an_error():
    bom = _real_document()
    # Register a component but never relate it to anything -- exactly the
    # "scanner registered it, forgot to add()/add_child() it" bug class
    # this check exists to catch.
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "skill:orphaned",
            "name": "orphaned",
            "properties": [{"name": "harness-aibom:componentClass", "value": "skill"}],
        }
    )
    # Still a fully valid document -- an orphan breaks no rule
    # validate_document() checks.
    assert validate_document(bom) == []
    orphans = find_orphan_components(bom)
    assert orphans == ["skill:orphaned"]


def test_orphan_check_does_not_mutate_its_input():
    bom = _real_document()
    before = copy.deepcopy(bom)
    find_orphan_components(bom)
    assert bom == before


# ---- v0.8.3: supplier.contact[].email shape check -----------------------


def _document_with_dependency_email(email: str) -> dict:
    """A dependency component with an explicit `supplier.contact[].email`
    -- hand-crafted rather than run through deps.py's own real collection
    path, since validate_document() must catch a malformed email in ANY
    document handed to it, not just this project's own scan output (which
    deps.py already checks before it ever reaches here)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "some-package",
                "properties": [{"name": "harness-aibom:componentClass", "value": "dependency"}],
                "supplier": {"name": "Some Author", "contact": [{"email": email}]},
            }
        ],
    }


def test_malformed_supplier_email_is_flagged():
    errors = validate_document(_document_with_dependency_email("not-an-email"))
    assert any("supplier.contact[0].email" in e and "not-an-email" in e for e in errors)


def test_valid_supplier_email_is_not_flagged():
    errors = validate_document(_document_with_dependency_email("jane@example.com"))
    assert not any("supplier.contact" in e for e in errors)


def test_missing_supplier_email_is_not_flagged():
    bom = _document_with_dependency_email("jane@example.com")
    del bom["components"][0]["supplier"]["contact"][0]["email"]
    assert validate_document(bom) == []


def test_no_supplier_at_all_is_not_flagged():
    bom = _document_with_dependency_email("jane@example.com")
    del bom["components"][0]["supplier"]
    assert validate_document(bom) == []


def test_malformed_supplier_email_on_a_service_is_also_flagged():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [],
        "services": [
            {
                "name": "some-mcp-server",
                "properties": [{"name": "harness-aibom:componentClass", "value": "mcp_server"}],
                "supplier": {"name": "Some Author", "contact": [{"email": "also not an email"}]},
            }
        ],
    }
    errors = validate_document(bom)
    assert any("supplier.contact[0].email" in e for e in errors)
