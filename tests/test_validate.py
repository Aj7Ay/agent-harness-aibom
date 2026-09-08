from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.validate import validate_document


def test_valid_document_has_no_errors():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="model", name="qwen3:8b"), "uses")
    assert validate_document(to_cyclonedx(doc)) == []


def test_missing_bom_format_is_flagged():
    errors = validate_document({"specVersion": "1.6", "components": []})
    assert any("bomFormat" in e for e in errors)


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
