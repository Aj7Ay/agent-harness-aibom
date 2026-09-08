from harness_aibom.cyclonedx import ROOT_BOM_REF, to_cyclonedx
from harness_aibom.model import Component, HarnessDocument


def build_doc() -> HarnessDocument:
    doc = HarnessDocument(harness_name="hermes@testhost", runtime_kind="hermes", hostname="testhost")
    model = Component(component_class="model", name="qwen3:8b")
    model.set("digest", "abc123")
    doc.add(model, "uses")
    return doc


def test_envelope_shape():
    bom = to_cyclonedx(build_doc())
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["bom-ref"] == ROOT_BOM_REF
    assert bom["metadata"]["component"]["name"] == "hermes@testhost"


def test_component_carries_class_and_custom_properties():
    bom = to_cyclonedx(build_doc())
    [comp] = bom["components"]
    assert comp["type"] == "machine-learning-model"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["harness-aibom:componentClass"] == "model"
    assert props["harness-aibom:digest"] == "abc123"


def test_dependencies_link_root_to_components():
    bom = to_cyclonedx(build_doc())
    [dep] = bom["dependencies"]
    assert dep["ref"] == ROOT_BOM_REF
    assert dep["dependsOn"] == ["model:qwen3-8b"]


def test_duplicate_names_get_disambiguated_bom_refs():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="secrets_surface", name=".env"), "accesses")
    doc.add(Component(component_class="secrets_surface", name=".env"), "accesses")
    bom = to_cyclonedx(doc)
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
