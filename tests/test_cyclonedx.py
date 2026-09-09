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


def test_default_output_has_serial_number_and_timestamp():
    bom = to_cyclonedx(build_doc())
    assert "serialNumber" in bom
    assert "timestamp" in bom["metadata"]


def test_deterministic_output_omits_serial_number_and_timestamp():
    bom = to_cyclonedx(build_doc(), deterministic=True)
    assert "serialNumber" not in bom
    assert "timestamp" not in bom["metadata"]


def test_deterministic_output_is_byte_identical_across_calls():
    # The whole point: two scans of the same unchanged state must produce
    # the same document, so it can be hashed/signed as a stable baseline.
    import json

    first = json.dumps(to_cyclonedx(build_doc(), deterministic=True), sort_keys=True)
    second = json.dumps(to_cyclonedx(build_doc(), deterministic=True), sort_keys=True)
    assert first == second


def test_sha256_property_also_gets_a_native_hashes_entry():
    # Additive, not a replacement -- the existing harness-aibom:sha256
    # property stays (diff.py's FINGERPRINT_FIELDS and identity fallback
    # both key on it by that exact name), but a generic CycloneDX tool
    # has no reason to know that namespace exists, only the native slot.
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    skill = Component(component_class="skill", name="incident-response")
    skill.set("sha256", "a" * 64)
    doc.add(skill, "loads")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["harness-aibom:sha256"] == "a" * 64


def test_component_without_sha256_has_no_hashes_field():
    bom = to_cyclonedx(build_doc())  # a `model`, no sha256 set
    [comp] = bom["components"]
    assert "hashes" not in comp


def test_add_child_creates_a_non_root_dependency_entry():
    # A real graph, not a flat star: a child added via add_child() must
    # appear under its *parent's* dependencies[] entry, not the root's.
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://x"), "uses")
    model = doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")

    bom = to_cyclonedx(doc)
    by_ref = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}

    assert by_ref[ROOT_BOM_REF] == [endpoint.bom_ref]  # only the direct child
    assert by_ref[endpoint.bom_ref] == [model.bom_ref]  # not the root
    assert model.bom_ref not in by_ref[ROOT_BOM_REF]


def test_known_spdx_license_gets_a_native_id_field():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="requests")
    dep.set("license", "MIT")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["licenses"] == [{"license": {"id": "MIT"}}]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["harness-aibom:license"] == "MIT"


def test_unrecognized_license_text_gets_a_native_name_field_not_a_guessed_id():
    # "Apache 2.0" (a very common raw METADATA value) is NOT the valid
    # SPDX identifier ("Apache-2.0") -- must never be guessed/normalized
    # into one, since CycloneDX's schema validates `license.id` against
    # the real SPDX enum and a wrong guess would fail strict validation.
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="oddpkg")
    dep.set("license", "Apache 2.0")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["licenses"] == [{"license": {"name": "Apache 2.0"}}]


def test_component_without_a_license_property_has_no_licenses_field():
    bom = to_cyclonedx(build_doc())  # a `model`, no license set
    [comp] = bom["components"]
    assert "licenses" not in comp


# ---- external references from purl (v0.6.0) --------------------------


def test_pypi_purl_gets_a_registry_external_reference():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="requests")
    dep.version = "2.31.0"
    dep.set("purl", "pkg:pypi/requests@2.31.0")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["externalReferences"] == [{"type": "distribution", "url": "https://pypi.org/project/requests/"}]


def test_npm_scoped_purl_gets_a_registry_external_reference_with_the_real_at_sign():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="@modelcontextprotocol/server-filesystem")
    dep.set("purl", "pkg:npm/%40modelcontextprotocol/server-filesystem@2.1.0")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["externalReferences"] == [{
        "type": "distribution",
        "url": "https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem",
    }]


def test_unpinned_purl_still_gets_a_version_agnostic_registry_reference():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="some-package")
    dep.set("purl", "pkg:npm/some-package")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["externalReferences"] == [{"type": "distribution", "url": "https://www.npmjs.com/package/some-package"}]


def test_component_without_a_purl_has_no_external_references_field():
    bom = to_cyclonedx(build_doc())  # a `model`, no purl set
    [comp] = bom["components"]
    assert "externalReferences" not in comp


def test_supplier_name_and_email_promote_to_a_native_organizational_entity():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="requests")
    dep.set("supplierName", "Kenneth Reitz")
    dep.set("supplierEmail", "me@kennethreitz.org")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["supplier"] == {"name": "Kenneth Reitz", "contact": [{"email": "me@kennethreitz.org"}]}


def test_supplier_email_only_still_produces_a_valid_partial_supplier():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="oddpkg")
    dep.set("supplierEmail", "maintainers@oddpkg.example")
    doc.add(dep, "uses")

    [comp] = to_cyclonedx(doc)["components"]
    assert comp["supplier"] == {"contact": [{"email": "maintainers@oddpkg.example"}]}


def test_component_without_supplier_fields_has_no_supplier_field():
    bom = to_cyclonedx(build_doc())  # a `model`, no supplier fields set
    [comp] = bom["components"]
    assert "supplier" not in comp


def test_dependency_graph_has_no_dangling_references():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://x"), "uses")
    doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")
    doc.add(Component(component_class="skill", name="incident-response"), "loads")

    bom = to_cyclonedx(doc)
    all_refs = {bom["metadata"]["component"]["bom-ref"]}
    all_refs |= {c["bom-ref"] for c in bom["components"]}
    all_refs |= {s["bom-ref"] for s in bom.get("services", [])}

    for dep in bom["dependencies"]:
        assert dep["ref"] in all_refs
        for target in dep["dependsOn"]:
            assert target in all_refs
