import re

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.report import render_html


def _doc_with_everything() -> dict:
    doc = HarnessDocument(harness_name="hermes@testhost", runtime_kind="hermes", hostname="testhost")

    model = Component(component_class="model", name="qwen3:8b")
    model.set("digest", "abc123")
    model.set("family", "qwen3")
    doc.add(model, "uses")

    endpoint = Component(component_class="model_endpoint", name="http://127.0.0.1:11434/v1")
    endpoint.set("provider", "custom")
    doc.add(endpoint, "uses")

    mcp = Component(component_class="mcp_server", name="local-fs")
    mcp.set("endpoint", "https://mcp.corp.lab")
    mcp.set("tls", True)
    doc.add(mcp, "uses")

    return to_cyclonedx(doc)


def test_report_is_a_complete_html_document():
    html_text = render_html(_doc_with_everything())
    assert html_text.startswith("<!doctype html>")
    assert "</html>" in html_text
    assert "hermes@testhost" in html_text


def test_report_includes_every_property_value_nothing_summarized_away():
    html_text = render_html(_doc_with_everything())
    for expected in ("qwen3:8b", "abc123", "qwen3", "custom", "https://mcp.corp.lab", "local-fs"):
        assert expected in html_text, f"{expected!r} missing from the report"


def test_report_renders_repeated_root_relationship_properties_without_collapsing():
    # The harness root gets one relationship edge per component added to
    # the document, so "harness-aibom:relationship" repeats many times on
    # the *same* entry (the root) -- confirmed the realistic case, since
    # every real scan produces exactly this shape. The naive
    # {p["name"]: p["value"] for p in properties} dict comprehension
    # would silently keep only the last repeat.
    html_text = render_html(_doc_with_everything())
    assert "uses:model:qwen3-8b" in html_text
    assert "uses:model_endpoint:" in html_text
    assert "uses:mcp_server:local-fs" in html_text


def test_report_escapes_html_special_characters_in_names():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    comp = Component(component_class="skill", name="<script>alert(1)</script>")
    comp.set("description", "a \"quoted\" & <tagged> value")
    doc.add(comp, "loads")
    html_text = render_html(to_cyclonedx(doc))

    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;" in html_text
    assert "&amp;" in html_text


def test_report_shows_a_summary_count_per_component_class():
    html_text = render_html(_doc_with_everything())
    # Each summary row's class name carries a leading color dot -- match
    # on what follows it, not the exact cell markup.
    assert re.search(r"</span>model</td><td>1</td>", html_text)
    assert re.search(r"</span>mcp_server</td><td>1</td>", html_text)


def test_report_shows_a_kpi_row_and_a_bar_chart():
    html_text = render_html(_doc_with_everything())
    assert "kpi-row" in html_text
    assert "<svg" in html_text
    assert 'aria-label=\'Component count by class\'' in html_text


def test_report_class_colors_are_consistent_between_group_header_and_bar_chart():
    # Color follows the entity everywhere it appears -- same CSS custom
    # property referenced in the group header dot and in the bar fill.
    html_text = render_html(_doc_with_everything())
    assert "background:var(--class-model)" in html_text
    assert "fill='var(--class-model)'" in html_text


def test_report_handles_a_document_with_no_services():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="only-a-skill"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "none found" in html_text  # the Services section


def test_report_shows_not_recorded_for_deterministic_scans():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    html_text = render_html(to_cyclonedx(doc, deterministic=True))
    assert "not recorded (deterministic scan)" in html_text


def test_report_shows_actual_timestamp_and_serial_for_a_normal_scan():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    bom = to_cyclonedx(doc)
    html_text = render_html(bom)
    assert bom["serialNumber"] in html_text
    assert bom["metadata"]["timestamp"] in html_text


def test_model_version_equal_to_name_is_not_shown_twice():
    # model components set version == name (ollama.py) -- "v" + version
    # would just repeat the name right after it (e.g. "qwen3:8b
    # vqwen3:8b"). Confirmed by an actual screenshot of the rendered
    # report before this fix.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    model = Component(component_class="model", name="qwen3:8b")
    model.version = "qwen3:8b"
    doc.add(model, "uses")
    html_text = render_html(to_cyclonedx(doc))
    assert "vqwen3:8b" not in html_text


def test_version_shown_when_it_actually_differs_from_name():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    runtime = Component(component_class="runtime", name="hermes")
    runtime.version = "0.19.0"
    doc.add(runtime, "uses")
    html_text = render_html(to_cyclonedx(doc))
    assert "v0.19.0" in html_text


def test_scan_warnings_render_as_a_banner():
    # Confirmed real gap: scan warnings used to reach only stderr, never
    # the document -- a partial scan (missed Ollama, unreadable skill)
    # produced a report indistinguishable from a complete one.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.warn("hermes binary not found on PATH; runtime component skipped")
    doc.warn("configured model 'qwen3:8b' not found via Ollama /api/tags; recorded from config only")
    html_text = render_html(to_cyclonedx(doc))

    assert "scan-warnings" in html_text
    assert "2 scan warnings" in html_text
    assert "hermes binary not found on PATH" in html_text
    assert "&#x27;qwen3:8b&#x27;" in html_text  # escaped, not raw


def test_no_warnings_means_no_banner():
    # The CSS rule for .scan-warnings is always present (static stylesheet);
    # only the rendered <div> itself should be conditional on there
    # actually being warnings.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    html_text = render_html(to_cyclonedx(doc))
    assert "<div class='scan-warnings'>" not in html_text


# ---- v0.3.0: architecture / security summary / risk / MCP security -------


def test_architecture_section_shows_class_level_nodes_not_instance_level():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    for name in ("a", "b", "c"):
        doc.add(Component(component_class="skill", name=name), "loads")
    html_text = render_html(to_cyclonedx(doc))
    architecture_section = html_text.split('id="architecture"')[1].split('id="security-summary"')[0]

    assert "Architecture" in html_text
    # the aggregate node label "skill" with its count, not three
    # separately-named skill boxes
    assert re.search(r">skill<.*?>3<", architecture_section, re.DOTALL)
    assert ">a<" not in architecture_section


def test_architecture_section_on_a_near_empty_document_says_nothing_to_diagram():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    html_text = render_html(to_cyclonedx(doc))
    assert "nothing to diagram" in html_text


def test_security_summary_shows_real_counts():
    html_text = render_html(_doc_with_everything())
    assert "Security summary" in html_text
    assert re.search(r"Models</td><td>1</td>", html_text)


def test_security_summary_baseline_line_is_honest_about_a_single_scan():
    # Must never claim "0 changes" -- report has no baseline to compare
    # against, unlike `diff`. A fabricated "0" would look verified when
    # it isn't.
    html_text = render_html(_doc_with_everything())
    assert "not available for a single scan" in html_text
    assert "harness-aibom diff" in html_text


def test_risk_observations_clean_state_is_explicit_not_silent():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    html_text = render_html(to_cyclonedx(doc))
    assert "No configured risk rule fired" in html_text
    assert "not a general clean bill of health" in html_text


def test_risk_observation_renders_with_a_severity_badge():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    html_text = render_html(to_cyclonedx(doc))

    assert "sev-critical" in html_text
    assert "world-readable" in html_text


def test_mcp_security_empty_state_is_explicit():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    html_text = render_html(to_cyclonedx(doc))
    assert "No MCP servers discovered" in html_text


def test_mcp_security_card_shows_tls_and_auth_status():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    server = Component(component_class="mcp_server", name="corp-docs")
    server.set("transport", "http")
    server.set("tls", True)
    server.set("authConfigured", True)
    doc.add(server, "uses")
    html_text = render_html(to_cyclonedx(doc))

    assert "mcp-card" in html_text
    assert "status-pill ok'>TLS" in html_text
    assert "auth configured" in html_text


def test_mcp_security_card_flags_stdio_as_not_applicable_not_bad():
    # tls="n/a" for stdio must never render as the "bad" (no TLS) pill --
    # there's no network transport for stdio to secure in the first place.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    server = Component(component_class="mcp_server", name="local-fs")
    server.set("transport", "stdio")
    server.set("tls", "n/a")
    doc.add(server, "uses")
    html_text = render_html(to_cyclonedx(doc))

    assert "status-pill na'>n/a (stdio)" in html_text
    assert "status-pill bad" not in html_text


def test_skill_category_breakdown_groups_by_real_category_property():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    for name, category in (("a", "devops"), ("b", "devops"), ("c", "research")):
        skill = Component(component_class="skill", name=name)
        skill.set("category", category)
        doc.add(skill, "loads")
    html_text = render_html(to_cyclonedx(doc))

    assert "Skills by category" in html_text
    assert re.search(r"devops</td><td>2</td>", html_text)
    assert re.search(r"research</td><td>1</td>", html_text)


def test_skill_category_breakdown_absent_when_no_skills():
    html_text = render_html(_doc_with_everything())  # no skills in this fixture
    assert "Skills by category" not in html_text


# ---- v0.4.0: AIBOM Explorer (search/filter, raw JSON, new sections) ------


def test_explorer_nav_has_an_anchor_for_every_new_section():
    html_text = render_html(_doc_with_everything())
    for anchor in ("#architecture", "#security-summary", "#risk", "#mcp", "#components",
                   "#services", "#metadata", "#external-references", "#vulnerabilities",
                   "#compositions", "#raw-bom"):
        assert f"href='{anchor}'" in html_text
    for section_id in ("architecture", "security-summary", "risk", "mcp", "components",
                        "services", "metadata", "external-references", "vulnerabilities",
                        "compositions", "raw-bom"):
        assert f"id=\"{section_id}\"" in html_text


def test_search_box_and_class_filter_are_present():
    html_text = render_html(_doc_with_everything())
    assert "id=\"search-box\"" in html_text
    assert "id=\"class-filter\"" in html_text
    # filter options are real classes from this document, not invented ones
    assert "<option value='model'>model (1)</option>" in html_text
    assert "<option value='mcp_server'>mcp_server (1)</option>" in html_text


def test_entries_carry_data_class_and_data_search_for_js_filtering():
    html_text = render_html(_doc_with_everything())
    assert "data-class='model'" in html_text
    # the search blob is lowercased and includes the property value, not
    # just the name -- an independent reviewer's own example was
    # "search sha256 -> find fingerprinted objects"
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    skill = Component(component_class="skill", name="blogwatcher")
    skill.set("sha256", "deadbeef" * 8)
    doc.add(skill, "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "deadbeef" in html_text.split("data-search='")[1].split("'")[0]


def test_architecture_nodes_are_clickable_and_filter_to_their_class():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="a"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "onclick=\"goToClass('skill')\"" in html_text
    # the root node resets the filter, not "filters to a class called harness"
    assert "onclick=\"goToClass('')\"" in html_text


def test_raw_json_reveal_exists_per_entry_and_contains_real_data():
    html_text = render_html(_doc_with_everything())
    assert "Raw JSON" in html_text
    assert "class='raw-json'" in html_text
    # the raw JSON goes through the same html.escape() as everything else
    # on the page (never raw, even inside a <pre> block) -- quotes come
    # out as &quot; entities, not literal characters.
    assert "&quot;name&quot;: &quot;qwen3:8b&quot;" in html_text


def test_raw_bom_section_contains_the_full_document():
    bom = _doc_with_everything()
    html_text = render_html(bom)
    assert "Raw CycloneDX AIBOM" in html_text
    assert bom["serialNumber"] in html_text


def test_metadata_section_shows_bom_format_and_spec_version():
    bom = _doc_with_everything()
    html_text = render_html(bom)
    metadata_section = html_text.split('id="metadata"')[1].split('id="external-references"')[0]
    assert "CycloneDX" in metadata_section
    assert "1.6" in metadata_section
    assert "agent-harness-aibom" in metadata_section


def test_external_references_vulnerabilities_compositions_have_honest_empty_states():
    html_text = render_html(_doc_with_everything())
    assert "External references are not collected by this scanner." in html_text
    assert "Vulnerability data is not collected by this scanner." in html_text
    assert "Composition/completeness declarations are not collected by this scanner." in html_text
    # never a bare "0" that could look like a verified empty *result*
    ext_section = html_text.split('id="external-references"')[1].split('id="vulnerabilities"')[0]
    assert ">0<" not in ext_section


# ---- v0.5.0: Agent Security Graph (capabilities, attack surface, blast radius) --


def test_attack_surface_nav_link_and_section_present():
    html_text = render_html(_doc_with_everything())
    assert "href='#attack-surface'" in html_text
    assert 'id="attack-surface"' in html_text
    assert "Attack surface" in html_text


def test_attack_surface_groups_real_components_by_reachability():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    secret = Component(component_class="secrets_surface", name=".env")
    doc.add(secret, "accesses")
    html_text = render_html(to_cyclonedx(doc))
    surface_section = html_text.split('id="attack-surface"')[1].split('id="mcp"')[0]
    assert re.search(r"credential-store</td><td>1</td>", surface_section)


def test_attack_surface_flags_a_remote_network_endpoint():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    endpoint = Component(component_class="model_endpoint", name="https://api.example.com/v1")
    doc.add(endpoint, "uses")
    html_text = render_html(to_cyclonedx(doc))
    assert "cross a network trust boundary" in html_text


def test_attack_surface_clean_state_when_nothing_crosses_the_network_boundary():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="only-a-skill"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "Nothing in this document reaches beyond loopback or the local filesystem" in html_text


def test_entry_shows_capability_and_reachability_line():
    html_text = render_html(_doc_with_everything())
    assert "capability: network" in html_text
    assert "reachability:" in html_text


def test_blast_radius_reveal_shown_for_a_component_with_real_children():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://x"), "uses")
    model = doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")
    html_text = render_html(to_cyclonedx(doc))

    assert "Blast radius (1 reachable, observed)" in html_text
    assert model.bom_ref in html_text


def test_blast_radius_reveal_absent_for_a_leaf_component():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="lonely-skill"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "Blast radius" not in html_text
