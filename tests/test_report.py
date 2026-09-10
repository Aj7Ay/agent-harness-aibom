import re

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.report import render_diff_report, render_html


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
    architecture_section = html_text.split('id="architecture"')[1].split('id="dependency-graph"')[0]

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
    assert "data-goto='skill'" in html_text
    # the root node resets the filter, not "filters to a class called harness"
    assert "data-goto=''" in html_text
    # v0.5.1: never a server-rendered onclick handler for this -- see the
    # dedicated XSS regression test below for why.
    assert "onclick=" not in html_text


def test_architecture_node_click_survives_a_componentclass_containing_a_quote():
    # Regression test: an independent reviewer found that a componentClass
    # value containing a single quote broke out of the old
    # onclick="goToClass('...')" JS string literal -- html.escape() is the
    # wrong escaper for "a value embedded in a JS string that is itself
    # inside an HTML attribute" (the browser HTML-decodes the attribute,
    # turning &#x27; back into a literal ', *before* the JS parser ever
    # sees it). Reproduced exactly: rendering a hand-crafted document (not
    # one this scanner itself produced -- collectors are restricted to a
    # fixed componentClass vocabulary, but `report` accepts any JSON file)
    # with a malicious class used to execute injected script. `data-goto`
    # (read via getAttribute(), never re-parsed as JS) has no such
    # nested-grammar problem in the first place.
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "harness-root", "name": "evil@test"}},
        "components": [{
            "type": "application", "bom-ref": "c1", "name": "x",
            "properties": [{"name": "harness-aibom:componentClass", "value": "x'); alert(document.domain); //"}],
        }],
        "dependencies": [{"ref": "harness-root", "dependsOn": ["c1"]}],
    }
    html_text = render_html(bom)
    assert "alert(document.domain)" not in html_text.split("data-goto='")[1].split("'")[0]
    assert "onclick=" not in html_text
    # the value still reaches the page, safely, as an HTML-attribute value
    assert "data-goto='x&#x27;); alert(document.domain); //'" in html_text


def test_raw_json_reveal_exists_per_entry_with_a_lazy_populated_pre_block():
    # v0.5.1: no longer server-embedded (see the file-size regression
    # test below) -- populated client-side from the shared #bom-data
    # blob, so the server-rendered <pre> starts empty.
    html_text = render_html(_doc_with_everything())
    assert "Raw JSON" in html_text
    assert "<pre class='raw-json'></pre>" in html_text
    assert "data-bom-ref=" in html_text
    # the one real copy is the compact #bom-data blob, not a second
    # pretty-printed copy per entry
    assert '"name":"qwen3:8b"' in html_text  # compact json.dumps has no space after ":"


def test_raw_bom_section_is_lazy_and_references_the_shared_data_blob():
    bom = _doc_with_everything()
    html_text = render_html(bom)
    assert "Raw CycloneDX AIBOM" in html_text
    assert "data-bom-ref='__bom__'" in html_text
    assert bom["serialNumber"] in html_text  # present once, in #bom-data


def test_report_does_not_duplicate_entry_data_into_a_second_pretty_json_copy():
    # Regression test: an independent reviewer measured a real report at
    # roughly 6x the size of the same document's v0.3.0 report, because
    # every entry embedded its own full pretty-printed json.dumps(...,
    # indent=2) copy *and* the top-level Raw BOM section embedded a
    # second full pretty copy of the whole document. Confirmed by
    # counting: a document with N entries should carry the entry's own
    # data only once (in the single compact #bom-data blob), not N+1
    # times.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    for i in range(20):
        doc.add(Component(component_class="skill", name=f"skill-{i}"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    # each skill's name would appear in a per-entry pretty copy AND the
    # raw-bom copy under the old design (2x); now it appears once, inside
    # the compact #bom-data blob, plus once more in the entry's own
    # visible name/search-blob text -- never a third, JSON-shaped copy.
    assert html_text.count('"name":"skill-0"') == 1


def test_metadata_section_shows_bom_format_and_spec_version():
    bom = _doc_with_everything()
    html_text = render_html(bom)
    metadata_section = html_text.split('id="metadata"')[1].split('id="external-references"')[0]
    assert "CycloneDX" in metadata_section
    assert "1.6" in metadata_section
    assert "agent-harness-aibom" in metadata_section


def test_external_references_vulnerabilities_compositions_have_honest_empty_states():
    # _doc_with_everything() has no purl-bearing dependency component,
    # so external references legitimately stay in the empty state too.
    html_text = render_html(_doc_with_everything())
    assert "External references are not collected by this scanner." in html_text
    # Vulnerabilities (v0.9.0, vex.py) now distinguishes "not collected" from
    # "checked, none found" -- see the dedicated tests below -- so this
    # document (never run through `scan-vulns`) gets the "never checked" copy.
    assert "has not been checked for this document" in html_text
    assert "Composition/completeness declarations are not collected by this scanner." in html_text
    # never a bare "0" that could look like a verified empty *result*
    ext_section = html_text.split('id="external-references"')[1].split('id="vulnerabilities"')[0]
    assert ">0<" not in ext_section


def test_external_references_section_shows_a_real_purl_derived_registry_link():
    # v0.6.0: no longer a permanent empty-state stub -- a dependency
    # component's purl produces a real, native externalReferences entry
    # (cyclonedx.py), and the report section must actually surface it.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    dep = Component(component_class="dependency", name="requests")
    dep.version = "2.31.0"
    dep.set("purl", "pkg:pypi/requests@2.31.0")
    doc.add(dep, "uses")
    html_text = render_html(to_cyclonedx(doc))

    ext_section = html_text.split('id="external-references"')[1].split('id="vulnerabilities"')[0]
    assert "https://pypi.org/project/requests/" in ext_section
    assert "not collected by this scanner" not in ext_section


def test_external_reference_with_a_non_http_scheme_is_never_a_clickable_link():
    # Regression test: report accepts any JSON file, not just ones this
    # scanner produced -- a hand-crafted document setting an
    # externalReferences[].url to a non-http(s) scheme (e.g. a
    # javascript: URI) must never render as a real <a href> link, the
    # same discipline as the v0.5.1 architecture-diagram XSS fix.
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "harness-root", "name": "evil@test"}},
        "components": [{
            "type": "library", "bom-ref": "c1", "name": "evil-dep",
            "externalReferences": [{"type": "website", "url": "javascript:alert(document.domain)"}],
            "properties": [{"name": "harness-aibom:componentClass", "value": "dependency"}],
        }],
        "dependencies": [{"ref": "harness-root", "dependsOn": ["c1"]}],
    }
    html_text = render_html(bom)
    assert "href='javascript:" not in html_text
    # the value still reaches the page, safely, as escaped text
    assert "javascript:alert(document.domain)" in html_text


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


def test_supply_chain_reveal_shown_for_a_component_with_real_dependencies():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://x"), "uses")
    model = doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")
    html_text = render_html(to_cyclonedx(doc))

    assert "Depends on (1 reachable, observed)" in html_text
    assert model.bom_ref in html_text


def test_blast_radius_reveal_shown_for_a_leaf_component_via_the_harness_root():
    # v0.5.1: blast radius is the reverse of "Depends on" -- what would
    # be affected if this were compromised, not what it relies on. Even
    # a leaf (a skill with nothing downstream of it) has the harness
    # root depend on it, so "Blast radius" is never simply absent the
    # way "Depends on" legitimately is for a leaf.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="lonely-skill"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "Blast radius (1 reachable, observed)" in html_text
    # "Depends on" as a cross-reference inside the blast-radius blurb is
    # fine -- what must be absent is the "Depends on" reveal itself.
    assert "<summary>Depends on" not in html_text


# ---- v0.7.0: report --baseline / Baseline diff section --------------------


def test_baseline_diff_section_absent_by_default():
    html_text = render_html(_doc_with_everything())
    section = html_text.split('id="baseline-diff"')[1].split('id="raw-bom"')[0]
    assert "No baseline supplied" in section


def test_baseline_diff_section_shows_added_removed_changed():
    from harness_aibom.diff import diff_documents

    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    kept = Component(component_class="skill", name="kept")
    kept.set("sha256", "aaa")
    before_doc.add(kept, "loads")
    removed = Component(component_class="skill", name="removed-skill")
    before_doc.add(removed, "loads")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    kept2 = Component(component_class="skill", name="kept")
    kept2.set("sha256", "bbb")
    after_doc.add(kept2, "loads")
    added = Component(component_class="skill", name="added-skill")
    after_doc.add(added, "loads")
    after = to_cyclonedx(after_doc)

    diff_result = diff_documents(before, after)
    html_text = render_html(after, diff_result=diff_result)
    section = html_text.split('id="baseline-diff"')[1].split('id="raw-bom"')[0]

    assert "skill:added-skill" in section
    assert "skill:removed-skill" in section
    assert "skill:kept" in section
    assert "No baseline supplied" not in section


def test_baseline_diff_clean_state_when_nothing_changed():
    from harness_aibom.diff import diff_documents

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="skill", name="unchanged"), "loads")
    bom = to_cyclonedx(doc)

    diff_result = diff_documents(bom, bom)
    html_text = render_html(bom, diff_result=diff_result)
    section = html_text.split('id="baseline-diff"')[1].split('id="raw-bom"')[0]
    assert "No changes since the baseline" in section


def test_security_summary_baseline_line_reflects_real_diff_counts():
    from harness_aibom.diff import diff_documents

    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before = to_cyclonedx(before_doc)
    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_doc.add(Component(component_class="skill", name="new-skill"), "loads")
    after = to_cyclonedx(after_doc)

    diff_result = diff_documents(before, after)
    html_text = render_html(after, diff_result=diff_result)
    assert "1 added" in html_text
    assert "not available for a single scan" not in html_text


# ---- v0.8.0: Component Inspector --------------------------------------


def test_entries_carry_a_bom_ref_and_an_inspect_button():
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    doc.add(Component(component_class="skill", name="research"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "data-bom-ref='skill:research'" in html_text
    assert "data-inspect='skill:research'" in html_text
    assert "class='inspect-btn'" in html_text
    assert "onclick=" not in html_text  # same data-* delegated pattern as data-goto, never inline


def test_inspector_modal_markup_is_present_once():
    html_text = render_html(_doc_with_everything())
    assert html_text.count('id="inspector-panel"') == 1
    assert 'id="inspector-body"' in html_text
    assert 'id="inspector-close"' in html_text
    assert 'id="inspector-copy"' in html_text
    # hidden by default -- see _CSS's .inspector-overlay:not([hidden])
    # note for why `hidden` (the attribute JS toggles) has to be the real
    # gate, not just the base CSS rule.
    assert '<div id="inspector-panel" class="inspector-overlay" hidden>' in html_text


def test_inspector_functions_are_wired_into_js():
    html_text = render_html(_doc_with_everything())
    assert "function openInspector(" in html_text
    assert "function closeInspector(" in html_text
    assert "function findEntryByRef(" in html_text
    assert "function copyBomRef(" in html_text
    # Escape-to-close is real behavior, not just markup -- along with
    # open/backdrop-click-close/inner-click-does-not-close/lazy raw-JSON
    # population inside the clone, all verified with real dispatched
    # browser events (headless Chrome, iframe + contentWindow.Event)
    # before shipping, same discipline as every prior JS-touching release.
    assert "event.key === 'Escape'" in html_text


def test_inspect_button_survives_a_bom_ref_containing_a_quote():
    # Same regression class as the data-goto XSS fix (v0.5.1): a bom-ref
    # this scanner didn't itself generate (report accepts any JSON file --
    # collectors are restricted to a safe bom_ref slug, but a hand-crafted
    # document isn't) must not be able to break out of the data-inspect
    # attribute and inject script.
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "harness-root", "name": "evil@test"}},
        "components": [{
            "type": "application", "bom-ref": "c1'); alert(document.domain); //", "name": "x",
            "properties": [{"name": "harness-aibom:componentClass", "value": "skill"}],
        }],
        "dependencies": [{"ref": "harness-root", "dependsOn": ["c1'); alert(document.domain); //"]}],
    }
    html_text = render_html(bom)
    assert "onclick=" not in html_text
    # The payload reaches the page only as an HTML-escaped attribute
    # *value* -- the escaped quote (&#x27;, never a literal ') means there
    # is no unescaped `'` left to close the attribute early with, so the
    # rest of the string can never be interpreted as a second attribute or
    # break out into markup, regardless of what text it contains.
    assert "data-inspect='c1&#x27;); alert(document.domain); //'" in html_text


# ---- v0.8.2: model digest drift callout in the baseline diff ----------


def test_model_digest_drift_is_called_out_distinctly():
    from harness_aibom.diff import diff_documents

    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before_model = Component(component_class="model", name="qwen3:8b")
    before_model.set("digest", "sha256:aaa")
    before_doc.add(before_model, "uses")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_model = Component(component_class="model", name="qwen3:8b")  # same tag/name
    after_model.set("digest", "sha256:bbb")  # different content
    after_doc.add(after_model, "uses")
    after = to_cyclonedx(after_doc)

    diff_result = diff_documents(before, after)
    html_text = render_html(after, diff_result=diff_result)
    section = html_text.split('id="baseline-diff"')[1].split('id="raw-bom"')[0]
    assert "model-drift-callout" in section
    assert "Model content changed" in section
    assert "sha256:aaa" in section
    assert "sha256:bbb" in section


def test_trust_zones_section_present_and_splits_local_from_network():
    html_text = render_html(_doc_with_everything())
    section = html_text.split('id="trust-zones"')[1].split('id="capability-matrix"')[0]
    assert "TRUST ZONE: LOCAL HOST" in section
    assert "TRUST ZONE: NETWORK" in section
    # the mcp_server's real remote endpoint (mcp.corp.lab) crosses the
    # network boundary; the loopback model_endpoint does not.
    assert "mcp_server:local-fs" in section


def test_trust_zones_clean_state_when_nothing_crosses_the_network():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="skill", name="local-only"), "loads")
    html_text = render_html(to_cyclonedx(doc))
    section = html_text.split('id="trust-zones"')[1].split('id="capability-matrix"')[0]
    assert "No components cross a network trust boundary" in section
    assert "TRUST ZONE: NETWORK" not in section


def test_raw_bom_search_box_and_highlight_wiring_present():
    # Real interactive behavior (open -> highlight matches -> clear ->
    # matches removed, including a query containing regex-special
    # characters) verified with real dispatched browser events (headless
    # Chrome, iframe + contentWindow.Event) before shipping, the same
    # discipline every JS-touching release follows -- this caught a real
    # missing addEventListener wiring bug (highlightRawBom() was defined
    # but never attached to the search box's 'input' event) during
    # development, the same class of bug the v0.4.0 postmortem warns
    # about. These assertions only cover what a static-HTML test can:
    # the markup and function/wiring text are actually present.
    html_text = render_html(_doc_with_everything())
    assert "id='raw-bom-search'" in html_text
    assert "function highlightRawBom(" in html_text
    assert "function escapeRegExp(" in html_text
    assert "rawBomSearch.addEventListener('input', highlightRawBom)" in html_text
    assert "pre.dataset.rawText" in html_text


def test_capability_matrix_aggregates_by_class_capability_reachability():
    html_text = render_html(_doc_with_everything())
    section = html_text.split('id="capability-matrix"')[1].split('id="mcp"')[0]
    assert "model" in section
    assert "model-provider" in section  # model's own reachability tag
    assert "network" in section  # mcp_server's https endpoint


def test_non_model_digest_style_changes_do_not_trigger_the_drift_callout():
    from harness_aibom.diff import diff_documents

    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before_skill = Component(component_class="skill", name="research")
    before_skill.set("sha256", "a" * 64)
    before_doc.add(before_skill, "loads")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_skill = Component(component_class="skill", name="research")
    after_skill.set("sha256", "b" * 64)
    after_doc.add(after_skill, "loads")
    after = to_cyclonedx(after_doc)

    diff_result = diff_documents(before, after)
    html_text = render_html(after, diff_result=diff_result)
    section = html_text.split('id="baseline-diff"')[1].split('id="raw-bom"')[0]
    assert "model-drift-callout" not in section


# ---- v0.8.2: Artifact integrity section ---------------------------------


def test_artifact_integrity_absent_by_default():
    html_text = render_html(_doc_with_everything())
    section = html_text.split('id="artifact-integrity"')[1].split('id="raw-bom"')[0]
    assert "No signature bundle supplied" in section


def test_artifact_integrity_shows_verified_state():
    html_text = render_html(_doc_with_everything(), signature_info={
        "sha256": "a" * 64, "bundle": "aibom.json.bundle", "key": "cosign.pub",
        "verified": True, "output": "Verified OK\n",
    })
    section = html_text.split('id="artifact-integrity"')[1].split('id="raw-bom"')[0]
    assert "Signature verified" in section
    assert "a" * 64 in section
    assert "NOT VERIFIED" not in section


def test_artifact_integrity_shows_not_verified_state_honestly():
    html_text = render_html(_doc_with_everything(), signature_info={
        "sha256": "b" * 64, "bundle": "aibom.json.bundle", "key": "cosign.pub",
        "verified": False, "output": "Error: failed to verify signature\n",
    })
    section = html_text.split('id="artifact-integrity"')[1].split('id="raw-bom"')[0]
    assert "NOT VERIFIED" in section
    assert "failed to verify signature" in section
    assert "Signature verified" not in section


# ---- Vulnerabilities section (vex.py / OSV.dev, opt-in) ------------------


def _vuln_section(bom: dict) -> str:
    html_text = render_html(bom)
    return html_text.split('id="vulnerabilities"')[1].split('id="compositions"')[0]


def test_vulnerabilities_section_says_never_checked_by_default():
    section = _vuln_section(_doc_with_everything())
    assert "has not been checked for this document" in section
    assert "scan-vulns" in section


def test_vulnerabilities_section_distinguishes_checked_clean_from_never_checked():
    bom = _doc_with_everything()
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "dependency:clean-pkg",
            "name": "clean-pkg",
            "purl": "pkg:pypi/clean-pkg@1.0",
            "properties": [
                {"name": "harness-aibom:componentClass", "value": "dependency"},
                {"name": "harness-aibom:vulnCheck", "value": "checked"},
            ],
        }
    )
    section = _vuln_section(bom)
    assert "has not been checked for this document" not in section
    assert "Checked, none found for 1 component" in section


def test_vulnerabilities_section_renders_a_real_finding_with_severity_and_link():
    bom = _doc_with_everything()
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "dependency:pyyaml",
            "name": "pyyaml",
            "purl": "pkg:pypi/pyyaml@5.3",
            "properties": [
                {"name": "harness-aibom:componentClass", "value": "dependency"},
                {"name": "harness-aibom:vulnCheck", "value": "checked"},
            ],
        }
    )
    bom["vulnerabilities"] = [
        {
            "id": "GHSA-6757-jp84-gxfx",
            "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx"},
            "description": "Improper Input Validation in PyYAML",
            "affects": [{"ref": "dependency:pyyaml"}],
            "ratings": [{"source": {"name": "OSV"}, "method": "CVSSv31", "severity": "critical",
                         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "cwes": [20],
        }
    ]
    section = _vuln_section(bom)
    assert "GHSA-6757-jp84-gxfx" in section
    assert "https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx" in section
    assert "Improper Input Validation in PyYAML" in section
    assert "CRITICAL" in section
    assert 'data-inspect=\'dependency:pyyaml\'' in section  # reuses the Component Inspector wiring
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in section


def test_vulnerabilities_with_no_cvss_vector_render_as_unrated_not_a_fabricated_severity():
    bom = _doc_with_everything()
    bom["vulnerabilities"] = [
        {"id": "PYSEC-2018-28", "source": {"name": "OSV"}, "affects": [{"ref": "harness-root"}]}
    ]
    section = _vuln_section(bom)
    assert "UNRATED" in section


# ---- Declarations section (cyclonedx.py, self-assessed coverage claims) --


def _declarations_section(bom: dict) -> str:
    html_text = render_html(bom)
    return html_text.split('id="declarations"')[1].split('id="compositions"')[0]


def test_declarations_section_present_for_a_real_scan():
    bom = to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t"))
    # A plain empty document has nothing to self-assess -- honest empty state.
    section = _declarations_section(bom)
    assert "No self-assessed claims" in section


def test_declarations_section_renders_a_real_claim_and_never_third_party():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    model = Component(component_class="model", name="qwen3:8b")
    model.set("digest", "abc123")
    doc.add(model, "uses")
    bom = to_cyclonedx(doc)
    section = _declarations_section(bom)
    assert "1 of 1 discovered model(s) carry a real content digest" in section
    assert "thirdParty: false" in section
    assert "is compliant" not in section.lower()
    assert "certified" not in section.lower()


# ---- Compliance evidence mapping section (compliance.py) -----------------


def _compliance_section(bom: dict) -> str:
    html_text = render_html(bom)
    return html_text.split('id="compliance"')[1].split('id="compositions"')[0]


def test_compliance_section_labels_itself_as_evidence_mapping_not_certification():
    section = _compliance_section(_doc_with_everything())
    assert "NOT a compliance or certification claim" in section
    assert "is compliant" not in section.lower()
    assert "certified" not in section.lower()


def test_compliance_section_renders_all_three_frameworks_with_real_ids():
    section = _compliance_section(_doc_with_everything())
    assert "NIST AI Risk Management Framework" in section
    assert "GOVERN 1.6" in section
    assert "OWASP Top 10 for LLM Applications" in section
    assert "LLM03:2025" in section
    assert "MITRE ATLAS" in section
    assert "AML.T0007" in section


# ---- Evidence chains in the Component Inspector (v0.9.0, built on #4) ----


def _skill_doc_with_content_analysis() -> dict:
    doc = HarnessDocument(harness_name="hermes@testhost", runtime_kind="hermes", hostname="testhost")
    skill = Component(component_class="skill", name="web-fetcher")
    skill.set("sha256", "a" * 64)
    skill.set("sha256Confidence", "observed")
    skill.set("referencedServers", "corp-docs")
    skill.set("shellIndicators", "curl")
    skill.set("contentAnalysisConfidence", "inferred")
    doc.add(skill, "loads")
    return to_cyclonedx(doc)


def test_evidence_chain_renders_for_a_skill_with_content_analysis():
    html_text = render_html(_skill_doc_with_content_analysis())
    assert "Evidence chain" in html_text
    assert "analyze_skill_content() found this MCP server name mentioned" in html_text
    assert ">corp-docs<" in html_text
    assert "INFERRED" in html_text
    assert "sha256_directory() directly hashed every file under this component directory" in html_text
    assert "OBSERVED" in html_text


def test_evidence_chain_absent_for_a_component_with_no_confidence_data():
    # _doc_with_everything() has a model/model_endpoint/mcp_server, none
    # of which carry the v0.9.0 confidence properties in this test setup.
    html_text = render_html(_doc_with_everything())
    assert "Evidence chain" not in html_text


def test_evidence_chain_never_shown_for_a_skill_analysis_found_nothing():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    skill = Component(component_class="skill", name="quiet-skill")
    skill.set("sha256", "b" * 64)
    skill.set("sha256Confidence", "observed")
    # No contentAnalysisConfidence -- analysis found nothing to infer.
    doc.add(skill, "loads")
    html_text = render_html(to_cyclonedx(doc))
    assert "Evidence chain" in html_text  # the observed sha256 row still shows
    assert "INFERRED" not in html_text
    assert "OBSERVED" in html_text


# ---- Dependency graph explorer (v0.9.0) -----------------------------------


def _dep_graph_doc_with_edges() -> dict:
    doc = HarnessDocument(harness_name="hermes@testhost", runtime_kind="hermes", hostname="testhost")
    endpoint = Component(component_class="model_endpoint", name="http://127.0.0.1:11434")
    doc.add(endpoint, "uses")
    model = Component(component_class="model", name="qwen3:8b")
    doc.add_child(model, endpoint, "uses")
    return to_cyclonedx(doc)


def test_dependency_graph_section_gives_every_real_component_at_least_a_root_edge():
    # A component added via HarnessDocument.add() is always a root child,
    # so it always has at least one recorded parent edge (the harness
    # root itself) -- a genuinely edge-less component (§ below) only
    # happens for a hand-edited/malformed document, not a real scan.
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    skill = Component(component_class="skill", name="lonely-skill")
    doc.add(skill, "loads")
    html_text = render_html(to_cyclonedx(doc))
    section = html_text.split('id="dependency-graph"')[1].split('id="security-summary"')[0]
    assert "dep-graph-node" in section


def test_dependency_graph_section_absent_state_for_a_genuine_orphan():
    # A component present in components[] but never referenced anywhere
    # in dependencies[] at all -- the same real, malformed-document case
    # validate.py's find_orphan_components() exists to catch (`report`
    # renders any JSON handed to it, not just this scanner's own output).
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="skill", name="normal-skill"), "loads")
    bom = to_cyclonedx(doc)
    bom["components"].append({
        "type": "library", "bom-ref": "skill:orphan", "name": "orphan-skill",
        "properties": [{"name": "harness-aibom:componentClass", "value": "skill"}],
    })
    html_text = render_html(bom)
    section = html_text.split('id="dependency-graph"')[1].split('id="security-summary"')[0]
    assert "data-ref='skill:orphan'" not in section  # no node pre-rendered for it
    assert "dep-graph-no-edges" in section  # the JS-side fallback message still exists


def test_dependency_graph_section_renders_hidden_nodes_and_controls():
    html_text = render_html(_dep_graph_doc_with_edges())
    section = html_text.split('id="dependency-graph"')[1].split('id="security-summary"')[0]
    assert "dep-graph-show" in section
    assert "dep-graph-input" in section
    assert "qwen3:8b" in section  # datalist option label
    # both the endpoint and the model have real edges -- both get a node
    assert section.count("dep-graph-node") >= 2
    # hidden by default -- collapsed, not an all-nodes-at-once canvas
    assert "class='dep-graph-node' data-ref=" in section and "hidden>" in section


def test_dependency_graph_neighbor_boxes_are_clickable_via_data_view_graph():
    html_text = render_html(_dep_graph_doc_with_edges())
    assert "data-view-graph=" in html_text


def test_inspector_has_a_view_in_graph_button():
    html_text = render_html(_dep_graph_doc_with_edges())
    assert "inspector-view-graph" in html_text
    assert "View in graph" in html_text


def test_dependency_graph_functions_are_wired_into_js():
    html_text = render_html(_dep_graph_doc_with_edges())
    for fn in ("showDependencyGraph", "findEntryRefByNameOrRef", "viewInGraph"):
        assert f"function {fn}(" in html_text
    assert "data-view-graph" in html_text
    assert "inspector-view-graph" in html_text


# ---- Raw BOM -> Component Inspector cross-navigation (v0.9.0) -----------


def test_raw_bom_intro_mentions_clickable_bom_refs():
    html_text = render_html(_doc_with_everything())
    assert "clickable link back to" in html_text


def test_linkify_bom_refs_function_is_wired_into_js():
    html_text = render_html(_doc_with_everything())
    assert "function linkifyBomRefs(" in html_text
    assert "raw-bom-ref-link" in html_text
    # Called unconditionally from highlightRawBom(), not only when a
    # search query happens to be active.
    assert "pre.innerHTML = linkifyBomRefs(html);" in html_text


# ---- v0.10.0: report --diff / render_diff_report() ----------------------


def _plain_doc(name: str = "h") -> HarnessDocument:
    return HarnessDocument(harness_name=name, runtime_kind="hermes", hostname="testhost")


def test_diff_report_is_a_complete_html_document():
    before = to_cyclonedx(_plain_doc())
    after = to_cyclonedx(_plain_doc())
    html_text = render_diff_report(before, after)
    assert html_text.startswith("<!doctype html>")
    assert "</html>" in html_text
    assert "Change report" in html_text


def test_diff_report_clean_state_is_honest_about_ignored_fields():
    before = to_cyclonedx(_plain_doc())
    after = to_cyclonedx(_plain_doc())
    html_text = render_diff_report(before, after)
    assert "No differences on the fields this tool compares" in html_text
    assert "path" in html_text
    assert "Changes (0)" in html_text


def test_diff_report_partial_scan_banner_appears_for_either_side():
    before_doc = _plain_doc()
    before_doc.warn("hermes binary not found on PATH; runtime component skipped")
    before = to_cyclonedx(before_doc)
    after = to_cyclonedx(_plain_doc())

    html_text = render_diff_report(before, after)
    assert "scan warnings" in html_text
    assert "before" in html_text.lower()


def test_diff_report_no_banner_when_neither_side_has_warnings():
    before = to_cyclonedx(_plain_doc())
    after = to_cyclonedx(_plain_doc())
    html_text = render_diff_report(before, after)
    assert "scan warnings" not in html_text


def test_diff_report_hostname_mismatch_banner():
    before = to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="box-a"))
    after = to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="box-b"))
    html_text = render_diff_report(before, after)
    assert "different hostnames" in html_text
    assert "box-a" in html_text and "box-b" in html_text


def test_diff_report_no_hostname_banner_when_hosts_match():
    before = to_cyclonedx(_plain_doc())
    after = to_cyclonedx(_plain_doc())
    html_text = render_diff_report(before, after)
    assert "different hostnames" not in html_text


def test_diff_report_is_byte_identical_for_two_deterministic_inputs():
    before = to_cyclonedx(_plain_doc(), deterministic=True)
    after_doc = _plain_doc()
    after_doc.add(Component(component_class="skill", name="a"), "loads")
    after = to_cyclonedx(after_doc, deterministic=True)

    first = render_diff_report(before, after)
    second = render_diff_report(before, after)
    assert first == second


# ---- one case per severity row --------------------------------------


def _changed_pair(cls: str, name: str, set_before, set_after):
    before_doc, after_doc = _plain_doc(), _plain_doc()
    b = Component(component_class=cls, name=name)
    set_before(b)
    before_doc.add(b, "loads" if cls in ("skill", "hook", "prompt_surface") else "uses")
    a = Component(component_class=cls, name=name)
    set_after(a)
    after_doc.add(a, "loads" if cls in ("skill", "hook", "prompt_surface") else "uses")
    return to_cyclonedx(before_doc), to_cyclonedx(after_doc)


def _severity_of(html_text: str, needle: str) -> str:
    """Extracts the risk-badge severity word immediately preceding
    `needle`'s own <li> in the Changes section -- lets each severity
    test assert against the real rendered badge, not just "the text is
    somewhere on the page"."""
    idx = html_text.index(needle)
    li_start = html_text.rindex("<li>", 0, idx)
    li = html_text[li_start:idx]
    for label in ("HIGH", "MEDIUM", "LOW"):
        if label in li:
            return label
    raise AssertionError(f"no severity badge found before {needle!r}")


def test_severity_hook_content_changed_after_approval_is_high():
    before, after = _changed_pair(
        "hook", "pre-commit.sh",
        lambda c: c.set("contentChangedSinceApproval", False),
        lambda c: c.set("contentChangedSinceApproval", True),
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "pre-commit.sh") == "HIGH"
    assert "content changed after approval" in html_text


def test_severity_skill_sha256_changed_is_high():
    before, after = _changed_pair("skill", "research", lambda c: c.set("sha256", "a" * 64), lambda c: c.set("sha256", "b" * 64))
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "research") == "HIGH"


def test_severity_prompt_surface_sha256_changed_is_high():
    before, after = _changed_pair(
        "prompt_surface", "AGENTS.md", lambda c: c.set("sha256", "a" * 64), lambda c: c.set("sha256", "b" * 64)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "AGENTS.md") == "HIGH"


def test_severity_secrets_surface_becoming_world_readable_is_high():
    before, after = _changed_pair(
        "secrets_surface", ".env", lambda c: c.set("worldReadable", False), lambda c: c.set("worldReadable", True)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, ".env") == "HIGH"
    assert "became world-readable" in html_text


def test_severity_model_digest_changed_is_high():
    before, after = _changed_pair("model", "qwen3:8b", lambda c: c.set("digest", "a" * 20), lambda c: c.set("digest", "b" * 20))
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "qwen3:8b") == "HIGH"


def test_severity_new_mcp_server_http_no_tls_is_high():
    doc = _plain_doc()
    doc.add(Component(component_class="mcp_server", name="exfil").set("transport", "http").set("tls", False), "uses")
    before, after = to_cyclonedx(_plain_doc()), to_cyclonedx(doc)
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "exfil") == "HIGH"
    assert "no TLS" in html_text


def test_severity_new_tool_riskclass_exec_is_high():
    doc = _plain_doc()
    doc.add(Component(component_class="tool", name="danger-tool").set("riskClass", "exec"), "invokes")
    before, after = to_cyclonedx(_plain_doc()), to_cyclonedx(doc)
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "danger-tool") == "HIGH"


def test_severity_new_mcp_server_stdio_is_medium():
    doc = _plain_doc()
    doc.add(Component(component_class="mcp_server", name="local-fs").set("transport", "stdio"), "uses")
    before, after = to_cyclonedx(_plain_doc()), to_cyclonedx(doc)
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "local-fs") == "MEDIUM"


def test_severity_version_pinned_true_to_false_is_medium():
    before, after = _changed_pair(
        "mcp_server", "local-fs", lambda c: c.set("versionPinned", True), lambda c: c.set("versionPinned", False)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "local-fs") == "MEDIUM"
    assert "no longer version-pinned" in html_text


def test_severity_dependency_version_changed_is_medium():
    before, after = _changed_pair(
        "dependency", "openai", lambda c: setattr(c, "version", "3.0.0"), lambda c: setattr(c, "version", "4.0.0")
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "openai") == "MEDIUM"
    assert "3.0.0 -&gt; 4.0.0" in html_text or "3.0.0 -> 4.0.0" in html_text


def test_severity_path_outside_home_newly_true_is_medium():
    before, after = _changed_pair(
        "prompt_surface", "AGENTS.md", lambda c: c.set("pathOutsideHome", False), lambda c: c.set("pathOutsideHome", True)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "AGENTS.md") == "MEDIUM"


def test_severity_symlink_newly_true_is_medium():
    before, after = _changed_pair(
        "memory_store", "chroma.sqlite3", lambda c: c.set("symlink", False), lambda c: c.set("symlink", True)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "chroma.sqlite3") == "MEDIUM"


def test_severity_model_added_is_low():
    doc = _plain_doc()
    doc.add(Component(component_class="model", name="qwen3:8b"), "uses")
    before, after = to_cyclonedx(_plain_doc()), to_cyclonedx(doc)
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "qwen3:8b") == "LOW"


def test_severity_model_removed_is_low():
    doc = _plain_doc()
    doc.add(Component(component_class="model", name="qwen3:8b"), "uses")
    before, after = to_cyclonedx(doc), to_cyclonedx(_plain_doc())
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "qwen3:8b") == "LOW"
    assert "removed" in html_text


def test_severity_configuration_sha256_changed_is_low():
    before, after = _changed_pair(
        "configuration", "config.yaml", lambda c: c.set("sha256", "a" * 64), lambda c: c.set("sha256", "b" * 64)
    )
    html_text = render_diff_report(before, after)
    assert _severity_of(html_text, "config.yaml") == "LOW"


def test_findings_are_sorted_worst_first_regardless_of_append_order():
    # Deliberately construct the LOW-severity change first in code, the
    # HIGH-severity one second -- the rendered order must still be
    # HIGH before LOW, proving this is a real sort, not insertion order.
    before_doc, after_doc = _plain_doc(), _plain_doc()

    low_before = Component(component_class="configuration", name="config.yaml")
    low_before.set("sha256", "a" * 64)
    before_doc.add(low_before, "uses")
    low_after = Component(component_class="configuration", name="config.yaml")
    low_after.set("sha256", "b" * 64)
    after_doc.add(low_after, "uses")

    high_before = Component(component_class="hook", name="pre-commit.sh")
    high_before.set("contentChangedSinceApproval", False)
    before_doc.add(high_before, "loads")
    high_after = Component(component_class="hook", name="pre-commit.sh")
    high_after.set("contentChangedSinceApproval", True)
    after_doc.add(high_after, "loads")

    html_text = render_diff_report(to_cyclonedx(before_doc), to_cyclonedx(after_doc))
    changes_section = html_text.split('id="findings"')[1].split('id="security"')[0]
    assert changes_section.index("pre-commit.sh") < changes_section.index("config.yaml")


def test_unrecognized_changed_field_still_shown_not_hidden():
    before, after = _changed_pair(
        "dependency", "some-lib", lambda c: c.set("someNewFutureField", "old"), lambda c: c.set("someNewFutureField", "new")
    )
    html_text = render_diff_report(before, after)
    assert "some-lib" in html_text
    assert "someNewFutureField" in html_text


# ---- security findings buckets ---------------------------------------


def test_diff_report_shows_new_and_resolved_security_findings():
    before_doc, after_doc = _plain_doc(), _plain_doc()
    resolved_secret = Component(component_class="secrets_surface", name="old.env")
    resolved_secret.set("worldReadable", True)
    before_doc.add(resolved_secret, "accesses")

    new_secret = Component(component_class="secrets_surface", name="new.env")
    new_secret.set("worldReadable", True)
    after_doc.add(new_secret, "accesses")

    html_text = render_diff_report(to_cyclonedx(before_doc), to_cyclonedx(after_doc))
    security_section = html_text.split('id="security"')[1].split('id="raw"')[0]
    assert "New (1)" in security_section
    assert "new.env" in security_section
    assert "Resolved (1)" in security_section
    assert "old.env" in security_section


def test_diff_report_persisting_bucket_is_collapsed_by_default():
    doc = _plain_doc()
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    bom = to_cyclonedx(doc)

    html_text = render_diff_report(bom, bom)
    security_section = html_text.split('id="security"')[1].split('id="raw"')[0]
    assert "<details><summary>Persisting (1)</summary>" in security_section


# ---- v0.10.1: proving the "no CDN, no external resources" claim --------
#
# report.py's own module docstring has claimed "no CDN, no JavaScript
# framework, no external dependency" since v0.4.0 -- asserted in prose,
# never actually proven by a test until now. Registered in
# test_docstring_claims.py's own CLAIMS dict.


def test_report_has_no_external_resource_references():
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="requests", version="2.34.2")
    dep.set("purl", "pkg:pypi/requests@2.34.2")
    doc.add(dep, "uses")
    html_text = render_html(to_cyclonedx(doc))

    # Every <script>/<style> is inline (no `src`/no separate <link>) --
    # this is the actual thing "no CDN" means: nothing the browser would
    # fetch over the network just to render the page.
    assert not re.search(r"<script[^>]*\ssrc=", html_text)
    assert "<link" not in html_text
    assert not re.search(r"<img[^>]*\ssrc=[\"']https?://", html_text)
    # Sanity check the test actually exercised real inline script/style,
    # not an empty page that would trivially pass the checks above too.
    assert re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html_text)
    assert "<style>" in html_text
