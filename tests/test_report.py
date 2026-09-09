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
