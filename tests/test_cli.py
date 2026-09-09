import json
import shutil
from pathlib import Path

from harness_aibom.cli import main

HERMES_HOME = Path(__file__).parent / "fixtures" / "hermes_home"
OPENCLAW_HOME = Path(__file__).parent / "fixtures" / "openclaw_home"


def test_scan_writes_valid_document(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    # No `hermes`/`ollama` on PATH in CI, so runtime/model discovery will
    # warn and skip -- this test only checks the CLI plumbing and the
    # config/mcp components that don't need subprocess/network calls.
    exit_code = main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    assert exit_code == 0

    data = json.loads(out.read_text())
    assert data["bomFormat"] == "CycloneDX"

    def classes_in(entries):
        return {
            p["value"]
            for c in entries
            for p in c["properties"]
            if p["name"] == "harness-aibom:componentClass"
        }

    component_classes = classes_in(data["components"])
    assert "configuration" in component_classes
    assert "skill" in component_classes

    # model_endpoint and mcp_server are CycloneDX *services*, not
    # components -- "service" isn't a valid component `type`.
    service_classes = classes_in(data["services"])
    assert "mcp_server" in service_classes
    assert "model_endpoint" in service_classes


def test_validate_accepts_its_own_scan_output(tmp_path):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "openclaw", "--home", str(OPENCLAW_HOME), "--output", str(out)])
    assert main(["validate", str(out)]) == 0


def test_diff_of_a_document_against_itself_is_empty(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    capsys.readouterr()
    main(["diff", str(out), str(out)])
    result = json.loads(capsys.readouterr().out)
    assert result == {"added": [], "removed": [], "changed": []}


def test_scan_resolves_relative_and_absolute_home_to_the_same_path(tmp_path, capsys):
    # A relative and an absolute --home naming the same directory must
    # produce identical `path` properties, or `diff` reports false
    # changes on every path-bearing component just from how --home was
    # spelled.
    import os

    old_cwd = Path.cwd()
    try:
        os.chdir(HERMES_HOME.parent)
        relative_out = tmp_path / "relative.json"
        main(["scan", "--runtime", "hermes", "--home", "hermes_home", "--output", str(relative_out)])
    finally:
        os.chdir(old_cwd)

    absolute_out = tmp_path / "absolute.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(absolute_out)])

    capsys.readouterr()
    main(["diff", str(relative_out), str(absolute_out)])
    result = json.loads(capsys.readouterr().out)
    assert result == {"added": [], "removed": [], "changed": []}


def test_validate_reports_a_clean_error_for_a_missing_file(capsys):
    exit_code = main(["validate", "/no/such/file.json"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_validate_reports_a_clean_error_for_invalid_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    exit_code = main(["validate", str(bad)])
    assert exit_code == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_diff_missing_file_is_a_clean_error_not_a_traceback(capsys):
    exit_code = main(["diff", "/no/such/before.json", "/no/such/after.json"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_diff_exit_code_flag(tmp_path, capsys):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(before)])
    main(["scan", "--runtime", "openclaw", "--home", str(OPENCLAW_HOME), "--output", str(after)])
    capsys.readouterr()

    # Without --exit-code: always 0, even though these two clearly differ.
    assert main(["diff", str(before), str(after)]) == 0
    capsys.readouterr()

    # With --exit-code: 1 for a real difference.
    assert main(["diff", "--exit-code", str(before), str(after)]) == 1
    capsys.readouterr()

    # With --exit-code, but no actual difference: still 0.
    assert main(["diff", "--exit-code", str(before), str(before)]) == 0


def test_no_pretty_produces_single_line_json(tmp_path):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out), "--no-pretty"])
    text = out.read_text()
    assert text.count("\n") == 1  # just the trailing newline main() adds
    assert json.loads(text)["bomFormat"] == "CycloneDX"


def test_openclaw_env_dir_flag_is_honored(tmp_path, capsys):
    env_dir = tmp_path / "custom-env-dir"
    env_dir.mkdir()
    (env_dir / ".env").write_text("OPENCLAW_GATEWAY_TOKEN=placeholder\n")

    out = tmp_path / "aibom.json"
    main(
        [
            "scan",
            "--runtime",
            "openclaw",
            "--home",
            str(OPENCLAW_HOME),
            "--openclaw-env-dir",
            str(env_dir),
            "--output",
            str(out),
        ]
    )
    data = json.loads(out.read_text())
    secret_paths = {
        p["value"]
        for c in data["components"]
        for p in c["properties"]
        if p["name"] == "harness-aibom:path"
    }
    assert str(env_dir / ".env") in secret_paths


def test_diff_across_two_different_home_roots_with_identical_content(tmp_path, capsys):
    # End-to-end regression test for the cross-host case an independent
    # reviewer found: scan the exact same tree under two different --home
    # roots (standing in for two different machines/usernames -- a golden
    # baseline vs. a lab VM, or one student's box vs. another's), and
    # confirm identical content produces an empty diff. Before relPath,
    # this reported everything as both added and removed, since every
    # `path` property was absolute and the two roots share no path
    # prefix.
    home_a = tmp_path / "students" / "alice" / "home"
    home_b = tmp_path / "students" / "bob" / "home"
    shutil.copytree(HERMES_HOME, home_a)
    shutil.copytree(HERMES_HOME, home_b)

    scan_a = tmp_path / "a.json"
    scan_b = tmp_path / "b.json"
    main(["scan", "--runtime", "hermes", "--home", str(home_a), "--output", str(scan_a)])
    main(["scan", "--runtime", "hermes", "--home", str(home_b), "--output", str(scan_b)])

    capsys.readouterr()
    exit_code = main(["diff", "--exit-code", str(scan_a), str(scan_b)])
    result = json.loads(capsys.readouterr().out)

    assert result == {"added": [], "removed": [], "changed": []}
    assert exit_code == 0


def test_deterministic_scan_is_byte_identical_across_runs(tmp_path):
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out_a), "--deterministic"])
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out_b), "--deterministic"])
    assert out_a.read_text() == out_b.read_text()

    data = json.loads(out_a.read_text())
    assert "serialNumber" not in data
    assert "timestamp" not in data["metadata"]


def test_report_command_writes_html_next_to_the_json_by_default(tmp_path):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    exit_code = main(["report", str(out)])
    assert exit_code == 0
    expected_html = out.with_suffix(".html")
    assert expected_html.is_file()
    assert expected_html.read_text().startswith("<!doctype html>")


def test_report_command_honors_explicit_output_path(tmp_path):
    out = tmp_path / "aibom.json"
    custom = tmp_path / "custom-report.html"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    exit_code = main(["report", str(out), "--output", str(custom)])
    assert exit_code == 0
    assert custom.is_file()


def test_report_command_reports_a_clean_error_for_a_missing_file(capsys):
    exit_code = main(["report", "/no/such/file.json"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_report_writes_utf8_regardless_of_process_locale(tmp_path):
    # Confirmed real: without an explicit encoding, write_text() uses the
    # platform locale's preferred encoding -- a C/POSIX locale (normal in
    # Docker/CI) raised UnicodeEncodeError on the em dash in <title> and
    # left a truncated file behind.
    out = tmp_path / "aibom.json"
    html_out = tmp_path / "report.html"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    exit_code = main(["report", str(out), "--output", str(html_out)])
    assert exit_code == 0
    assert html_out.read_bytes().decode("utf-8").startswith("<!doctype html>")


def test_report_refuses_to_overwrite_its_own_input(tmp_path, capsys):
    # Confirmed real: report x.html with no --output silently destroyed
    # x.html, since with_suffix(".html") on an .html input is itself.
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    html_out = tmp_path / "aibom.html"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(html_out)])
    original = html_out.read_text()

    exit_code = main(["report", str(html_out)])  # default output == html_out itself
    assert exit_code == 1
    assert "refusing to overwrite" in capsys.readouterr().err
    assert html_out.read_text() == original  # untouched


def test_report_rejects_non_dict_json(tmp_path, capsys):
    bad = tmp_path / "not-a-document.json"
    bad.write_text("[]")
    exit_code = main(["report", str(bad), "--output", str(tmp_path / "out.html")])
    assert exit_code == 1
    assert "not a CycloneDX document" in capsys.readouterr().err


def test_report_reports_a_clean_error_for_an_unwritable_output_path(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])

    ro_dir = tmp_path / "ro"
    ro_dir.mkdir(mode=0o555)
    try:
        exit_code = main(["report", str(out), "--output", str(ro_dir / "x.html")])
        assert exit_code == 1
        assert "Permission denied" in capsys.readouterr().err
    finally:
        ro_dir.chmod(0o755)  # so tmp_path cleanup can remove it


def test_deterministic_report_is_byte_identical_across_renders(tmp_path):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out), "--deterministic"])

    html_a = tmp_path / "a.html"
    html_b = tmp_path / "b.html"
    main(["report", str(out), "--output", str(html_a)])
    main(["report", str(out), "--output", str(html_b)])

    assert html_a.read_text() == html_b.read_text()
    assert "no render timestamp" in html_a.read_text()


# ---- v0.7.0: report --baseline / policy ------------------------------------


def test_report_baseline_renders_the_diff_section(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(before), "--deterministic"])
    main(["scan", "--runtime", "openclaw", "--home", str(OPENCLAW_HOME), "--output", str(after), "--deterministic"])

    html_out = tmp_path / "diff.html"
    exit_code = main(["report", str(after), "--baseline", str(before), "--output", str(html_out)])
    assert exit_code == 0

    html_text = html_out.read_text()
    assert "No baseline supplied" not in html_text
    assert "not available for a single scan" not in html_text


def test_report_baseline_missing_file_is_a_clean_error(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])

    exit_code = main(["report", str(out), "--baseline", "/no/such/before.json", "--output", str(tmp_path / "x.html")])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_policy_passes_when_nothing_qualifies(tmp_path, capsys):
    # A minimal, purpose-built clean document -- not the real hermes_home
    # fixture, which (correctly) has real findings of its own as of
    # v0.6.0 (a world-readable memory store, a plaintext/unauthenticated
    # MCP server), so scanning it isn't a "nothing qualifies" case.
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    out = tmp_path / "aibom.json"
    out.write_text(json.dumps(to_cyclonedx(doc)))

    exit_code = main(["policy", str(out)])
    assert exit_code == 0
    assert "policy: passed" in capsys.readouterr().out


def test_policy_fails_on_a_qualifying_finding(tmp_path, capsys):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    out = tmp_path / "aibom.json"
    out.write_text(json.dumps(to_cyclonedx(doc)))

    exit_code = main(["policy", str(out)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "policy: FAILED" in captured.err
    assert "world_readable_secret_high_confidence" in captured.out


def test_policy_fail_on_threshold_is_honored(tmp_path):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    doc.add(Component(component_class="model", name="mystery-model"), "uses")  # low
    out = tmp_path / "aibom.json"
    out.write_text(json.dumps(to_cyclonedx(doc)))

    assert main(["policy", str(out)]) == 0  # default --fail-on medium: a LOW finding doesn't fail
    assert main(["policy", str(out), "--fail-on", "low"]) == 1


def test_policy_baseline_only_fails_on_genuinely_new_findings(tmp_path, capsys):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    baseline_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    old_secret = Component(component_class="secrets_surface", name=".env")
    old_secret.set("worldReadable", True)
    baseline_doc.add(old_secret, "accesses")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(to_cyclonedx(baseline_doc)))

    # Same pre-existing finding, plus one genuinely new one.
    current_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    same_secret = Component(component_class="secrets_surface", name=".env")
    same_secret.set("worldReadable", True)
    current_doc.add(same_secret, "accesses")
    new_secret = Component(component_class="secrets_surface", name="newly-exposed.env")
    new_secret.set("worldReadable", True)
    current_doc.add(new_secret, "accesses")
    current = tmp_path / "current.json"
    current.write_text(json.dumps(to_cyclonedx(current_doc)))

    # Without --baseline: fails on both (both currently exist).
    assert main(["policy", str(current)]) == 1

    # With --baseline: only the genuinely new finding counts.
    exit_code = main(["policy", str(current), "--baseline", str(baseline)])
    assert exit_code == 1
    assert "newly-exposed.env" in capsys.readouterr().out


def test_policy_baseline_passes_when_nothing_new_since_baseline(tmp_path):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    bom_text = json.dumps(to_cyclonedx(doc))

    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(bom_text)
    current.write_text(bom_text)  # identical -- nothing new

    assert main(["policy", str(current), "--baseline", str(baseline)]) == 0


def test_policy_rejects_non_dict_json(tmp_path, capsys):
    bad = tmp_path / "not-a-document.json"
    bad.write_text("[]")
    exit_code = main(["policy", str(bad)])
    assert exit_code == 1
    assert "not a CycloneDX document" in capsys.readouterr().err


# ---- v0.8.0: validate's own referential-integrity / orphan checks -----


def test_validate_flags_referential_integrity_errors(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    bom = json.loads(out.read_text())
    bom["dependencies"].append({"ref": "no-such-ref", "dependsOn": []})
    out.write_text(json.dumps(bom))

    capsys.readouterr()
    exit_code = main(["validate", str(out)])
    assert exit_code == 1
    assert "no-such-ref" in capsys.readouterr().err


def test_validate_reports_orphans_as_warnings_not_failures(tmp_path, capsys):
    out = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(out)])
    bom = json.loads(out.read_text())
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "skill:orphaned",
            "name": "orphaned",
            "properties": [{"name": "harness-aibom:componentClass", "value": "skill"}],
        }
    )
    out.write_text(json.dumps(bom))

    capsys.readouterr()
    exit_code = main(["validate", str(out)])
    captured = capsys.readouterr()
    # An orphan is still a valid document -- `validate` succeeds (exit 0),
    # but says so, on stderr, as a warning rather than staying silent.
    assert exit_code == 0
    assert "skill:orphaned" in captured.err
    assert "orphan" in captured.err
    assert "valid (1 orphan warning)" in captured.out
