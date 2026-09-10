import json
import shutil
import subprocess
from pathlib import Path

import pytest

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


def test_scan_verify_deterministic_passes_on_an_unchanged_fixture(capsys):
    capsys.readouterr()
    exit_code = main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--verify-deterministic"])
    assert exit_code == 0
    assert "PASS [hermes]" in capsys.readouterr().out


def test_scan_verify_deterministic_fails_on_a_genuinely_flaky_collector(capsys):
    # A real collector never behaves this way -- this proves the check
    # actually catches a difference, not just that it always prints PASS.
    from harness_aibom.cli import _run_verify_deterministic
    from harness_aibom.model import Component

    class _FlakyCollector:
        runtime_kind = "hermes"
        _calls = 0

        def collect(self, doc):
            self._calls += 1
            doc.add(Component(component_class="skill", name=f"run-{self._calls}"), "loads")

    capsys.readouterr()
    exit_code = _run_verify_deterministic([_FlakyCollector()])
    assert exit_code == 1
    assert "FAIL [hermes]" in capsys.readouterr().err


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


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_report_bundle_and_key_renders_a_verified_artifact_integrity_section(tmp_path, monkeypatch):
    key_path, pub_path = _cosign_keypair(tmp_path, monkeypatch)
    bom_path = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(bom_path), "--deterministic"])

    bundle_path = tmp_path / "aibom.json.bundle"
    assert main(["sign", str(bom_path), "--key", str(key_path), "--bundle", str(bundle_path)]) == 0

    html_out = tmp_path / "report.html"
    exit_code = main([
        "report", str(bom_path), "--output", str(html_out),
        "--bundle", str(bundle_path), "--key", str(pub_path),
    ])
    assert exit_code == 0
    html_text = html_out.read_text()
    section = html_text.split('id="artifact-integrity"')[1].split('id="raw-bom"')[0]
    assert "Signature verified" in section
    assert "No signature bundle supplied" not in section


def test_report_bundle_without_key_is_a_clean_error(tmp_path, capsys):
    bom_path = tmp_path / "aibom.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(bom_path)])
    exit_code = main(["report", str(bom_path), "--bundle", "some.bundle", "--output", str(tmp_path / "x.html")])
    assert exit_code == 1
    assert "--bundle and --key must be given together" in capsys.readouterr().err


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


def test_policy_baseline_shows_accepted_marker_for_persisting_findings(tmp_path, capsys):
    """v0.8.3: a reviewer found that a pre-existing, still-present
    finding (every one of its matches already in the baseline, so
    --baseline correctly never fails on it) printed with the exact same
    "." marker as a rule that never fired at all -- indistinguishable,
    with zero visibility that it's an accepted, still-present risk. Same
    document as baseline == current above, but this time asserting the
    actual `~ [accepted]` marker text -- and that PASS/exit-code behavior
    is unchanged."""
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
    current.write_text(bom_text)  # identical -- persisting, not new

    exit_code = main(["policy", str(current), "--baseline", str(baseline)])
    out = capsys.readouterr().out
    assert exit_code == 0  # never changes baseline-mode PASS/FAIL
    assert "~ [high] world_readable_secret_high_confidence" in out
    assert "[accepted]" in out
    assert "accepted: secrets_surface:.env" in out
    assert "policy: passed" in out


def test_policy_no_baseline_never_shows_accepted_marker(tmp_path, capsys):
    """The `~ [accepted]` marker is a --baseline-only concept -- without
    one, there's no "already existed" to distinguish, so the same
    document must still print the plain `x`/`.` markers it always has."""
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    out_path = tmp_path / "current.json"
    out_path.write_text(json.dumps(to_cyclonedx(doc)))

    main(["policy", str(out_path)])
    out = capsys.readouterr().out
    assert "[accepted]" not in out
    assert "x [high] world_readable_secret_high_confidence" in out


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


# ---- v0.8.2: diff --security -------------------------------------------


def test_diff_security_reports_a_new_finding(tmp_path, capsys):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    baseline_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    old = Component(component_class="secrets_surface", name=".env")
    old.set("worldReadable", True)
    baseline_doc.add(old, "accesses")

    current_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    same = Component(component_class="secrets_surface", name=".env")
    same.set("worldReadable", True)
    current_doc.add(same, "accesses")
    new = Component(component_class="secrets_surface", name="newly-exposed.env")
    new.set("worldReadable", True)
    current_doc.add(new, "accesses")

    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps(to_cyclonedx(baseline_doc)))
    current.write_text(json.dumps(to_cyclonedx(current_doc)))

    capsys.readouterr()
    exit_code = main(["diff", str(baseline), str(current), "--security"])
    result = json.loads(capsys.readouterr().out)
    assert exit_code == 0  # no --exit-code passed
    new_refs = [ref for o in result["new"] for ref in o["components"]]
    assert any("newly-exposed.env" in ref for ref in new_refs)
    assert result["resolved"] == []


def test_diff_security_exit_code_gates_on_new_findings_only(tmp_path, capsys):
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

    capsys.readouterr()
    exit_code = main(["diff", str(baseline), str(current), "--security", "--exit-code"])
    assert exit_code == 0  # persisting, not new -- --exit-code must not fire


# ---- v0.8.2: sign / verify-signature (real cosign, skipped if absent) --


def _cosign_keypair(tmp_path, monkeypatch):
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    prefix = tmp_path / "cosign"
    subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
        capture_output=True, text=True, check=True,
    )
    return tmp_path / "cosign.key", tmp_path / "cosign.pub"


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_sign_then_verify_signature_round_trip(tmp_path, monkeypatch, capsys):
    key_path, pub_path = _cosign_keypair(tmp_path, monkeypatch)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')

    capsys.readouterr()
    sign_exit = main(["sign", str(doc), "--key", str(key_path)])
    assert sign_exit == 0
    bundle_path = doc.with_suffix(".json.bundle")
    assert bundle_path.is_file()

    capsys.readouterr()
    verify_exit = main(["verify-signature", str(doc), "--key", str(pub_path)])
    assert verify_exit == 0
    captured = capsys.readouterr()
    # cosign writes "Verified OK" to its own stderr, not stdout (confirmed
    # against the real binary) -- relayed verbatim either way, so check
    # both rather than assume a stream this project doesn't control.
    assert "Verified OK" in captured.out + captured.err


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_verify_signature_fails_on_tampered_file(tmp_path, monkeypatch):
    key_path, pub_path = _cosign_keypair(tmp_path, monkeypatch)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')
    assert main(["sign", str(doc), "--key", str(key_path)]) == 0

    doc.write_text('{"bomFormat": "CycloneDX", "tampered": true}')
    assert main(["verify-signature", str(doc), "--key", str(pub_path)]) != 0


def test_verify_signature_missing_bundle_is_a_clean_error(tmp_path, capsys):
    doc = tmp_path / "aibom.json"
    doc.write_text("{}")
    exit_code = main(["verify-signature", str(doc), "--key", "/no/such/key.pub"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


def test_sign_missing_input_file_is_a_clean_error(capsys):
    exit_code = main(["sign", "/no/such/aibom.json", "--key", "/no/such/key"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err


# ---- v0.8.3: sign's own default signing-config, and the CLI override ---


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_sign_uses_the_vendored_signing_config_by_default(tmp_path, monkeypatch):
    """`sign` with no `--signing-config` flag must still succeed with an
    isolated `$HOME` (no pre-existing TUF cache) -- this is the actual CLI
    entry point for the offline-signing fix verified directly against
    sign.py in test_sign.py; here it's confirmed to actually reach through
    `main()`, not just `sign_blob()` in isolation."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    key_path, pub_path = _cosign_keypair(tmp_path, monkeypatch)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')

    assert main(["sign", str(doc), "--key", str(key_path)]) == 0
    bundle_path = doc.with_suffix(".json.bundle")
    assert bundle_path.is_file()
    assert main(["verify-signature", str(doc), "--key", str(pub_path)]) == 0


@pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")
def test_sign_signing_config_flag_override_is_passed_through(tmp_path, monkeypatch, capsys):
    """A user-supplied `--signing-config` file must actually be handed to
    cosign, not silently ignored -- a nonexistent path is rejected by
    cosign itself, proving the CLI flag reaches `sign_blob()`."""
    key_path, _pub_path = _cosign_keypair(tmp_path, monkeypatch)
    doc = tmp_path / "aibom.json"
    doc.write_text('{"bomFormat": "CycloneDX"}')

    exit_code = main(["sign", str(doc), "--key", str(key_path), "--signing-config", "/no/such/signing-config.json"])
    assert exit_code != 0


# ---- v0.8.2: policy --format sarif --------------------------------------


def test_policy_format_sarif_writes_a_schema_shaped_document(tmp_path, capsys):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    bom_path = tmp_path / "aibom.json"
    bom_path.write_text(json.dumps(to_cyclonedx(doc)))

    out_path = tmp_path / "results.sarif"
    capsys.readouterr()
    exit_code = main(["policy", str(bom_path), "--format", "sarif", "--output", str(out_path)])
    assert exit_code == 1  # a high-severity finding exists, at or above the default --fail-on medium
    assert f"wrote {out_path}" in capsys.readouterr().out

    sarif_doc = json.loads(out_path.read_text())
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) == 1


def test_policy_format_sarif_to_stdout_when_no_output_given(tmp_path, capsys):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import HarnessDocument

    bom_path = tmp_path / "aibom.json"
    bom_path.write_text(json.dumps(to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t"))))

    capsys.readouterr()
    exit_code = main(["policy", str(bom_path), "--format", "sarif"])
    assert exit_code == 0  # no findings at all
    out = capsys.readouterr().out
    assert '"version": "2.1.0"' in out


# ---- v0.8.2: policy --policy-file (policy-as-code) ----------------------


def _bom_with_dependency(tmp_path):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="some-package", version="1.0.0")
    doc.add(dep, "uses")
    bom_path = tmp_path / "aibom.json"
    bom_path.write_text(json.dumps(to_cyclonedx(doc)))
    return bom_path


def test_policy_file_fail_action_fails_the_command(tmp_path, capsys):
    bom_path = _bom_with_dependency(tmp_path)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "rules:\n  - id: NO-DEPS\n    severity: high\n    action: fail\n    "
        "condition:\n      componentClass: dependency\n"
    )
    capsys.readouterr()
    exit_code = main(["policy", str(bom_path), "--policy-file", str(policy_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "NO-DEPS" in captured.out
    assert "policy-file rule(s) with action: fail" in captured.err


def test_policy_file_warn_action_does_not_fail_the_command(tmp_path, capsys):
    bom_path = _bom_with_dependency(tmp_path)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "rules:\n  - id: DEPS-NOTICE\n    severity: low\n    action: warn\n    "
        "condition:\n      componentClass: dependency\n"
    )
    capsys.readouterr()
    exit_code = main(["policy", str(bom_path), "--policy-file", str(policy_file)])
    captured = capsys.readouterr()
    assert exit_code == 0  # no built-in findings either, on this minimal document
    assert "DEPS-NOTICE" in captured.out


def test_policy_file_malformed_yaml_is_a_clean_error(tmp_path, capsys):
    bom_path = _bom_with_dependency(tmp_path)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("not: a policy file\n")
    exit_code = main(["policy", str(bom_path), "--policy-file", str(policy_file)])
    assert exit_code == 1
    assert "expected a top-level 'rules:' list" in capsys.readouterr().err


def test_policy_file_missing_file_is_a_clean_error(tmp_path, capsys):
    bom_path = _bom_with_dependency(tmp_path)
    capsys.readouterr()
    exit_code = main(["policy", str(bom_path), "--policy-file", "/no/such/policy.yaml"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err.lower()


def test_policy_file_together_with_sarif_format_is_a_clean_error(tmp_path, capsys):
    bom_path = _bom_with_dependency(tmp_path)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("rules: []\n")
    exit_code = main(["policy", str(bom_path), "--policy-file", str(policy_file), "--format", "sarif"])
    assert exit_code == 1
    assert "not supported together with --format sarif" in capsys.readouterr().err


# ---- scan-vulns (OSV.dev enrichment, opt-in, network-requiring) ---------


def _bom_with_purl_dependency(tmp_path):
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="pyyaml", version="5.3")
    dep.set("purl", "pkg:pypi/pyyaml@5.3")
    doc.add(dep, "uses")
    bom_path = tmp_path / "aibom.json"
    bom_path.write_text(json.dumps(to_cyclonedx(doc)))
    return bom_path


def test_scan_vulns_never_makes_a_real_network_call_in_this_suite(tmp_path, capsys, monkeypatch):
    # Confirms the CLI wiring end-to-end (arg parsing, vex.py call,
    # output file) using an injected fake `query` -- never the real
    # OSV.dev network function, same discipline as test_vex.py.
    from harness_aibom import vex

    monkeypatch.setattr(vex, "default_query", lambda purl: [
        {
            "id": "GHSA-6757-jp84-gxfx",
            "summary": "Improper Input Validation in PyYAML",
            "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-20"]},
            "references": [],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
    ])

    bom_path = _bom_with_purl_dependency(tmp_path)
    out_path = tmp_path / "aibom-with-vulns.json"
    exit_code = main(["scan-vulns", str(bom_path), "-o", str(out_path)])
    assert exit_code == 0

    stderr = capsys.readouterr().err
    assert "checked 1/1 purl(s)" in stderr
    assert "1 with known vulnerabilities" in stderr

    data = json.loads(out_path.read_text())
    assert data["vulnerabilities"][0]["id"] == "GHSA-6757-jp84-gxfx"


def test_scan_vulns_fails_the_command_when_every_check_failed(tmp_path, capsys, monkeypatch):
    # v0.9.1: a reviewer found a wholesale OSV outage (every query
    # failing, e.g. behind a blocking proxy) previously still exited 0
    # and wrote a document indistinguishable from "no known
    # vulnerabilities" -- fixed so a CI job can actually catch this
    # instead of a silently "clean" result.
    from harness_aibom import vex

    def _boom(purl):
        raise TimeoutError("simulated OSV outage")

    monkeypatch.setattr(vex, "default_query", _boom)
    bom_path = _bom_with_purl_dependency(tmp_path)
    exit_code = main(["scan-vulns", str(bom_path)])
    assert exit_code == 1  # every check failed -- this must now fail the command
    stderr = capsys.readouterr().err
    assert "1 check(s) failed" in stderr
    assert "simulated OSV outage" in stderr


def test_scan_vulns_a_partial_failure_still_succeeds(tmp_path, capsys, monkeypatch):
    # A failed check is still never fatal on its own -- only a TOTAL
    # failure is (see the test above). Same "missing pieces are never
    # fatal" discipline `scan` itself already follows.
    from harness_aibom import vex
    from harness_aibom.cyclonedx import to_cyclonedx
    from harness_aibom.model import Component, HarnessDocument

    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    ok_dep = Component(component_class="dependency", name="requests", version="2.34.2")
    ok_dep.set("purl", "pkg:pypi/requests@2.34.2")
    doc.add(ok_dep, "uses")
    bad_dep = Component(component_class="dependency", name="pyyaml", version="5.3")
    bad_dep.set("purl", "pkg:pypi/pyyaml@5.3")
    doc.add(bad_dep, "uses")
    bom_path = tmp_path / "aibom.json"
    bom_path.write_text(json.dumps(to_cyclonedx(doc)))

    def _selective_boom(purl):
        if "pyyaml" in purl:
            raise TimeoutError("simulated OSV outage")
        return []

    monkeypatch.setattr(vex, "default_query", _selective_boom)
    exit_code = main(["scan-vulns", str(bom_path)])
    assert exit_code == 0  # one of two checks failed -- still not total


def test_scan_vulns_missing_file_is_a_clean_error(capsys):
    exit_code = main(["scan-vulns", "/no/such/aibom.json"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err.lower()


def test_scan_vulns_rejects_non_dict_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]")
    exit_code = main(["scan-vulns", str(bad)])
    assert exit_code == 1
    assert "not a json object" in capsys.readouterr().err.lower()


# ---- compliance (evidence mapping, never a certification claim) ---------


def test_compliance_text_output_names_real_control_ids(tmp_path, capsys):
    bom_path = _bom_with_purl_dependency(tmp_path)
    exit_code = main(["compliance", str(bom_path), "--framework", "nist-ai-rmf"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "NOT a compliance or certification claim" in out
    assert "GOVERN 1.6" in out
    assert "MAP 4.1" in out


def test_compliance_json_output_is_well_formed(tmp_path, capsys):
    bom_path = _bom_with_purl_dependency(tmp_path)
    exit_code = main(["compliance", str(bom_path), "--framework", "mitre-atlas", "--format", "json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["framework"] == "mitre-atlas"
    assert {m["controlId"] for m in data["mappings"]} == {"AML.T0010", "AML.T0055", "AML.T0007"}


def test_compliance_unknown_framework_is_a_clean_argparse_error(tmp_path, capsys):
    bom_path = _bom_with_purl_dependency(tmp_path)
    with pytest.raises(SystemExit):
        main(["compliance", str(bom_path), "--framework", "iso-42001"])


def test_compliance_missing_file_is_a_clean_error(capsys):
    exit_code = main(["compliance", "/no/such/aibom.json", "--framework", "owasp-llm-top10-2025"])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err.lower()


# ---- v0.10.0: report --diff ---------------------------------------------


def test_report_diff_end_to_end(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(before)])
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(after)])

    out = tmp_path / "change.html"
    exit_code = main(["report", "--diff", str(before), str(after), "-o", str(out)])
    assert exit_code == 0
    html_text = out.read_text()
    assert html_text.startswith("<!doctype html>")
    assert "Change report" in html_text


def test_report_diff_default_output_path(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(before)])
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(after)])

    exit_code = main(["report", "--diff", str(before), str(after)])
    assert exit_code == 0
    assert (tmp_path / "after.diff.html").is_file()


def test_report_diff_missing_file_is_a_clean_error(tmp_path, capsys):
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(after)])
    exit_code = main(["report", "--diff", "/no/such/before.json", str(after)])
    assert exit_code == 1
    assert "no such file" in capsys.readouterr().err.lower()


def test_report_diff_rejects_a_non_dict_json_side(tmp_path, capsys):
    before = tmp_path / "before.json"
    before.write_text("[1, 2, 3]")
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(after)])

    exit_code = main(["report", "--diff", str(before), str(after)])
    assert exit_code == 1
    assert "not a CycloneDX document" in capsys.readouterr().err


def test_report_diff_one_file_is_an_argparse_error():
    # --diff has nargs=2 -- argparse itself rejects a single value,
    # before this project's own code ever runs.
    with pytest.raises(SystemExit):
        main(["report", "--diff", "/tmp/only-one.json"])


def test_report_two_positional_files_without_diff_is_an_argparse_error():
    # `file` only ever accepts one positional -- a second one is an
    # argparse-level "unrecognized arguments" error, not this project's.
    with pytest.raises(SystemExit):
        main(["report", "/tmp/a.json", "/tmp/b.json"])


def test_report_diff_combined_with_file_is_a_clean_error(tmp_path, capsys):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(before)])
    main(["scan", "--runtime", "hermes", "--home", str(HERMES_HOME), "--output", str(after)])

    exit_code = main(["report", str(before), "--diff", str(before), str(after)])
    assert exit_code == 1
    assert "cannot be combined" in capsys.readouterr().err


def test_report_no_file_and_no_diff_is_a_clean_error(capsys):
    exit_code = main(["report"])
    assert exit_code == 1
    assert "a file is required" in capsys.readouterr().err
