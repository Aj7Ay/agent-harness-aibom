import json
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
