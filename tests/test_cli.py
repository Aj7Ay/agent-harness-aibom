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
    classes = {
        p["value"]
        for c in data["components"]
        for p in c["properties"]
        if p["name"] == "harness-aibom:componentClass"
    }
    assert "configuration" in classes
    assert "skill" in classes
    assert "mcp_server" in classes


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
