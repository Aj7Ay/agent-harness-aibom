"""Proves the promise made throughout this codebase's own docstrings and
SPEC.md: secret *values* never reach the output, only their presence,
path, and permissions. Plants one unique, unmistakable string everywhere
a secret could plausibly leak from, then greps the fully serialized
CycloneDX JSON for it.

This is a promise, not an assumption -- an independent reviewer pointed
out that the stdio MCP `env` handling added in v0.1.6 (collectors/mcp.py)
is exactly the kind of new code path that could accidentally start
reading a value instead of just a name, so it matters more to actually
test this than to keep asserting it in comments.
"""

import json
from pathlib import Path

from harness_aibom.collectors.hermes import HermesCollector
from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import HarnessDocument

PLANTED_SECRET = "sk-PLANTED-SECRET-VALUE-4f8a9c21"


def _build_home_with_planted_secrets(root: Path) -> Path:
    home = root / "home"
    hermes_dir = home / ".hermes"
    hermes_dir.mkdir(parents=True)

    (hermes_dir / "config.yaml").write_text(
        f"""\
model:
  default: qwen3:8b
  provider: custom
  base_url: http://127.0.0.1:11434/v1

mcp_servers:
  - name: local-fs
    command: npx
    args: [-y, "@modelcontextprotocol/server-filesystem", /]
    env:
      API_KEY: {PLANTED_SECRET}
  - name: corp-docs
    url: https://mcp.corp.lab
    auth:
      token: {PLANTED_SECRET}
"""
    )
    # A .env the secrets scan should record the *presence* of, never read.
    (hermes_dir / ".env").write_text(f"SECRET_KEY={PLANTED_SECRET}\n")

    skill_dir = hermes_dir / "skills" / "leaky-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(f"# Leaky Skill\n\nDo not leak {PLANTED_SECRET}.\n")
    (skill_dir / ".env").write_text(f"EXFIL_TOKEN={PLANTED_SECRET}\n")

    hooks_dir = hermes_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "audit.sh").write_text(f"#!/bin/sh\n# {PLANTED_SECRET}\necho hi\n")

    # v0.10.1: the two v0.6.0 collectors this test didn't originally cover
    # -- memory_store never reads file contents at all (metadata only),
    # and prompt_surface only ever fingerprints (sha256), never stores
    # the file's own text -- both real, separate promises worth planting
    # a canary against directly, not just asserting in a comment.
    (hermes_dir / "chroma.sqlite3").write_bytes(f"SQLite format 3\x00{PLANTED_SECRET}".encode())
    (hermes_dir / "AGENTS.md").write_text(f"Internal note: {PLANTED_SECRET}\n")

    return home


def test_no_planted_secret_value_reaches_the_serialized_output(tmp_path):
    home = _build_home_with_planted_secrets(tmp_path)

    def fake_run(argv):
        if argv == ["hermes", "--version"]:
            raise FileNotFoundError()
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ allowlisted (approved 2026-08-03) audit.sh\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=home, run=fake_run, fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    bom = to_cyclonedx(doc)
    serialized = json.dumps(bom)

    assert PLANTED_SECRET not in serialized, "a secret value leaked into the AIBOM output"

    # Sanity check the test actually exercised the paths it claims to:
    # if none of these components were found at all, the assertion above
    # would pass for the wrong reason (nothing to leak), not because
    # redaction worked.
    classes = {
        p["value"]
        for c in bom["components"] + bom.get("services", [])
        for p in c["properties"]
        if p["name"] == "harness-aibom:componentClass"
    }
    assert "secrets_surface" in classes
    assert "mcp_server" in classes
    assert "skill" in classes
    assert "hook" in classes
    assert "memory_store" in classes
    assert "prompt_surface" in classes


# ---- v0.10.1: the same promise, across every downstream command's own
# output -- not just the raw scan. `to_cyclonedx()` never seeing the
# secret is necessary but not sufficient: report.py/sarif.py/compliance.py
# each re-derive their own text from the same document, and each is a
# real, separate place a future change could accidentally start reading
# a value verbatim (a docstring or an f-string touching the wrong field).


def test_no_planted_secret_reaches_any_downstream_command_output(tmp_path, capsys):
    from harness_aibom.cli import main
    from harness_aibom.compliance import FRAMEWORKS

    home = _build_home_with_planted_secrets(tmp_path)
    bom_path = tmp_path / "aibom.json"

    # A real `scan` (not the injected-collector path the test above
    # uses) -- `hermes`/`ollama` aren't installed in CI either, so this
    # degrades exactly the way a real lab box without them would: a
    # warning, not a crash, and everything else (config, MCP servers,
    # skills, hooks, secrets, memory store, prompt surface) still
    # collected for real.
    capsys.readouterr()
    assert main(["scan", "--runtime", "hermes", "--home", str(home), "-o", str(bom_path)]) == 0
    scan_stderr = capsys.readouterr().err

    capsys.readouterr()
    assert main(["validate", str(bom_path)]) == 0
    validate_out = capsys.readouterr().out

    report_path = tmp_path / "report.html"
    assert main(["report", str(bom_path), "-o", str(report_path)]) == 0
    report_html = report_path.read_text()

    diff_report_path = tmp_path / "diff.html"
    # Against itself -- this test is about what the *rendering* of one
    # document can leak, not about constructing a second scan; an empty
    # diff still exercises every renderer in render_diff_report().
    assert main(["report", "--diff", str(bom_path), str(bom_path), "-o", str(diff_report_path)]) == 0
    diff_html = diff_report_path.read_text()

    sarif_path = tmp_path / "results.sarif"
    assert main(["policy", str(bom_path), "--format", "sarif", "-o", str(sarif_path), "--fail-on", "low"]) in (0, 1)
    sarif_json = sarif_path.read_text()

    capsys.readouterr()
    for framework in FRAMEWORKS:
        assert main(["compliance", str(bom_path), "--framework", framework, "--format", "json"]) == 0
    compliance_out = capsys.readouterr().out

    outputs = {
        "scan stderr (warnings)": scan_stderr,
        "validate stdout": validate_out,
        "report html": report_html,
        "report --diff html": diff_html,
        "policy --format sarif": sarif_json,
        "compliance --format json (all frameworks)": compliance_out,
    }
    secret_lower = PLANTED_SECRET.lower()
    for label, text in outputs.items():
        assert secret_lower not in text.lower(), f"planted secret leaked into {label}"
