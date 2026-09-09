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
