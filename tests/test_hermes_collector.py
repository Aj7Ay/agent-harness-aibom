import textwrap
from pathlib import Path

from harness_aibom.collectors.hermes import HermesCollector
from harness_aibom.model import HarnessDocument

FIXTURE_HOME = Path(__file__).parent / "fixtures" / "hermes_home"

VERSION_OUTPUT = textwrap.dedent("""\
    Hermes Agent v0.19.0 (2026.7.20) · upstream 6bd02ae1
    Install directory: /usr/local/lib/hermes-agent
    Install method: git
    Python: 3.11.15
    OpenAI SDK: 2.24.0
""")

HOOKS_OUTPUT = textwrap.dedent("""\
    ✓ allowlisted (approved 2026-08-03) numbat-pre-tool.sh
    ✓ script unchanged since approval
    ✗ not allowlisted stray-hook.sh
    All shell hooks look healthy.
""")

TAGS_RESPONSE = {
    "models": [
        {
            "name": "qwen3:8b",
            "digest": "500a1f067a9f",
            "size": 5200000000,
            "modified_at": "2026-08-03T12:00:00Z",
            "details": {"family": "qwen3", "parameter_size": "8B", "quantization_level": "Q4_K_M"},
        }
    ]
}


def fake_run(argv):
    if argv == ["hermes", "--version"]:
        return VERSION_OUTPUT
    if argv == ["hermes", "hooks", "doctor"]:
        return HOOKS_OUTPUT
    raise AssertionError(f"unexpected command {argv}")


def fake_fetch(url):
    assert url.endswith("/api/tags")
    return TAGS_RESPONSE


def collect() -> HarnessDocument:
    collector = HermesCollector(home=FIXTURE_HOME, run=fake_run, fetch=fake_fetch)
    assert collector.is_present()
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)
    return doc


def by_class(doc, cls):
    return [c for c in doc.components if c.component_class == cls]


def test_runtime_component():
    doc = collect()
    [runtime] = by_class(doc, "runtime")
    assert runtime.version == "0.19.0"
    assert runtime.properties["installDir"] == "/usr/local/lib/hermes-agent"
    assert runtime.properties["installMethod"] == "git"
    assert runtime.properties["pythonVersion"] == "3.11.15"
    assert runtime.properties["upstreamHash"] == "6bd02ae1"


def test_model_endpoint_and_model():
    doc = collect()
    [endpoint] = by_class(doc, "model_endpoint")
    assert endpoint.properties["provider"] == "custom"
    assert endpoint.properties["apiMode"] == "chat_completions"

    [model] = by_class(doc, "model")
    assert model.name == "qwen3:8b"
    assert model.properties["digest"] == "500a1f067a9f"
    assert model.properties["contextLength"] == "65536"
    assert model.properties["thinking"] == "True"


def test_configuration_component_has_hash():
    doc = collect()
    [config] = by_class(doc, "configuration")
    assert config.name == "config.yaml"
    assert len(config.properties["sha256"]) == 64


def test_skill_component_flat():
    doc = collect()
    skills = by_class(doc, "skill")
    flat = next(s for s in skills if s.name == "incident-response")
    assert len(flat.properties["sha256"]) == 64
    assert flat.properties["description"] == "Incident Response"
    assert "category" not in flat.properties


def test_skill_component_nested_under_a_category():
    doc = collect()
    skills = by_class(doc, "skill")
    nested = next(s for s in skills if s.name == "software-development/dogfood")
    assert nested.properties["category"] == "software-development"
    assert len(nested.properties["sha256"]) == 64


def test_mcp_servers_from_config():
    doc = collect()
    servers = by_class(doc, "mcp_server")
    names = {s.name for s in servers}
    assert names == {"local-time", "corp-docs", "local-fs"}

    corp = next(s for s in servers if s.name == "corp-docs")
    assert corp.properties["tls"] == "True"
    assert corp.properties["authConfigured"] == "True"
    assert corp.properties["toolCount"] == "2"

    local = next(s for s in servers if s.name == "local-time")
    assert local.properties["tls"] == "False"

    stdio = next(s for s in servers if s.name == "local-fs")
    assert stdio.properties["transport"] == "stdio"
    assert stdio.properties["tls"] == "n/a"
    assert stdio.properties["authConfigured"] == "True"
    assert stdio.properties["command"] == "npx"
    assert local.properties["authConfigured"] == "False"


def test_hooks():
    doc = collect()
    hooks = by_class(doc, "hook")
    assert len(hooks) == 2

    allowed = next(h for h in hooks if h.name == "numbat-pre-tool.sh")
    assert allowed.properties["approvalStatus"] == "allowlisted"
    assert allowed.properties["approvedAt"] == "2026-08-03"

    denied = next(h for h in hooks if h.name == "stray-hook.sh")
    assert denied.properties["approvalStatus"] == "not_allowlisted"

    assert any("best-effort" in w for w in doc.warnings)


def test_hook_status_line_records_content_changed_since_approval():
    # "✓ script unchanged since approval" (confirmed real text from course
    # material) follows the numbat-pre-tool.sh line in HOOKS_OUTPUT and
    # describes *that* hook -- the highest-severity finding a hook scan
    # can produce is an allowlisted hook whose body changed since then.
    doc = collect()
    allowed = next(h for h in by_class(doc, "hook") if h.name == "numbat-pre-tool.sh")
    assert allowed.properties["contentChangedSinceApproval"] == "False"

    # stray-hook.sh has no follow-up status line in the fixture output --
    # nothing to report, not a false "unchanged".
    denied = next(h for h in by_class(doc, "hook") if h.name == "stray-hook.sh")
    assert "contentChangedSinceApproval" not in denied.properties


def test_hook_script_is_hashed_when_found_at_a_guessed_location():
    # Opportunistic: tests/fixtures/hermes_home/.hermes/hooks/numbat-pre-tool.sh
    # exists, matching one of _attach_script_fingerprint's guessed
    # candidate locations -- hermes_dir/"hooks"/<name>. Uses the same
    # property names as configuration/skill (path/relPath/sha256), not a
    # hook-specific name, so diff.py picks it up with no extra logic.
    doc = collect()
    allowed = next(h for h in by_class(doc, "hook") if h.name == "numbat-pre-tool.sh")
    assert len(allowed.properties["sha256"]) == 64
    assert allowed.properties["path"].endswith(".hermes/hooks/numbat-pre-tool.sh")
    assert allowed.properties["relPath"] == ".hermes/hooks/numbat-pre-tool.sh"
    assert allowed.properties["symlink"] == "False"
    assert "pathOutsideHome" not in allowed.properties


def test_hook_script_fingerprint_absent_when_not_found_anywhere():
    # stray-hook.sh has no file at any guessed location in the fixture --
    # must not raise, and must not fabricate a fingerprint for a file that
    # was never actually found.
    doc = collect()
    denied = next(h for h in by_class(doc, "hook") if h.name == "stray-hook.sh")
    assert "sha256" not in denied.properties
    assert "path" not in denied.properties


def test_content_changed_since_approval_fires_even_without_its_own_marker():
    # Regression test: an independent reviewer found the status line
    # ("script unchanged since approval") was silently dropped whenever
    # it didn't carry its own leading ✓/✗ -- confirmed real course-
    # material text has the marker, but whether every real box's output
    # does too isn't actually confirmed, so this must work either way.
    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ allowlisted (approved 2026-08-03) numbat-pre-tool.sh\n  script unchanged since approval\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    [hook] = by_class(doc, "hook")
    assert hook.properties["contentChangedSinceApproval"] == "False"


def test_hook_fingerprint_never_resolves_a_relative_name_against_cwd(tmp_path, monkeypatch):
    # Regression test: an independent reviewer found that a bare relative
    # captured name (e.g. "pre-commit.sh") got hashed against whatever
    # the *process's current working directory* happened to be -- so an
    # unrelated file placed there could be reported as the hook's own
    # fingerprint, worse than reporting no fingerprint for a tool whose
    # purpose is integrity. Confirmed here: a decoy file in cwd must
    # never be picked over the real hook under --home, or over nothing.
    fixture_home = FIXTURE_HOME.resolve()
    decoy_dir = tmp_path / "wherever-scan-happens-to-run-from"
    decoy_dir.mkdir()
    (decoy_dir / "numbat-pre-tool.sh").write_text("echo this is not the real hook\n")

    monkeypatch.chdir(decoy_dir)
    collector = HermesCollector(home=fixture_home, run=fake_run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    [hook] = [h for h in by_class(doc, "hook") if h.name == "numbat-pre-tool.sh"]
    assert hook.properties["path"] == str(fixture_home / ".hermes" / "hooks" / "numbat-pre-tool.sh")
    assert hook.properties["relPath"] == ".hermes/hooks/numbat-pre-tool.sh"


def test_no_hooks_configured_is_not_treated_as_a_parsing_failure():
    # Confirmed real output on a live box with zero hooks registered.
    no_hooks_output = "No shell hooks configured — nothing to check.\n"

    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return no_hooks_output
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    assert by_class(doc, "hook") == []
    assert not any("best-effort" in w for w in doc.warnings)


def test_relationships_recorded_on_document_root():
    doc = collect()
    verbs = {v for v, _ in doc.root_relationships}
    assert {"uses", "loads", "approves", "executes"} <= verbs


def test_status_line_that_repeats_the_script_name_still_sets_content_changed(tmp_path):
    # Regression test: an independent reviewer found a status line that
    # repeats the hook's script name (e.g. "pre-commit.sh CHANGED since
    # approval") matched the name regex, skipped the no-name branch
    # entirely, then failed the marker check and was dropped -- silently
    # losing the content-changed signal for a plausible real format.
    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ pre-commit.sh allowlisted (approved 2026-08-14)\n  pre-commit.sh CHANGED since approval\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    hooks = by_class(doc, "hook")
    assert len(hooks) == 1  # no phantom second hook from the status line
    assert hooks[0].properties["contentChangedSinceApproval"] == "True"


def test_hook_symlink_pointing_outside_home_sets_path_outside_home(tmp_path):
    # Regression test: an independent reviewer found pathOutsideHome only
    # fired when the *captured name itself* was absolute -- missing
    # exactly the case the flag exists to catch, a hook that sits inside
    # the harness directory but is a symlink resolving somewhere else
    # entirely (~/.hermes/hooks/audit.sh -> /tmp/evil/payload.sh).
    home = tmp_path / "home"
    hooks_dir = home / ".hermes" / "hooks"
    hooks_dir.mkdir(parents=True)
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    (evil_dir / "payload.sh").write_text("echo payload\n")
    (hooks_dir / "audit.sh").symlink_to(evil_dir / "payload.sh")

    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ allowlisted (approved 2026-08-03) audit.sh\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=home, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    [hook] = by_class(doc, "hook")
    assert hook.properties["path"] == str((evil_dir / "payload.sh").resolve())
    assert "relPath" not in hook.properties
    assert hook.properties["pathOutsideHome"] == "True"
    assert hook.properties["symlink"] == "True"


def test_combined_marker_name_and_status_line_is_not_dropped():
    # Regression test: an independent reviewer found the v0.1.9 fix for
    # "status line repeats the name" introduced a worse regression -- an
    # unconditional "since approval" check swallowed a line that was
    # BOTH a real hook entry (marker + name) AND mentioned "since
    # approval" in the same breath, silently dropping every hook with no
    # warning. A reader couldn't tell "this box has no hooks" from "the
    # parser dropped them".
    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return (
                "✓ pre-commit.sh allowlisted (unchanged since approval)\n"
                "✗ evil-payload.py allowlisted but CHANGED since approval\n"
            )
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    hooks = by_class(doc, "hook")
    assert len(hooks) == 2

    unchanged = next(h for h in hooks if h.name == "pre-commit.sh")
    assert unchanged.properties["contentChangedSinceApproval"] == "False"

    changed = next(h for h in hooks if h.name == "evil-payload.py")
    assert changed.properties["approvalStatus"] == "not_allowlisted"
    assert changed.properties["contentChangedSinceApproval"] == "True"


def test_marker_lines_with_zero_extracted_hooks_warns_instead_of_silently_reporting_none():
    # Guard against the same class of failure recurring in a form this
    # specific fix doesn't cover: if the parser ever again fails to
    # extract hooks from output that clearly has marker lines, it must
    # say so, not report a clean "no hooks" the same way a genuinely
    # hook-free box does.
    def run(argv):
        if argv == ["hermes", "--version"]:
            return VERSION_OUTPUT
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ some format this parser doesn't recognize at all\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=fake_fetch)
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    assert by_class(doc, "hook") == []
    assert any("no hook components could be extracted" in w for w in doc.warnings)
