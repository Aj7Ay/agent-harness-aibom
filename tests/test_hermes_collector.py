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
