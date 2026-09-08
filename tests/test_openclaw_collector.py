from pathlib import Path

from harness_aibom.collectors.openclaw import OpenClawCollector
from harness_aibom.model import HarnessDocument

FIXTURE_HOME = Path(__file__).parent / "fixtures" / "openclaw_home"

VERSION_OUTPUT = "openclaw 1.4.2\n"

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
    if argv == ["openclaw", "--version"]:
        return VERSION_OUTPUT
    raise AssertionError(f"unexpected command {argv}")


def fake_fetch(url):
    assert url.endswith("/api/tags")
    return TAGS_RESPONSE


def collect() -> HarnessDocument:
    collector = OpenClawCollector(
        home=FIXTURE_HOME,
        run=fake_run,
        fetch=fake_fetch,
        env_dir=FIXTURE_HOME / "opt-openclaw-does-not-exist",
    )
    assert collector.is_present()
    doc = HarnessDocument(harness_name="openclaw@test", runtime_kind="openclaw", hostname="test")
    collector.collect(doc)
    return doc


def by_class(doc, cls):
    return [c for c in doc.components if c.component_class == cls]


def test_runtime_component():
    doc = collect()
    [runtime] = by_class(doc, "runtime")
    assert runtime.version == "openclaw 1.4.2"


def test_model_from_ollama_provider():
    doc = collect()
    [endpoint] = by_class(doc, "model_endpoint")
    assert endpoint.name == "http://127.0.0.1:11434"
    assert endpoint.properties["provider"] == "ollama"

    [model] = by_class(doc, "model")
    assert model.name == "qwen3:8b"
    assert model.properties["digest"] == "500a1f067a9f"


def test_configuration_component_has_hash():
    doc = collect()
    [config] = by_class(doc, "configuration")
    assert config.name == "openclaw.json"
    assert len(config.properties["sha256"]) == 64


def test_mcp_servers():
    doc = collect()
    [server] = by_class(doc, "mcp_server")
    assert server.name == "local-fs"
    assert server.properties["tls"] == "False"


def test_secrets_surface_finds_sqlite_store():
    doc = collect()
    secrets = by_class(doc, "secrets_surface")
    names = {s.name for s in secrets}
    assert "openclaw-agent.sqlite" in names

    sqlite_comp = next(s for s in secrets if s.name == "openclaw-agent.sqlite")
    assert "credential store" in sqlite_comp.properties["note"]
    # never the token value, only that a config file with a token key exists
    assert all("REDACTED" not in v for v in sqlite_comp.properties.values())
