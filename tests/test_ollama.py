from harness_aibom.collectors.ollama import discover_models


def test_discover_models_basic_fields():
    def fetch(url):
        assert url.endswith("/api/tags")
        return {"models": [{"name": "qwen3:8b", "digest": "abc123", "size": 100}]}

    [model] = discover_models("http://127.0.0.1:11434", fetch=fetch)
    assert model.name == "qwen3:8b"
    assert model.properties["digest"] == "abc123"


def test_model_digest_is_tagged_observed_when_present():
    # v0.9.0: digest is taken verbatim from Ollama's own manifest --
    # a real, directly observed fact, tagged so a reader can contrast it
    # with a genuinely inferred one elsewhere in the document (skills.py).
    def fetch(url):
        return {"models": [{"name": "qwen3:8b", "digest": "abc123"}]}

    [model] = discover_models("http://127.0.0.1:11434", fetch=fetch)
    assert model.properties["digestConfidence"] == "observed"


def test_model_with_no_digest_gets_no_confidence_tag_fabricated():
    def fetch(url):
        return {"models": [{"name": "qwen3:8b"}]}  # no digest at all

    [model] = discover_models("http://127.0.0.1:11434", fetch=fetch)
    assert "digest" not in model.properties
    assert "digestConfidence" not in model.properties


def test_unreachable_ollama_returns_no_models_not_a_crash():
    def fetch(url):
        raise ConnectionError("refused")

    assert discover_models("http://127.0.0.1:11434", fetch=fetch) == []
