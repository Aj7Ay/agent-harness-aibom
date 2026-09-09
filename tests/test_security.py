from harness_aibom.collectors.secrets import SECRET_NAME_PATTERNS
from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.security import (
    HEURISTIC_PATTERNS,
    HIGH_CONFIDENCE_PATTERNS,
    ROOT_LABEL,
    build_architecture_graph,
    classify_secret_confidence,
    compute_coverage,
    compute_risk_observations,
    compute_security_summary,
)


def _doc() -> HarnessDocument:
    return HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")


# ---- architecture graph -----------------------------------------------


def test_architecture_graph_is_class_level_not_instance_level():
    # The whole point: 3 skills must collapse into one "skill" node, not
    # three separate boxes -- an instance-level graph would just be the
    # same "here's everything" inventory problem in diagram form.
    doc = _doc()
    for name in ("a", "b", "c"):
        doc.add(Component(component_class="skill", name=name), "loads")
    bom = to_cyclonedx(doc)

    graph = build_architecture_graph(bom)
    assert graph["nodes"]["skill"] == 3
    assert (ROOT_LABEL, "skill") in graph["edges"]
    # exactly one edge for the class, not three
    assert graph["edges"].count((ROOT_LABEL, "skill")) == 1


def test_architecture_graph_reflects_real_multi_level_edges():
    doc = _doc()
    endpoint = doc.add(Component(component_class="model_endpoint", name="http://x"), "uses")
    doc.add_child(Component(component_class="model", name="qwen3:8b"), endpoint, "uses")
    bom = to_cyclonedx(doc)

    graph = build_architecture_graph(bom)
    assert (ROOT_LABEL, "model_endpoint") in graph["edges"]
    assert ("model_endpoint", "model") in graph["edges"]
    # the real edge is endpoint -> model, never root -> model directly
    assert (ROOT_LABEL, "model") not in graph["edges"]


def test_architecture_graph_on_empty_document_has_only_the_root():
    bom = to_cyclonedx(_doc())
    graph = build_architecture_graph(bom)
    assert graph["nodes"] == {ROOT_LABEL: 1}
    assert graph["edges"] == []


# ---- security summary ---------------------------------------------------


def test_security_summary_counts_are_real_lens_not_guesses():
    doc = _doc()
    doc.add(Component(component_class="skill", name="a"), "loads")
    doc.add(Component(component_class="skill", name="b"), "loads")
    server = doc.add(Component(component_class="mcp_server", name="srv"), "uses")
    exec_tool = Component(component_class="tool", name="srv/run")
    exec_tool.set("riskClass", "exec")
    doc.add_child(exec_tool, server, "uses")
    read_tool = Component(component_class="tool", name="srv/read")
    read_tool.set("riskClass", "read")
    doc.add_child(read_tool, server, "uses")
    bom = to_cyclonedx(doc)

    summary = compute_security_summary(bom)
    assert summary["skills"] == 2
    assert summary["mcp_servers"] == 1
    assert summary["mcp_tools"] == 2
    assert summary["executable_tools"] == 1


def test_security_summary_fingerprinted_counts_only_hashed_entries():
    doc = _doc()
    hashed = Component(component_class="skill", name="hashed")
    hashed.set("sha256", "a" * 64)
    doc.add(hashed, "loads")
    doc.add(Component(component_class="skill", name="unhashed"), "loads")
    bom = to_cyclonedx(doc)

    assert compute_security_summary(bom)["fingerprinted"] == 1


# ---- risk observations ---------------------------------------------------


def test_world_readable_secret_is_flagged_high():
    doc = _doc()
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    bom = to_cyclonedx(doc)

    [obs] = compute_risk_observations(bom)
    assert obs["rule"] == "world_readable_secret"
    assert obs["severity"] == "high"


def test_no_observations_when_nothing_matches_any_rule():
    doc = _doc()
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", False)
    doc.add(secret, "accesses")
    bom = to_cyclonedx(doc)

    assert compute_risk_observations(bom) == []


def test_plaintext_mcp_transport_is_flagged():
    doc = _doc()
    server = Component(component_class="mcp_server", name="srv")
    server.set("transport", "http")
    server.set("tls", False)
    doc.add(server, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "mcp_plaintext_transport" in rules


def test_stdio_mcp_server_never_flagged_for_missing_tls():
    # tls="n/a" for stdio (see mcp.py) must never misread as "plaintext".
    doc = _doc()
    server = Component(component_class="mcp_server", name="srv")
    server.set("transport", "stdio")
    server.set("tls", "n/a")
    server.set("authConfigured", True)
    doc.add(server, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "mcp_plaintext_transport" not in rules


def test_mcp_server_without_auth_is_flagged():
    doc = _doc()
    server = Component(component_class="mcp_server", name="srv")
    server.set("authConfigured", False)
    doc.add(server, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "mcp_no_auth" in rules


def test_unpinned_dependency_package_is_flagged():
    doc = _doc()
    dep = Component(component_class="dependency", name="some-pkg")  # no .version
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "unpinned_dependency" in rules


def test_pinned_dependency_package_is_not_flagged():
    doc = _doc()
    dep = Component(component_class="dependency", name="some-pkg")
    dep.version = "1.2.3"
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "unpinned_dependency" not in rules


def test_model_without_digest_is_flagged():
    doc = _doc()
    doc.add(Component(component_class="model", name="mystery-model"), "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "model_no_digest" in rules


# ---- secrets confidence tiers --------------------------------------------


def test_high_and_heuristic_tiers_exactly_partition_the_real_pattern_list():
    # Regression guard: if secrets.py's SECRET_NAME_PATTERNS ever changes,
    # this fails loudly instead of silently misclassifying a new pattern.
    assert set(HIGH_CONFIDENCE_PATTERNS) | set(HEURISTIC_PATTERNS) == set(SECRET_NAME_PATTERNS)
    assert set(HIGH_CONFIDENCE_PATTERNS).isdisjoint(HEURISTIC_PATTERNS)


def test_dotenv_file_is_high_confidence():
    assert classify_secret_confidence({"name": ".env"}) == "high"
    assert classify_secret_confidence({"name": "skills/foo/.env"}) == "high"


def test_pem_and_key_files_are_high_confidence():
    assert classify_secret_confidence({"name": "server.pem"}) == "high"
    assert classify_secret_confidence({"name": "id.key"}) == "high"


def test_token_substring_match_is_only_heuristic():
    # The exact false-positive an independent reviewer named: "tokenize.js"
    # matches "*token*" but obviously isn't a credential.
    assert classify_secret_confidence({"name": "tokenize.js"}) == "heuristic"
    assert classify_secret_confidence({"name": "npm-token.1"}) == "heuristic"


def test_sqlite_file_is_only_heuristic():
    assert classify_secret_confidence({"name": "openclaw-agent.sqlite"}) == "heuristic"


# ---- coverage -------------------------------------------------------------


def test_coverage_reports_found_and_empty_collectible_classes():
    doc = _doc()
    doc.add(Component(component_class="skill", name="a"), "loads")
    bom = to_cyclonedx(doc)

    coverage = compute_coverage(bom)
    assert "skill" in coverage["found"]
    assert "mcp_server" in coverage["empty"]
    assert "prompt_surface" in coverage["not_collected"]
    assert "memory_store" in coverage["not_collected"]


def test_coverage_score_counts_found_against_the_full_known_universe():
    bom = to_cyclonedx(_doc())  # nothing found at all
    found, total = compute_coverage(bom)["score"]
    assert found == 0
    assert total == len(compute_coverage(bom)["empty"]) + len(compute_coverage(bom)["not_collected"])
