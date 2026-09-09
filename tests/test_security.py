from harness_aibom.collectors.secrets import SECRET_NAME_PATTERNS
from harness_aibom.cyclonedx import ROOT_BOM_REF, to_cyclonedx
from harness_aibom.model import Component, HarnessDocument
from harness_aibom.security import (
    HEURISTIC_PATTERNS,
    HIGH_CONFIDENCE_PATTERNS,
    ROOT_LABEL,
    build_architecture_graph,
    classify_capabilities,
    classify_reachability,
    classify_secret_confidence,
    compute_attack_surface,
    compute_blast_radius,
    compute_coverage,
    compute_risk_observations,
    compute_security_summary,
    compute_supply_chain,
    index_mcp_servers,
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


def test_world_readable_secret_high_confidence_match_is_flagged_high():
    doc = _doc()
    secret = Component(component_class="secrets_surface", name=".env")
    secret.set("worldReadable", True)
    doc.add(secret, "accesses")
    bom = to_cyclonedx(doc)

    [obs] = compute_risk_observations(bom)
    assert obs["rule"] == "world_readable_secret_high_confidence"
    assert obs["severity"] == "high"


def test_world_readable_secret_heuristic_match_is_flagged_separately_at_lower_severity():
    # Regression test: an independent reviewer found classify_secret_
    # confidence() was dead code -- a *token*/*.sqlite heuristic match
    # (secrets.py's own noisy tier) was reported at the same "high"
    # severity as an exact .env/*.pem/*.key match.
    doc = _doc()
    high = Component(component_class="secrets_surface", name=".env")
    high.set("worldReadable", True)
    doc.add(high, "accesses")
    heuristic = Component(component_class="secrets_surface", name="npm-token.1")
    heuristic.set("worldReadable", True)
    doc.add(heuristic, "accesses")
    bom = to_cyclonedx(doc)

    by_rule = {o["rule"]: o for o in compute_risk_observations(bom)}
    assert by_rule["world_readable_secret_high_confidence"]["severity"] == "high"
    assert by_rule["world_readable_secret_high_confidence"]["components"] == [high.bom_ref]
    assert by_rule["world_readable_secret_heuristic"]["severity"] == "medium"
    assert by_rule["world_readable_secret_heuristic"]["components"] == [heuristic.bom_ref]


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


def test_unpinned_mcp_launcher_package_is_flagged():
    doc = _doc()
    dep = Component(component_class="dependency", name="some-pkg")  # no .version
    dep.set("origin", "mcp-launcher")
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "unpinned_mcp_launcher" in rules
    assert "python_package_missing_version" not in rules


def test_python_package_missing_version_is_flagged_as_a_different_rule():
    # Regression test: an independent reviewer found this rule used to
    # infer "unpinned MCP launcher" purely from the *absence* of a
    # version field -- a Python package with malformed METADATA missing
    # its own Version: header (a real, if rare, case) would have been
    # silently merged into that same finding. `origin` (set by mcp.py vs
    # deps.py) makes the two genuinely distinguishable rules.
    doc = _doc()
    dep = Component(component_class="dependency", name="some-pkg")  # no .version
    dep.set("origin", "python-package")
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "python_package_missing_version" in rules
    assert "unpinned_mcp_launcher" not in rules


def test_pinned_dependency_package_is_not_flagged():
    doc = _doc()
    dep = Component(component_class="dependency", name="some-pkg")
    dep.version = "1.2.3"
    dep.set("origin", "mcp-launcher")
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    rules = {o["rule"] for o in compute_risk_observations(bom)}
    assert "unpinned_mcp_launcher" not in rules
    assert "python_package_missing_version" not in rules


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
    # v0.6.0: both now genuinely collectible (see collectors/
    # prompt_surface.py, collectors/memory_store.py), so "not found in
    # THIS document" correctly reads as "empty", not "not_collected" --
    # that tuple is empty as of this release, kept only as a place for a
    # future genuinely-uncollected gap to go.
    assert "prompt_surface" in coverage["empty"]
    assert "memory_store" in coverage["empty"]
    assert coverage["not_collected"] == []


def test_coverage_score_counts_found_against_the_full_known_universe():
    bom = to_cyclonedx(_doc())  # nothing found at all
    found, total = compute_coverage(bom)["score"]
    assert found == 0
    assert total == len(compute_coverage(bom)["empty"]) + len(compute_coverage(bom)["not_collected"])


# ---- capabilities (v0.5.0) -------------------------------------------------


def test_tool_capability_comes_from_its_own_riskclass_not_a_fixed_default():
    entry = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "tool"},
        {"name": "harness-aibom:riskClass", "value": "exec"},
    ]}
    assert classify_capabilities(entry) == "execute"


def test_secrets_surface_capability_is_credential():
    entry = {"properties": [{"name": "harness-aibom:componentClass", "value": "secrets_surface"}]}
    assert classify_capabilities(entry) == "credential"


def test_model_endpoint_and_mcp_server_capability_is_network():
    for cls in ("model_endpoint", "mcp_server"):
        entry = {"properties": [{"name": "harness-aibom:componentClass", "value": cls}]}
        assert classify_capabilities(entry) == "network"


def test_stdio_mcp_server_capability_is_process_not_network():
    # Regression test: an independent reviewer found mcp_server's
    # capability was a fixed "network" regardless of transport,
    # contradicting classify_reachability()'s already-correct "process"
    # for the very same stdio server on the very same row.
    entry = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "mcp_server"},
        {"name": "harness-aibom:transport", "value": "stdio"},
    ]}
    assert classify_capabilities(entry) == "process"


# ---- reachability / attack surface (v0.5.0) --------------------------------


def test_secrets_surface_is_credential_store():
    entry = {"properties": [{"name": "harness-aibom:componentClass", "value": "secrets_surface"}]}
    assert classify_reachability(entry) == "credential-store"


def test_stdio_mcp_server_is_process_not_network():
    entry = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "mcp_server"},
        {"name": "harness-aibom:transport", "value": "stdio"},
    ]}
    assert classify_reachability(entry) == "process"


def test_loopback_model_endpoint_is_loopback_not_network():
    entry = {"name": "http://127.0.0.1:11434/v1", "properties": [
        {"name": "harness-aibom:componentClass", "value": "model_endpoint"},
    ]}
    assert classify_reachability(entry) == "loopback"


def test_remote_mcp_server_endpoint_is_network():
    entry = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "mcp_server"},
        {"name": "harness-aibom:transport", "value": "http"},
        {"name": "harness-aibom:endpoint", "value": "https://mcp.corp.lab:8443"},
    ]}
    assert classify_reachability(entry) == "network"


def test_tool_reachability_is_inherited_from_its_parent_mcp_server_not_guessed():
    # Regression test: an independent reviewer found a tool's
    # reachability used to come from its own riskClass alone -- a
    # read/write tool on a remote HTTPS server read as "filesystem" (the
    # opposite of true), and a network-tagged tool on a local stdio
    # server read as "network" (also backwards). Reachability is a
    # property of the *server* a tool belongs to, not of the tool.
    doc = _doc()
    remote = Component(component_class="mcp_server", name="remote-tls")
    remote.set("transport", "http")
    remote.set("endpoint", "https://mcp.corp.lab:8443")
    doc.add(remote, "uses")
    local = Component(component_class="mcp_server", name="stdio-srv")
    local.set("transport", "stdio")
    doc.add(local, "uses")
    bom = to_cyclonedx(doc)

    servers = index_mcp_servers(bom)
    remote_tool = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "tool"},
        {"name": "harness-aibom:server", "value": "remote-tls"},
        {"name": "harness-aibom:riskClass", "value": "read"},
    ]}
    local_tool = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "tool"},
        {"name": "harness-aibom:server", "value": "stdio-srv"},
        {"name": "harness-aibom:riskClass", "value": "network"},
    ]}
    assert classify_reachability(remote_tool, servers) == "network"
    assert classify_reachability(local_tool, servers) == "process"


def test_tool_reachability_is_unknown_without_a_resolvable_parent_server():
    entry = {"properties": [
        {"name": "harness-aibom:componentClass", "value": "tool"},
        {"name": "harness-aibom:server", "value": "no-such-server"},
    ]}
    assert classify_reachability(entry, {}) == "unknown"


def test_attack_surface_uses_the_correct_tool_reachability_end_to_end():
    doc = _doc()
    server = Component(component_class="mcp_server", name="remote-tls")
    server.set("transport", "http")
    server.set("endpoint", "https://mcp.corp.lab:8443")
    tool = Component(component_class="tool", name="remote-tls/search")
    tool.set("server", "remote-tls")
    tool.set("riskClass", "read")
    doc.add(server, "uses")
    doc.add_child(tool, server, "uses")
    bom = to_cyclonedx(doc)

    surface = compute_attack_surface(bom)
    assert tool.bom_ref in surface["by_tier"]["network"]
    assert tool.bom_ref in surface["crosses_network_boundary"]


def test_attack_surface_groups_entries_by_reachability_tier():
    doc = _doc()
    secret = Component(component_class="secrets_surface", name=".env")
    doc.add(secret, "accesses")
    endpoint = Component(component_class="model_endpoint", name="https://api.example.com/v1")
    doc.add(endpoint, "uses")
    bom = to_cyclonedx(doc)

    surface = compute_attack_surface(bom)
    assert secret.bom_ref in surface["by_tier"]["credential-store"]
    assert endpoint.bom_ref in surface["by_tier"]["network"]
    assert endpoint.bom_ref in surface["crosses_network_boundary"]


def test_attack_surface_loopback_entries_dont_cross_a_network_boundary():
    doc = _doc()
    endpoint = Component(component_class="model_endpoint", name="http://127.0.0.1:11434/v1")
    doc.add(endpoint, "uses")
    bom = to_cyclonedx(doc)

    surface = compute_attack_surface(bom)
    assert endpoint.bom_ref not in surface["crosses_network_boundary"]
    assert endpoint.bom_ref in surface["by_tier"]["loopback"]


# ---- supply chain: what a component depends on (v0.5.0) -------------------


def test_supply_chain_is_the_real_transitive_dependency_set():
    doc = _doc()
    config = Component(component_class="configuration", name="config.yaml")
    doc.add(config, "loads")
    endpoint = Component(component_class="model_endpoint", name="http://x")
    doc.add_child(endpoint, config, "uses")
    model = Component(component_class="model", name="qwen3:8b")
    doc.add_child(model, endpoint, "uses")
    bom = to_cyclonedx(doc)

    chain = compute_supply_chain(bom, config.bom_ref)
    assert chain["direct_children"] == [endpoint.bom_ref]
    assert set(chain["reachable"]) == {endpoint.bom_ref, model.bom_ref}


def test_supply_chain_of_a_leaf_component_is_empty():
    doc = _doc()
    skill = Component(component_class="skill", name="lonely-skill")
    doc.add(skill, "loads")
    bom = to_cyclonedx(doc)

    chain = compute_supply_chain(bom, skill.bom_ref)
    assert chain["direct_children"] == []
    assert chain["reachable"] == []


def test_supply_chain_of_an_unknown_ref_is_empty_not_an_error():
    bom = to_cyclonedx(_doc())
    assert compute_supply_chain(bom, "no-such-ref") == {"direct_children": [], "reachable": []}


# ---- blast radius: what depends on a component (v0.5.1, direction fixed) --


def test_blast_radius_is_the_reverse_of_supply_chain():
    # Regression test: an independent reviewer found the original v0.5.0
    # compute_blast_radius() followed dependsOn *forward* (a component's
    # own supply chain -- what it relies on), so a poisoned leaf
    # component always reported zero blast radius, the least useful
    # possible answer to "what's affected if this is compromised".
    doc = _doc()
    config = Component(component_class="configuration", name="config.yaml")
    doc.add(config, "loads")
    endpoint = Component(component_class="model_endpoint", name="http://x")
    doc.add_child(endpoint, config, "uses")
    model = Component(component_class="model", name="qwen3:8b")
    doc.add_child(model, endpoint, "uses")
    bom = to_cyclonedx(doc)

    # Compromising the model affects the endpoint and configuration that
    # depend on it -- the reverse of the model's own (empty) supply chain.
    radius = compute_blast_radius(bom, model.bom_ref)
    assert radius["direct_dependents"] == [endpoint.bom_ref]
    assert set(radius["reachable"]) == {endpoint.bom_ref, config.bom_ref, ROOT_BOM_REF}
    assert compute_supply_chain(bom, model.bom_ref) == {"direct_children": [], "reachable": []}


def test_blast_radius_of_a_leaf_component_reaches_the_harness_root():
    # A leaf still has something depend on it -- the harness root itself,
    # via HarnessDocument.add(). "Zero blast radius" for a compromised
    # skill or secrets file would be exactly as misleading as the
    # original forward-only bug.
    doc = _doc()
    skill = Component(component_class="skill", name="lonely-skill")
    doc.add(skill, "loads")
    bom = to_cyclonedx(doc)

    radius = compute_blast_radius(bom, skill.bom_ref)
    assert radius["direct_dependents"] == [ROOT_BOM_REF]
    assert radius["reachable"] == [ROOT_BOM_REF]


def test_blast_radius_of_an_unknown_ref_is_empty_not_an_error():
    bom = to_cyclonedx(_doc())
    assert compute_blast_radius(bom, "no-such-ref") == {"direct_dependents": [], "reachable": []}
