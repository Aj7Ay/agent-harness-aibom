"""Table-driven sweep over diff.py's identity resolution -- every
componentClass/scenario combination this project's history has actually
found a bug in, consolidated in one place so a future change to
`_index()` gets checked against all of them at once. See
tests/test_hook_parsing_matrix.py for the same idea applied to hook
output shapes.

Each case builds a `before` and `after` HarnessDocument via a small
builder function, and asserts on the resulting diff.
"""

from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.diff import diff_documents
from harness_aibom.model import Component, HarnessDocument


def _doc(*components_and_verbs: tuple[Component, str]) -> dict:
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    for comp, verb in components_and_verbs:
        doc.add(comp, verb)
    return to_cyclonedx(doc)


def test_two_secrets_with_same_basename_different_directories_dont_collide():
    def build(mode: str) -> dict:
        a = Component(component_class="secrets_surface", name=".env")
        a.set("path", "/root/.hermes/.env")
        a.set("mode", mode)
        b = Component(component_class="secrets_surface", name=".env")
        b.set("path", "/root/.hermes/skills/devops/k8s-triage/.env")
        b.set("mode", "0o600")
        return _doc((a, "accesses"), (b, "accesses"))

    result = diff_documents(build("0o644"), build("0o600"))
    assert len(result["changed"]) == 1
    assert result["changed"][0]["component"] == "secrets_surface:/root/.hermes/.env"


def test_secrets_with_relpath_match_across_different_home_roots():
    def build(username: str) -> dict:
        c = Component(component_class="secrets_surface", name=".env")
        c.set("path", f"/home/{username}/.hermes/.env")
        c.set("relPath", ".hermes/.env")
        c.set("mode", "0o600")
        return _doc((c, "accesses"))

    assert diff_documents(build("alice"), build("bob")) == {"added": [], "removed": [], "changed": []}


def test_secrets_without_relpath_dont_match_across_different_home_roots():
    # OpenClaw's env_dir (/opt/openclaw by default) is outside --home, so
    # it never gets a relPath -- confirmed limitation, documented in
    # SPEC.md, not a bug: those components fall back to the absolute
    # path, which two different machines will never share.
    def build(hostname: str) -> dict:
        c = Component(component_class="secrets_surface", name=".env")
        c.set("path", f"/opt/openclaw-{hostname}/.env")
        c.set("mode", "0o600")
        return _doc((c, "accesses"))

    result = diff_documents(build("box-a"), build("box-b"))
    assert result["added"] and result["removed"]
    assert result["changed"] == []


def test_hook_with_found_script_diffs_via_fingerprint():
    def build(sha: str) -> dict:
        h = Component(component_class="hook", name="pre-commit.sh")
        h.set("path", "/root/.hermes/hooks/pre-commit.sh")
        h.set("relPath", ".hermes/hooks/pre-commit.sh")
        h.set("sha256", sha)
        return _doc((h, "approves"))

    result = diff_documents(build("aaa"), build("bbb"))
    [change] = result["changed"]
    assert change["fingerprint_changed"] is True


def test_two_mcp_servers_same_name_url_based_disambiguate_by_endpoint():
    def build(first_tls: bool) -> dict:
        a = Component(component_class="mcp_server", name="fs")
        a.set("endpoint", "https://a.example.com/sse" if first_tls else "http://a.example.com/sse")
        a.set("tls", first_tls)
        b = Component(component_class="mcp_server", name="fs")
        b.set("endpoint", "https://b.example.com/sse")
        b.set("tls", True)
        return _doc((a, "uses"), (b, "uses"))

    result = diff_documents(build(True), build(False))
    # The endpoint (the tiebreaker itself) changed -- visible as add+remove,
    # not silently absent. See SPEC.md §4 for the trade-off.
    assert result["added"] and result["removed"]
    assert result["changed"] == []


def test_two_mcp_servers_same_name_stdio_based_disambiguate_by_command():
    # Not previously covered: two *stdio* servers (no endpoint at all)
    # sharing a name must disambiguate by command/args instead.
    def build(args_value: str) -> dict:
        a = Component(component_class="mcp_server", name="fs")
        a.set("command", "npx")
        a.set("args", args_value)
        b = Component(component_class="mcp_server", name="fs")
        b.set("command", "uvx")
        b.set("args", "other-server")
        return _doc((a, "uses"), (b, "uses"))

    result = diff_documents(build("-y server-a"), build("-y server-a --verbose"))
    assert result["added"] and result["removed"]
    assert result["changed"] == []


def test_uniquely_named_mcp_server_keeps_plain_changed_semantics():
    # The common case: no collision at all. Must not be affected by the
    # duplicate-handling code path existing.
    def build(tls: bool) -> dict:
        s = Component(component_class="mcp_server", name="corp-docs")
        s.set("endpoint", "https://mcp.corp.lab" if tls else "http://mcp.corp.lab")
        s.set("tls", tls)
        return _doc((s, "uses"))

    result = diff_documents(build(True), build(False))
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "mcp_server:corp-docs"
