from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom.diff import diff_documents
from harness_aibom.model import Component, HarnessDocument


def doc_with_skill(sha: str) -> dict:
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    skill = Component(component_class="skill", name="incident-response")
    skill.set("sha256", sha)
    doc.add(skill, "loads")
    return to_cyclonedx(doc)


def test_unchanged_skill_produces_no_diff():
    before = doc_with_skill("aaa")
    after = doc_with_skill("aaa")
    assert diff_documents(before, after) == {"added": [], "removed": [], "changed": []}


def test_poisoned_skill_shows_as_fingerprint_changed():
    before = doc_with_skill("aaa")
    after = doc_with_skill("bbb")
    result = diff_documents(before, after)

    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "skill:incident-response"
    assert change["fingerprint_changed"] is True
    assert change["fields"]["harness-aibom:sha256"] == {"before": "aaa", "after": "bbb"}


def test_added_and_removed_components():
    before = to_cyclonedx(HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t"))

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_doc.add(Component(component_class="mcp_server", name="new-server"), "uses")
    after = to_cyclonedx(after_doc)

    result = diff_documents(before, after)
    assert result["added"] == ["mcp_server:new-server"]
    assert result["removed"] == []


def doc_with_two_same_named_envs(top_level_mode: str) -> dict:
    # Both components share the exact same `name` (".env") -- the shape
    # that used to collide in diff._index() before it started keying on
    # `path`. Testing diff.py's own contract directly, independent of
    # whatever collectors/secrets.py happens to set `name` to.
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")

    top_level = Component(component_class="secrets_surface", name=".env")
    top_level.set("path", "/root/.hermes/.env")
    top_level.set("mode", top_level_mode)
    doc.add(top_level, "accesses")

    nested = Component(component_class="secrets_surface", name=".env")
    nested.set("path", "/root/.hermes/skills/devops/k8s-triage/.env")
    nested.set("mode", "0o600")
    doc.add(nested, "accesses")

    return to_cyclonedx(doc)


def test_same_basename_in_different_directories_does_not_collide_in_diff():
    # Regression test: two secrets_surface components both literally named
    # ".env" used to collapse into one dict entry keyed on name alone,
    # silently hiding a real permission change to whichever one lost that
    # collision -- confirmed by an independent reviewer, reproduced here.
    before = doc_with_two_same_named_envs("0o644")
    after = doc_with_two_same_named_envs("0o600")

    result = diff_documents(before, after)

    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "secrets_surface:/root/.hermes/.env"
    assert change["fields"]["harness-aibom:mode"] == {"before": "0o644", "after": "0o600"}


def doc_with_relpath_skill(home_username: str, sha: str) -> dict:
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    skill = Component(component_class="skill", name="incident-response")
    # Different absolute path (different machine, different username),
    # same relPath (same layout relative to --home).
    skill.set("path", f"/home/{home_username}/.hermes/skills/incident-response")
    skill.set("relPath", ".hermes/skills/incident-response")
    skill.set("sha256", sha)
    doc.add(skill, "loads")
    return to_cyclonedx(doc)


def test_cross_host_diff_uses_relpath_not_absolute_path():
    # Regression test: keying on the absolute `path` alone (v0.1.4's fix
    # for the previous bug) broke comparing two different machines with
    # the same layout -- a golden baseline vs. a lab VM, or one student's
    # box vs. another's. /home/alice and /home/bob share no absolute
    # paths, so every unchanged file used to read as both added and
    # removed. relPath fixes this: same layout, same identity, regardless
    # of whose home directory it is.
    before = doc_with_relpath_skill("alice", "aaa")
    after = doc_with_relpath_skill("bob", "aaa")

    assert diff_documents(before, after) == {"added": [], "removed": [], "changed": []}


def test_cross_host_diff_still_finds_a_real_change_via_relpath():
    before = doc_with_relpath_skill("alice", "aaa")
    after = doc_with_relpath_skill("bob", "bbb")

    result = diff_documents(before, after)
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["fingerprint_changed"] is True


def doc_with_hook(sha: str) -> dict:
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    hook = Component(component_class="hook", name="pre-commit.sh")
    hook.set("approvalStatus", "allowlisted")
    hook.set("path", "/root/.hermes/hooks/pre-commit.sh")
    hook.set("relPath", ".hermes/hooks/pre-commit.sh")
    hook.set("sha256", sha)
    doc.add(hook, "approves")
    return to_cyclonedx(doc)


def test_a_changed_allowlisted_hook_body_is_flagged_as_fingerprint_changed():
    # The highest-severity finding a hook scan can produce: a hook that
    # was allowlisted, then had its script content changed afterward.
    # Confirms path/relPath/sha256 naming (not scriptPath/scriptSha256)
    # was the right call -- diff needs zero hook-specific code for this.
    before = doc_with_hook("aaa")
    after = doc_with_hook("bbb")

    result = diff_documents(before, after)
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "hook:.hermes/hooks/pre-commit.sh"
    assert change["fingerprint_changed"] is True


def doc_with_two_same_named_mcp_servers(first_endpoint: str) -> dict:
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")

    first = Component(component_class="mcp_server", name="fs")
    first.set("endpoint", first_endpoint)
    first.set("tls", first_endpoint.startswith("https://"))
    doc.add(first, "uses")

    second = Component(component_class="mcp_server", name="fs")
    second.set("endpoint", "https://b.example.com/sse")
    second.set("tls", True)
    doc.add(second, "uses")

    return to_cyclonedx(doc)


def test_duplicate_mcp_server_names_do_not_collide_in_diff():
    # Regression test: an independent reviewer found two mcp_server
    # entries sharing a `name` collapsed into one dict entry, the same
    # class of bug relPath fixed for files -- except services carry no
    # path/relPath at all, so `name` was the only identity available and
    # a TLS downgrade on one of two identically-named servers vanished
    # from the diff entirely.
    before = doc_with_two_same_named_mcp_servers("https://a.example.com/sse")
    after = doc_with_two_same_named_mcp_servers("http://a.example.com/sse")  # downgraded to plaintext

    result = diff_documents(before, after)
    # Visible as add+remove (the disambiguator itself is what changed),
    # not silently absent -- see diff.py's _index() for the trade-off.
    assert result["added"] == ["mcp_server:fs#http://a.example.com/sse"]
    assert result["removed"] == ["mcp_server:fs#https://a.example.com/sse"]
    assert result["changed"] == []


def test_single_named_mcp_server_is_unaffected_by_duplicate_handling():
    # The common case (no name collision at all) must keep clean
    # "changed" semantics, not regress to add+remove just because the
    # duplicate-handling code path exists.
    def doc_with(tls: bool) -> dict:
        doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
        server = Component(component_class="mcp_server", name="corp-docs")
        server.set("endpoint", "https://mcp.corp.lab" if tls else "http://mcp.corp.lab")
        server.set("tls", tls)
        doc.add(server, "uses")
        return to_cyclonedx(doc)

    result = diff_documents(doc_with(True), doc_with(False))
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "mcp_server:corp-docs"
    assert change["fields"]["harness-aibom:tls"] == {"before": "True", "after": "False"}
