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
