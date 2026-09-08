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
