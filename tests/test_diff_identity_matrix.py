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


def test_name_unique_in_before_but_duplicated_in_after_matches_the_persisting_server():
    # Regression test: an independent reviewer found that computing
    # ambiguity separately per document meant a name unique in `before`
    # (one bare-keyed entry) never matched either of `after`'s two
    # disambiguated entries once a second same-named server appeared --
    # the unchanged server read as removed, and BOTH after-side entries
    # read as added, even though one of them was the exact same server
    # persisting untouched. Fixed by deciding ambiguity from the union of
    # both scans, so the persisting server gets the same disambiguated
    # key on both sides and only the genuinely new one shows as added.
    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://x.example.com"), "uses")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://x.example.com"), "uses")
    after_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://y.example.com"), "uses")
    after = to_cyclonedx(after_doc)

    result = diff_documents(before, after)
    assert result["added"] == ["mcp_server:fs#https://y.example.com"]
    assert result["removed"] == []
    assert result["changed"] == []


def test_hook_replaced_by_a_symlink_escaping_home_is_visible_in_diff():
    # These two hook behaviors (symlink, pathOutsideHome) were previously
    # covered only by unit tests on the collector, not by anything
    # exercising diff.py against them -- added here per an independent
    # reviewer's suggestion, while the behavior is fresh. A hook that was
    # a real file inside --home, later replaced by a symlink pointing
    # outside it, changes identity (relPath present, then absent) -- so
    # this shows as one hook removed and a new, clearly-flagged one
    # added, rather than matching as "changed". Still visible, which is
    # what matters: pathOutsideHome on the new entry is exactly the
    # signal an operator needs to see.
    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    legit = Component(component_class="hook", name="audit.sh")
    legit.set("path", "/home/u/.hermes/hooks/audit.sh")
    legit.set("relPath", ".hermes/hooks/audit.sh")
    legit.set("sha256", "aaa")
    before_doc.add(legit, "approves")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    escaped = Component(component_class="hook", name="audit.sh")
    escaped.set("path", "/tmp/evil/payload.sh")
    escaped.set("symlink", True)
    escaped.set("pathOutsideHome", True)
    escaped.set("sha256", "bbb")
    after_doc.add(escaped, "approves")
    after = to_cyclonedx(after_doc)

    result = diff_documents(before, after)
    assert result["removed"] == ["hook:.hermes/hooks/audit.sh"]
    assert result["added"] == ["hook:/tmp/evil/payload.sh"]
    assert result["changed"] == []


def test_name_duplicated_in_before_but_unique_in_after_matches_the_persisting_server():
    # Reverse of the case above: one of two same-named servers is
    # removed. The persisting one must still match, not read as
    # "removed + re-added" just because it no longer has a sibling to
    # disambiguate against.
    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://x.example.com"), "uses")
    before_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://y.example.com"), "uses")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://x.example.com"), "uses")
    after = to_cyclonedx(after_doc)

    result = diff_documents(before, after)
    assert result["added"] == []
    assert result["removed"] == ["mcp_server:fs#https://y.example.com"]
    assert result["changed"] == []


def test_three_same_named_servers_only_the_changed_one_shows_up():
    # Three-way disambiguation, not just two: a change to the middle
    # entry must not disturb the other two.
    def build(middle_tls: bool) -> dict:
        doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
        doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://a.example.com"), "uses")
        middle = Component(component_class="mcp_server", name="fs")
        middle.set("endpoint", "https://b.example.com")
        middle.set("tls", middle_tls)
        doc.add(middle, "uses")
        doc.add(Component(component_class="mcp_server", name="fs").set("endpoint", "https://c.example.com"), "uses")
        return to_cyclonedx(doc)

    result = diff_documents(build(True), build(False))
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "mcp_server:fs#https://b.example.com"
    assert change["fields"]["harness-aibom:tls"] == {"before": "True", "after": "False"}


def test_positional_fallback_works_when_entry_order_is_stable():
    # Two same-named services with neither endpoint nor command/args --
    # nothing content-derived to disambiguate on, so position is the last
    # resort. Works correctly as long as the set of entries doesn't
    # change shape between scans.
    def build(second_note: str) -> dict:
        doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
        first = Component(component_class="mcp_server", name="bare")
        first.set("note", "first")
        doc.add(first, "uses")
        second = Component(component_class="mcp_server", name="bare")
        second.set("note", second_note)
        doc.add(second, "uses")
        return to_cyclonedx(doc)

    result = diff_documents(build("second"), build("second-modified"))
    assert result["added"] == []
    assert result["removed"] == []
    [change] = result["changed"]
    assert change["component"] == "mcp_server:bare#1"
    assert change["fields"]["harness-aibom:note"] == {"before": "second", "after": "second-modified"}


def test_positional_fallback_inherent_limit_when_a_third_indistinguishable_entry_is_inserted():
    # Documented limitation, not a bug (SPEC.md §4 / §5): when entries
    # carry nothing to tell them apart, inserting a new, equally
    # undistinguishable one *between* two existing ones shifts every
    # later position -- no scheme could avoid this without some
    # content-derived property to key on instead. This test pins the
    # known, accepted behavior so it can't silently change unnoticed,
    # not because it's the desired outcome.
    before_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    before_doc.add(Component(component_class="mcp_server", name="bare").set("note", "first"), "uses")
    before_doc.add(Component(component_class="mcp_server", name="bare").set("note", "second"), "uses")
    before = to_cyclonedx(before_doc)

    after_doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    after_doc.add(Component(component_class="mcp_server", name="bare").set("note", "first"), "uses")
    after_doc.add(Component(component_class="mcp_server", name="bare").set("note", "inserted"), "uses")
    after_doc.add(Component(component_class="mcp_server", name="bare").set("note", "second"), "uses")
    after = to_cyclonedx(after_doc)

    result = diff_documents(before, after)
    # The genuinely new entry lands at position 2 and reads as "added" --
    # visible, which is what matters.
    assert result["added"] == ["mcp_server:bare#2"]
    assert result["removed"] == []
    # But the original second entry (now shifted to position 1) reads as
    # a false "changed" against the newly-inserted one, since position is
    # all either has to go on.
    [change] = result["changed"]
    assert change["component"] == "mcp_server:bare#1"
    assert change["fields"]["harness-aibom:note"] == {"before": "second", "after": "inserted"}
