"""Table-driven sweep over every hook-output shape found across this
project's history -- confirmed real course-material text, and every shape
an independent reviewer's testing surfaced (some of which broke the
parser at the time, including one regression this project shipped and
then fixed). Consolidated here, in one place, specifically so a future
change to `_collect_hooks` gets checked against all of them at once
instead of one report at a time -- which is exactly the gap that let the
v0.1.9 regression (a fix for one shape silently broke a different,
already-working shape) reach a release.

Each case is (label, doctor_output, expected) where `expected` is a list
of (hook_name, approval_status, content_changed_since_approval_or_None)
tuples, in the order the hooks were found.
"""

from pathlib import Path

import pytest

from harness_aibom.collectors.hermes import HermesCollector
from harness_aibom.model import HarnessDocument

FIXTURE_HOME = Path(__file__).parent / "fixtures" / "hermes_home"

CASES = [
    (
        "no hooks configured (confirmed real text from a live box)",
        "No shell hooks configured — nothing to check.\n",
        [],
    ),
    (
        "two hooks, no status lines at all (original baseline shape)",
        "✓ allowlisted (approved 2026-08-03) numbat-pre-tool.sh\n✗ not allowlisted stray-hook.sh\n",
        [
            ("numbat-pre-tool.sh", "allowlisted", None),
            ("stray-hook.sh", "not_allowlisted", None),
        ],
    ),
    (
        "marker-prefixed no-name status line (confirmed real course-material text)",
        "✓ allowlisted (approved 2026-08-03) numbat-pre-tool.sh\n✓ script unchanged since approval\n",
        [("numbat-pre-tool.sh", "allowlisted", False)],
    ),
    (
        "plain indented no-marker status line",
        "✓ allowlisted (approved 2026-08-03) numbat-pre-tool.sh\n  script unchanged since approval\n",
        [("numbat-pre-tool.sh", "allowlisted", False)],
    ),
    (
        "no-marker status line repeating the script name",
        "✓ pre-commit.sh allowlisted (approved 2026-08-14)\n  pre-commit.sh CHANGED since approval\n",
        [("pre-commit.sh", "allowlisted", True)],
    ),
    (
        "combined single line: marker + name + status together (the v0.1.9 regression)",
        (
            "✓ pre-commit.sh allowlisted (unchanged since approval)\n"
            "✗ evil-payload.py allowlisted but CHANGED since approval\n"
        ),
        [
            ("pre-commit.sh", "allowlisted", False),
            ("evil-payload.py", "not_allowlisted", True),
        ],
    ),
]


@pytest.mark.parametrize("label,output,expected", CASES, ids=[c[0] for c in CASES])
def test_hook_output_shape(label, output, expected):
    def run(argv):
        if argv == ["hermes", "--version"]:
            raise FileNotFoundError()
        if argv == ["hermes", "hooks", "doctor"]:
            return output
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    hooks = [c for c in doc.components if c.component_class == "hook"]
    actual = [
        (h.name, h.properties.get("approvalStatus"), h.properties.get("contentChangedSinceApproval"))
        for h in hooks
    ]
    # properties are stored as strings; normalize the expected bools the
    # same way Component.set() does, so the table above can stay readable.
    expected_normalized = [
        (name, status, None if changed is None else str(changed)) for name, status, changed in expected
    ]
    assert actual == expected_normalized


def test_marker_lines_with_no_extractable_hooks_warns():
    def run(argv):
        if argv == ["hermes", "--version"]:
            raise FileNotFoundError()
        if argv == ["hermes", "hooks", "doctor"]:
            return "✓ a format this parser has never seen before\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    assert [c for c in doc.components if c.component_class == "hook"] == []
    assert any("no hook components could be extracted" in w for w in doc.warnings)


def test_no_hooks_configured_produces_no_misleading_warning():
    def run(argv):
        if argv == ["hermes", "--version"]:
            raise FileNotFoundError()
        if argv == ["hermes", "hooks", "doctor"]:
            return "No shell hooks configured — nothing to check.\n"
        raise AssertionError(f"unexpected command {argv}")

    collector = HermesCollector(home=FIXTURE_HOME, run=run, fetch=lambda url: {"models": []})
    doc = HarnessDocument(harness_name="hermes@test", runtime_kind="hermes", hostname="test")
    collector.collect(doc)

    hook_warnings = [w for w in doc.warnings if "hook" in w.lower()]
    assert hook_warnings == []
