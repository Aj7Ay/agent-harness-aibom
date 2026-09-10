"""A registry, not a blanket phrase scan. Three times a docstring in this
codebase claimed something the code did not actually do:

- cyclonedx.py once said `purl` has "no top-level slot on a component"
  (false -- it's a real, native CycloneDX field, confirmed against the
  schema and used since v0.2.1).
- report.py's Risk observations section claimed "each observation names
  the exact rule that fired" while the rule name itself was never
  actually rendered (only its free-text summary was) until fixed.
- sign.py claimed cosign signing was "fully offline" -- true for
  `verify-blob`, false for `sign-blob` until the v0.8.3 fix.

A blanket scan for "never"/"always"/"fully" across every docstring
produces mostly noise (most such words are accurate). A registry doesn't:
every time this project writes one of those words into a docstring
describing real behavior, a matching entry goes here, naming the one
real test that actually proves it. That habit -- not a scanner -- is
what would have caught all three claims above before a reviewer did.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

#: (module filename, a short paraphrase of the claim) -> the exact test
#: function name that proves it. Add an entry here whenever a docstring
#: states a "never"/"always"/"fully"/"confirmed"/"guaranteed"-shaped
#: claim about real behavior -- test_every_registered_claim_has_a_live_test()
#: below fails loudly if the named test doesn't actually exist and get
#: collected, so a claim can never quietly point at a typo'd or deleted
#: test name.
CLAIMS: dict[tuple[str, str], str] = {
    ("sign.py", "a sign with the bundled default signing config succeeds fully offline, no TUF fetch needed"):
        "test_sign_blob_default_works_when_tuf_is_unreachable",
    ("sign.py", "verify-blob was already fully offline before v0.8.3, needed no fix"):
        "test_verify_rejects_a_tampered_file",
    ("vex.py", "an empty vulnerabilities array is a real 'checked, clean' result, never conflated with 'never enriched'"):
        "test_enrich_records_checked_clean_when_osv_returns_no_vulns",
    ("vex.py", "a wholesale OSV outage is visible at the document's own root level, not silent"):
        "test_a_failed_query_promotes_a_root_level_warning",
    ("compliance.py", "the JSON output carries the same 'not a compliance claim' disclaimer the text mode has"):
        "test_evaluate_framework_json_result_carries_the_disclaimer",
    ("compliance.py", "no mapping's own text ever uses compliance/pass-fail language"):
        "test_no_mapping_ever_uses_compliance_or_pass_fail_language",
    ("report.py", "no CDN, no JavaScript framework, no external resource the browser would fetch"):
        "test_report_has_no_external_resource_references",
    ("report.py", "a --deterministic scan's report has no render timestamp embedded"):
        "test_report_shows_not_recorded_for_deterministic_scans",
    ("report.py", "render_diff_report() is fully deterministic -- no wall-clock read anywhere in it"):
        "test_diff_report_is_byte_identical_for_two_deterministic_inputs",
    ("cyclonedx.py", "purl is a real, native top-level CycloneDX component field, not harness-aibom-only"):
        "test_dependency_purl_is_a_native_top_level_field",
    ("collectors/secrets.py", "a secret's own value is never read into the output, only its path/mode"):
        "test_no_planted_secret_reaches_any_downstream_command_output",
}


def _collected_test_names() -> set[str]:
    """Every test function name pytest itself actually collects under
    `tests/` -- a real collection run, not a text grep, so a claim can't
    be satisfied by a test name that merely appears in a comment or a
    docstring somewhere.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    names = set()
    for line in result.stdout.splitlines():
        if "::" in line:
            names.add(line.rsplit("::", 1)[-1].split("[")[0])  # strip a parametrize suffix, if any
    return names


def test_every_registered_claim_has_a_live_test():
    collected = _collected_test_names()
    missing = [f"{module} claim {claim!r} -> {test_name!r}"
               for (module, claim), test_name in CLAIMS.items() if test_name not in collected]
    assert not missing, f"registered claims point at a test that doesn't exist or isn't collected: {missing}"


def test_claims_registry_is_never_empty():
    # A trivially-passing empty registry would defeat the whole point --
    # this is the "did someone delete every entry" tripwire.
    assert len(CLAIMS) >= 5
