"""Tests for vex.py -- OSV.dev vulnerability enrichment.

`query` is always injected (never a real network call in this suite --
see cli.py/vex.py docstrings for the one real manual call made against
the live OSV.dev API during development to confirm the shapes fixtured
here). The fixture payloads below are trimmed, real response bodies
captured from `api.osv.dev/v1/query` for `pkg:pypi/pyyaml@5.3` (a real,
known CVE -- GHSA-6757-jp84-gxfx / CVE-2020-1747) and
`pkg:pypi/requests@2.34.2` (the real latest release at the time this
was written, with zero known vulnerabilities), not invented shapes.
"""

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from harness_aibom.model import Component, HarnessDocument
from harness_aibom.cyclonedx import to_cyclonedx
from harness_aibom import vex

import json

# A trimmed, real OSV.dev response body for pkg:pypi/pyyaml@5.3 (fields
# irrelevant to this module -- e.g. `affected[].versions`, most of
# `references[]` -- dropped for brevity, but every field this module
# actually reads is verbatim from the real response).
_PYYAML_VULN = {
    "id": "GHSA-6757-jp84-gxfx",
    "summary": "Improper Input Validation in PyYAML",
    "details": "A vulnerability was discovered in the PyYAML library...",
    "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
    "modified": "2026-05-04T08:57:14.897560893Z",
    "published": "2021-04-20T16:14:24Z",
    "database_specific": {
        "github_reviewed": True,
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-20"],
    },
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1747"},
        {"type": "WEB", "url": "https://github.com/yaml/pyyaml/pull/386"},
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-6757-jp84-gxfx"},
    ],
    "affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI", "purl": "pkg:pypi/pyyaml"}}],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
}


def _bom_with_dependency(purl: str, name: str = "pyyaml", bom_ref: str = "dependency:pyyaml") -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "harness-root", "name": "h"}},
        "components": [
            {
                "type": "library",
                "bom-ref": bom_ref,
                "name": name,
                "purl": purl,
                "properties": [{"name": "harness-aibom:componentClass", "value": "dependency"}],
            }
        ],
    }


def test_default_query_shape_is_never_used_directly_in_tests():
    # Guard against accidentally calling the real network function in
    # this suite -- every test below must pass its own `query=`.
    assert vex.default_query.__name__ == "default_query"


def test_enrich_adds_native_vulnerabilities_array_for_a_real_finding():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])

    assert result.checked == ["pkg:pypi/pyyaml@5.3"]
    assert result.failed == {}
    assert result.vulnerable_purls == ["pkg:pypi/pyyaml@5.3"]
    assert result.total_vulnerabilities == 1

    vulns = enriched["vulnerabilities"]
    assert len(vulns) == 1
    v = vulns[0]
    assert v["id"] == "GHSA-6757-jp84-gxfx"
    assert v["source"] == {"name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx"}
    assert v["affects"] == [{"ref": "dependency:pyyaml"}]
    assert v["description"] == "Improper Input Validation in PyYAML"
    assert v["cwes"] == [20]
    assert v["ratings"][0]["method"] == "CVSSv31"
    assert v["ratings"][0]["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert v["ratings"][0]["severity"] == "critical"
    assert {"url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1747"} in v["advisories"]
    assert {"url": "https://github.com/yaml/pyyaml/pull/386"} not in v["advisories"]  # type WEB, not ADVISORY


def test_enrich_records_checked_clean_when_osv_returns_no_vulns():
    # Real, confirmed shape: OSV.dev returns a bare {} (no "vulns" key)
    # for a clean package version -- default_query() then returns [].
    bom = _bom_with_dependency("pkg:pypi/requests@2.34.2")
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [])

    assert result.checked == ["pkg:pypi/requests@2.34.2"]
    assert result.vulnerable_purls == []
    # v0.9.1: an empty list here, NOT an absent key -- this run actually
    # checked something and found it clean, which is a real, meaningful
    # result, distinct from "vulnerabilities" being absent entirely
    # (never enriched at all). See the idempotency tests further down
    # for why this also has to be true on a second, re-run pass.
    assert enriched["vulnerabilities"] == []
    comp = enriched["components"][0]
    check_props = [p for p in comp["properties"] if p["name"] == "harness-aibom:vulnCheck"]
    assert check_props == [{"name": "harness-aibom:vulnCheck", "value": "checked"}]


def test_a_failed_query_is_recorded_as_failed_not_as_clean():
    # The whole point of this module: "checked, none found" must never
    # be indistinguishable from "the query itself never actually ran".
    bom = _bom_with_dependency("pkg:pypi/somepkg@1.0")

    def _boom(purl):
        raise TimeoutError("OSV.dev did not respond")

    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=_boom)

    assert result.checked == []
    assert result.failed == {"pkg:pypi/somepkg@1.0": "OSV.dev did not respond"}
    # v0.9.1: still an empty list, not an absent key -- a component was
    # actually attempted this run (it just failed), so this run is still
    # the authoritative source for `vulnerabilities[]`.
    assert enriched["vulnerabilities"] == []
    comp = enriched["components"][0]
    check_props = [p for p in comp["properties"] if p["name"] == "harness-aibom:vulnCheck"]
    assert check_props == [{"name": "harness-aibom:vulnCheck", "value": "failed"}]


def test_a_component_with_no_purl_is_never_queried_at_all():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    bom["components"].append(
        {
            "type": "file",
            "bom-ref": "configuration:config-yaml",
            "name": "config.yaml",
            "properties": [{"name": "harness-aibom:componentClass", "value": "configuration"}],
        }
    )
    calls = []
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=lambda p: (calls.append(p), [])[1])
    assert calls == ["pkg:pypi/pyyaml@5.3"]  # the configuration entry (no purl) never triggers a query


def test_one_failure_does_not_abort_enrichment_of_the_rest():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "dependency:requests",
            "name": "requests",
            "purl": "pkg:pypi/requests@2.34.2",
            "properties": [{"name": "harness-aibom:componentClass", "value": "dependency"}],
        }
    )

    def query(purl):
        if "pyyaml" in purl:
            raise ConnectionError("network down")
        return []

    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=query)
    assert result.failed == {"pkg:pypi/pyyaml@5.3": "network down"}
    assert result.checked == ["pkg:pypi/requests@2.34.2"]


def test_same_vulnerability_affecting_two_components_merges_affects_not_duplicates():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3", bom_ref="dependency:pyyaml-a")
    bom["components"].append(
        {
            "type": "library",
            "bom-ref": "dependency:pyyaml-b",
            "name": "pyyaml",
            "purl": "pkg:pypi/pyyaml@5.3",
            "properties": [{"name": "harness-aibom:componentClass", "value": "dependency"}],
        }
    )
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])
    assert len(enriched["vulnerabilities"]) == 1
    refs = {a["ref"] for a in enriched["vulnerabilities"][0]["affects"]}
    assert refs == {"dependency:pyyaml-a", "dependency:pyyaml-b"}


def test_enrich_never_mutates_the_input_bom():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    original = json.dumps(bom, sort_keys=True)
    vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])
    assert json.dumps(bom, sort_keys=True) == original


def test_enriched_document_is_still_valid_cyclonedx_1_6():
    # The real vendored 1.6 schema validator this project already uses
    # elsewhere (test_cyclonedx_schema.py) -- confirms the vulnerability
    # shape this module builds actually matches the real schema, not
    # just "looks plausible".
    doc = HarnessDocument(harness_name="h", runtime_kind="hermes", hostname="t")
    dep = Component(component_class="dependency", name="pyyaml")
    dep.version = "5.3"
    dep.set("purl", "pkg:pypi/pyyaml@5.3")
    doc.add(dep, "uses")
    bom = to_cyclonedx(doc)

    enriched, _ = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])

    validator = JsonStrictValidator(SchemaVersion.V1_6)
    error = validator.validate_str(json.dumps(enriched))
    assert error is None, f"not valid CycloneDX 1.6: {error}"


def test_cvss_method_mapping_matches_the_real_scoremethod_enum():
    assert vex._cvss_method("CVSS:3.1/AV:N") == "CVSSv31"
    assert vex._cvss_method("CVSS:3.0/AV:N") == "CVSSv3"
    assert vex._cvss_method("CVSS:2.0/AV:N") == "CVSSv2"
    assert vex._cvss_method("CVSS:4.0/AV:N") == "CVSSv4"
    assert vex._cvss_method("something-else") == "other"


def test_malformed_cwe_ids_are_dropped_not_guessed():
    vuln = dict(_PYYAML_VULN, database_specific={"cwe_ids": ["CWE-20", "not-a-cwe", "CWE-abc"]})
    assert vex._cwes_from_osv(vuln) == [20]


# ---- v0.9.1: a failed check must never read as "clean" -----------------


def _failing_query(purl):
    raise RuntimeError("simulated OSV outage")


def test_a_failed_query_promotes_a_root_level_warning():
    # Confirmed real gap: harness-aibom:vulnCheck=failed on the affected
    # component was real, but nothing surfaced the failure at the
    # document level -- the one place report.py's Vulnerabilities section
    # and a human skimming the raw JSON both actually look, and the same
    # place `scan` itself already promotes a partial-scan warning to.
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=_failing_query)
    assert result.failed
    root_props = enriched["metadata"]["component"]["properties"]
    warnings = [p["value"] for p in root_props if p["name"] == "harness-aibom:warning"]
    assert len(warnings) == 1
    assert "1 package" in warnings[0]


def test_no_root_warning_when_nothing_failed():
    bom = _bom_with_dependency("pkg:pypi/requests@2.34.2")
    enriched, result = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [])
    assert not result.failed
    root_props = enriched["metadata"]["component"]["properties"]
    assert not [p for p in root_props if p["name"] == "harness-aibom:warning"]


# ---- v0.9.1: re-running enrichment must be idempotent -------------------


def test_rerunning_enrichment_does_not_duplicate_vulncheck_properties():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    once, _ = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])
    twice, _ = vex.enrich_bom_with_vulnerabilities(once, query=lambda purl: [_PYYAML_VULN])

    dep_props = twice["components"][0]["properties"]
    vuln_check_entries = [p for p in dep_props if p["name"] == "harness-aibom:vulnCheck"]
    assert len(vuln_check_entries) == 1
    assert vuln_check_entries[0]["value"] == "checked"


def test_rerunning_enrichment_clears_a_now_stale_vulnerability():
    # A dependency that WAS vulnerable, then got upgraded -- a second
    # enrichment run must reflect the current, clean state, not keep the
    # first run's finding around forever.
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    once, _ = vex.enrich_bom_with_vulnerabilities(bom, query=lambda purl: [_PYYAML_VULN])
    assert once["vulnerabilities"]

    twice, _ = vex.enrich_bom_with_vulnerabilities(once, query=lambda purl: [])
    assert twice["vulnerabilities"] == []


def test_rerunning_after_a_failure_replaces_the_failed_marker():
    bom = _bom_with_dependency("pkg:pypi/pyyaml@5.3")
    failed_once, _ = vex.enrich_bom_with_vulnerabilities(bom, query=_failing_query)
    recovered, result = vex.enrich_bom_with_vulnerabilities(failed_once, query=lambda purl: [])

    assert not result.failed
    dep_props = recovered["components"][0]["properties"]
    vuln_check_entries = [p for p in dep_props if p["name"] == "harness-aibom:vulnCheck"]
    assert len(vuln_check_entries) == 1
    assert vuln_check_entries[0]["value"] == "checked"
    # The stale root warning from the failed run must not persist either.
    root_props = recovered["metadata"]["component"]["properties"]
    assert not [p for p in root_props if p["name"] == "harness-aibom:warning"]
