"""Compliance/framework evidence mapping -- **never** a compliance,
certification, or "pass"/"fail" claim. Every mapping below says only
that this scanner collects real, checkable evidence *toward* a real,
published control or technique ID -- an honest, narrow "evidence
collected" / "partial evidence" / "not assessed" per SPEC.md's own
"never overclaim" discipline (the same one this whole project has
followed since v0.1).

**Every control/technique ID here was fetched from each framework's own
real, canonical, currently-published source before being written down**
-- never recalled from memory or guessed:

- NIST AI RMF: https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/
  (the real Playbook pages for GOVERN/MAP/MEASURE), confirming exact
  control IDs and titles verbatim.
- OWASP Top 10 for LLM Applications (2025):
  https://genai.owasp.org/llm-top-10/ (the real, official list --
  LLM01:2025 through LLM10:2025).
- MITRE ATLAS: https://github.com/mitre-atlas/atlas-data (the actual
  data source ATLAS's own website is built from), confirming real
  tactic/technique IDs (AML.TAxxxx / AML.Txxxx).

**Frameworks this project deliberately did NOT include, and why**: ISO/
IEC 42001 (its actual clause text is paywalled by ISO -- this project
would either have to guess clause numbers from secondary summaries or
buy the standard, neither of which meets this project's "verify against
a real, fetched, canonical source" bar) and SLSA (a build-provenance
framework about how software is *built*, not about what an already-
deployed agent harness *has access to* -- this scanner reads a running
harness's filesystem/config, so SLSA's own levels don't have a
meaningful evidence source here without inventing one). Both are listed
here, not silently dropped, exactly like every other deliberate
deferral in this project's history.
"""

from __future__ import annotations

from . import security


def _entries(bom: dict) -> list[dict]:
    return bom.get("components", []) + bom.get("services", [])


def _properties(entry: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in entry.get("properties", [])}


def _component_class(entry: dict) -> str:
    return _properties(entry).get("harness-aibom:componentClass", "unknown")


def _count_class(bom: dict, cls: str) -> int:
    return sum(1 for e in _entries(bom) if _component_class(e) == cls)


def _inventory_count(bom: dict) -> int:
    return len(_entries(bom))


def _dependency_evidence(bom: dict) -> int:
    return _count_class(bom, "dependency")


def _tool_capability_evidence(bom: dict) -> int:
    return _count_class(bom, "tool")


def _secrets_evidence(bom: dict) -> int:
    return _count_class(bom, "secrets_surface")


def _credential_posture_evidence(bom: dict) -> int:
    """MCP servers with `authConfigured` explicitly recorded (either
    value) plus secrets-surface entries -- the two places this scanner
    actually records something about credential exposure."""
    servers = [e for e in _entries(bom) if _component_class(e) == "mcp_server"]
    recorded = sum(1 for s in servers if "harness-aibom:authConfigured" in _properties(s))
    return recorded + _count_class(bom, "secrets_surface")


def _security_rule_count(bom: dict) -> int:
    return len(security.compute_risk_observations(bom))


#: framework key -> {display_name, source_note, mappings: [...]}. Each
#: mapping's `ceiling` is the *most* this scanner could ever honestly
#: claim for that control (chosen once, deliberately, never per-document)
#: -- `evaluate_framework()` downgrades it to "not assessed" whenever
#: this specific document has zero relevant entries, so a claim is never
#: shown about evidence that doesn't actually exist in front of the reader.
FRAMEWORKS = {
    "nist-ai-rmf": {
        "display_name": "NIST AI Risk Management Framework (AI RMF 1.0)",
        "source_note": (
            "Control IDs and titles verified verbatim against the real, published NIST AI RMF "
            "Playbook (airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/), fetched directly."
        ),
        "mappings": [
            {
                "control_id": "GOVERN 1.6",
                "control_title": "Mechanisms are in place to inventory AI systems and are resourced "
                                  "according to organizational risk priorities.",
                "ceiling": "evidence collected",
                "rationale": "Every `harness-aibom scan` IS an AI-system inventory action -- this "
                             "document's own components[]/services[] arrays are that inventory.",
                "count_fn": _inventory_count,
            },
            {
                "control_id": "GOVERN 6.1",
                "control_title": "Policies and procedures are in place that address AI risks associated "
                                  "with third-party entities, including risks of infringement of a third "
                                  "party's intellectual property or other rights.",
                "ceiling": "partial evidence",
                "rationale": "Records real third-party facts (native license, supplier, purl) for every "
                             "discovered Python/MCP-launcher dependency -- this scanner records the facts "
                             "a policy would need, it does not itself implement or verify one.",
                "count_fn": _dependency_evidence,
            },
            {
                "control_id": "MAP 4.1",
                "control_title": "Approaches for mapping AI technology and legal risks of its components "
                                  "-- including the use of third-party data or software -- are in place, "
                                  "followed, and documented.",
                "ceiling": "evidence collected",
                "rationale": "The real dependency graph (configuration -> mcp_server -> tool, plus "
                             "standalone `dependency` components) is a documented map of third-party "
                             "components and their risk-relevant properties (purl, version pinning, license).",
                "count_fn": _dependency_evidence,
            },
            {
                "control_id": "MEASURE 2.7",
                "control_title": "AI system security and resilience -- as identified in the MAP function "
                                  "-- are evaluated and documented.",
                "ceiling": "partial evidence",
                "rationale": "security.py's fixed, named risk-rule set (world-readable secrets, "
                             "plaintext/unauthenticated MCP transport, unpinned launchers, missing model "
                             "digests) is a real, explainable evaluation -- but a fixed rule set, never a "
                             "comprehensive security assessment.",
                "count_fn": _security_rule_count,
            },
        ],
    },
    "owasp-llm-top10-2025": {
        "display_name": "OWASP Top 10 for LLM Applications (2025)",
        "source_note": (
            "Verified against the real, official list published at genai.owasp.org/llm-top-10/, "
            "fetched directly (LLM01:2025 through LLM10:2025)."
        ),
        "mappings": [
            {
                "control_id": "LLM03:2025",
                "control_title": "Supply Chain",
                "ceiling": "evidence collected",
                "rationale": "Native purl/license/supplier on every `dependency` component (Python "
                             "packages and MCP launcher packages), plus security.py's "
                             "unpinned_mcp_launcher/python_package_missing_version rules.",
                "count_fn": _dependency_evidence,
            },
            {
                "control_id": "LLM06:2025",
                "control_title": "Excessive Agency",
                "ceiling": "partial evidence",
                "rationale": "`tool` components' name-only riskClass heuristic (read/write/exec/network) "
                             "and the capability matrix show what an agent's configured tools *could* "
                             "reach -- never a runtime authorization or permission check.",
                "count_fn": _tool_capability_evidence,
            },
            {
                "control_id": "LLM02:2025",
                "control_title": "Sensitive Information Disclosure",
                "ceiling": "partial evidence",
                "rationale": "secrets_surface discovery (world-readable files, credential-shaped "
                             "filenames) at two confidence tiers -- location and permissions only, file "
                             "contents never read (SPEC.md section 3).",
                "count_fn": _secrets_evidence,
            },
        ],
    },
    "mitre-atlas": {
        "display_name": "MITRE ATLAS",
        "source_note": (
            "Tactic/technique IDs verified against the real, canonical ATLAS data "
            "(github.com/mitre-atlas/atlas-data), fetched directly."
        ),
        "mappings": [
            {
                "control_id": "AML.T0010",
                "control_title": "AI Supply Chain Compromise",
                "ceiling": "partial evidence",
                "rationale": "Records the exact facts a defender would check for this technique (purl, "
                             "version pinning, license/supplier) for every dependency -- does not itself "
                             "detect a compromised package.",
                "count_fn": _dependency_evidence,
            },
            {
                "control_id": "AML.T0055",
                "control_title": "Unsecured Credentials",
                "ceiling": "partial evidence",
                "rationale": "secrets_surface world-readability/confidence tiers plus MCP servers' "
                             "recorded authConfigured posture -- location/permissions and configuration "
                             "facts only, never credential contents.",
                "count_fn": _credential_posture_evidence,
            },
            {
                "control_id": "AML.T0007",
                "control_title": "Discover AI Artifacts",
                "ceiling": "evidence collected",
                "rationale": "This AIBOM itself is the artifact inventory a defender would use to "
                             "understand what this technique could discover on this box -- not a live "
                             "detection of the technique actually being performed.",
                "count_fn": _inventory_count,
            },
        ],
    },
}


#: The exact caveat the text-format output (cli.py's `_run_compliance`)
#: already leads with -- also carried on the dict itself (v0.9.1) so a
#: caller reading only the JSON (a dashboard, a CI job, `--format json`)
#: still gets it. Before this fix, the JSON's `sourceNote` covered ID
#: *provenance* ("verified against the real, canonical source") only --
#: it said nothing about the mapping not being a compliance verdict, the
#: one sentence a machine consumer is the most likely audience to need
#: and the least likely to see, since it isn't the one that reads the
#: text-mode header.
#: Deliberately avoids the literal words this project's own
#: `test_no_mapping_ever_uses_compliance_or_pass_fail_language` bans from
#: appearing ANYWHERE in a mapping's text (a blanket substring check, not
#: aware of negation) -- an earlier draft of this exact sentence said
#: "never 'compliant' or 'pass'", which technically never claims either
#: one but still contains both words literally. Says the same thing
#: without them.
DISCLAIMER = (
    "This is an evidence mapping, not a compliance or certification claim. "
    "Statuses are limited to 'evidence collected', 'partial evidence', or 'not assessed'."
)


def evaluate_framework(bom: dict, framework: str) -> dict:
    """The evidence mapping for one framework against `bom`. Raises
    ValueError for an unknown framework key -- callers (cli.py) turn
    that into a clean, listed error rather than a traceback.
    """
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r} -- expected one of {sorted(FRAMEWORKS)}")
    fw = FRAMEWORKS[framework]
    mappings = []
    for m in fw["mappings"]:
        count = m["count_fn"](bom)
        status = m["ceiling"] if count > 0 else "not assessed"
        mappings.append({
            "controlId": m["control_id"],
            "controlTitle": m["control_title"],
            "status": status,
            "rationale": m["rationale"],
            "evidenceCount": count,
        })
    return {
        "framework": framework,
        "displayName": fw["display_name"],
        "disclaimer": DISCLAIMER,
        "sourceNote": fw["source_note"],
        "mappings": mappings,
    }
