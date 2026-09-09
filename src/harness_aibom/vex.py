"""Vulnerability enrichment via OSV.dev -- a separate, opt-in, network-
requiring step, deliberately never part of `scan` (which stays fully
offline). See SPEC.md's vulnerability/VEX section for the reasoning.

**Real, public, no-auth API, confirmed directly against the live
service before writing a single line of this module** (not guessed from
memory or documentation alone):

    POST https://api.osv.dev/v1/query
    Body: {"package": {"purl": "pkg:pypi/pyyaml@5.3"}}

confirmed to return a real record for a known-vulnerable version
(`GHSA-6757-jp84-gxfx` / `CVE-2020-1747`, PyYAML's real 2020
arbitrary-code-execution advisory) with this exact shape:

    {"vulns": [{
        "id": "GHSA-6757-jp84-gxfx",
        "summary": "...", "details": "...",
        "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
        "modified": "...", "published": "...",
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-20"], ...},
        "references": [{"type": "ADVISORY", "url": "..."}, ...],
        "affected": [{"package": {...}, "ranges": [...], "versions": [...]}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/.../A:N"}],
    }]}

and confirmed to return a bare `{}` (no "vulns" key at all) for a
version with zero known vulnerabilities (`pkg:pypi/requests@2.34.2`,
the real latest release as of this scan) -- so this module treats
*only* a present, non-empty "vulns" list as "found something"; anything
else (missing key, empty list) is "checked, none found", never
conflated with "not checked at all" (see `VulnScanResult` below).
`https://osv.dev/vulnerability/<id>` was also confirmed to be a real,
live page (HTTP 200) for the id above, so it's used verbatim as this
module's CycloneDX `vulnerability.source.url`.

The CycloneDX 1.6 `vulnerability`/`rating`/`affects` shapes this module
emits were read directly out of this project's own vendored validator
dependency (`cyclonedx.schema._res.bom-1.6.SNAPSHOT.schema.json`, the
same schema `tests/test_cyclonedx_schema.py` already validates every
other document against) -- not guessed. In particular: `cwes[]` is a
bare array of positive integers (not the string "CWE-20" OSV itself
uses), `rating.method` is a closed enum (`CVSSv2`/`CVSSv3`/`CVSSv31`/
`CVSSv4`/`OWASP`/`SSVC`/`other`), and `affects[].ref` is the only
required field of an `affects` entry.
"""

from __future__ import annotations

import copy
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

QueryFn = Callable[[str], list[dict]]

#: GitHub Security Advisory's own qualitative severity scale, exactly as
#: it comes back in OSV's `database_specific.severity` field (confirmed
#: real values from a live query: CRITICAL, HIGH, MODERATE, LOW) mapped
#: onto CycloneDX 1.6's own `severity` enum (confirmed from the vendored
#: schema: critical/high/medium/low/info/none/unknown). Never guessed --
#: only mapped when OSV's own value matches one of these four exactly.
_OSV_TO_CDX_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
}

_CWE_ID_RE = re.compile(r"^CWE-(\d+)$")


def default_query(purl: str, timeout: int = 10) -> list[dict]:
    """POST the real OSV.dev query endpoint for one purl. Raises
    (urllib.error.URLError/HTTPError, TimeoutError, json errors) on any
    failure -- callers must catch and record that as "check failed", not
    silently treat it as "no vulnerabilities found". That distinction is
    the entire point of this module; see `enrich_bom_with_vulnerabilities`.
    """
    body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed, public, documented endpoint
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("vulns", [])


def _cvss_method(vector: str) -> str:
    """`"CVSS:3.1/..."` -> `"CVSSv31"`, matching the exact closed enum
    CycloneDX 1.6 validates `rating.method` against. Anything OSV might
    send that isn't one of the four CVSS major/minor versions this
    project has actually observed falls back to `"other"` rather than a
    guessed new enum value.
    """
    if vector.startswith("CVSS:3.0"):
        return "CVSSv3"
    if vector.startswith("CVSS:3.1"):
        return "CVSSv31"
    if vector.startswith("CVSS:2"):
        return "CVSSv2"
    if vector.startswith("CVSS:4"):
        return "CVSSv4"
    return "other"


def _ratings_from_osv(vuln: dict) -> list[dict]:
    """Real CVSS vectors only -- OSV's own `severity[]` array (numeric
    CVSS score is deliberately never computed from the vector by this
    module: that would mean re-implementing the CVSS scoring formula
    ourselves and risking getting it subtly wrong, the same reasoning
    `sign.py` never re-implements signature verification). The
    `database_specific.severity` qualitative label is folded in only
    when at least one real CVSS vector exists to attach it to; with no
    vector at all there's nothing to rate CycloneDX-style, so nothing is
    fabricated.
    """
    ratings = []
    qualitative = (vuln.get("database_specific") or {}).get("severity")
    cdx_severity = _OSV_TO_CDX_SEVERITY.get(qualitative)
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        if not score:
            continue
        rating: dict = {
            "source": {"name": "OSV"},
            "method": _cvss_method(score),
            "vector": score,
        }
        if cdx_severity:
            rating["severity"] = cdx_severity
        ratings.append(rating)
    return ratings


def _cwes_from_osv(vuln: dict) -> list[int]:
    ids = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    out = []
    for cwe in ids:
        m = _CWE_ID_RE.match(str(cwe))
        if m:
            out.append(int(m.group(1)))
    return out


def _advisories_from_osv(vuln: dict) -> list[dict]:
    return [
        {"url": ref["url"]}
        for ref in vuln.get("references") or []
        if ref.get("type") == "ADVISORY" and ref.get("url")
    ]


def _build_vulnerability(vuln: dict, ref: str) -> dict:
    """One real CycloneDX 1.6 `vulnerability` entry for `vuln` (OSV's own
    record, verbatim field names -- see this module's docstring),
    affecting the component at bom-ref `ref`. Every field here either
    comes straight from OSV's response or is a schema-required wrapper
    around one (`source`, `affects`) -- nothing is invented.
    """
    vid = vuln["id"]
    out: dict = {
        "id": vid,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
        "affects": [{"ref": ref}],
    }
    if vuln.get("summary"):
        out["description"] = vuln["summary"]
    if vuln.get("details"):
        out["detail"] = vuln["details"]
    if vuln.get("published"):
        out["published"] = vuln["published"]
    if vuln.get("modified"):
        out["updated"] = vuln["modified"]
    ratings = _ratings_from_osv(vuln)
    if ratings:
        out["ratings"] = ratings
    cwes = _cwes_from_osv(vuln)
    if cwes:
        out["cwes"] = cwes
    advisories = _advisories_from_osv(vuln)
    if advisories:
        out["advisories"] = advisories
    return out


@dataclass
class VulnScanResult:
    """Explicit accounting of what was actually checked, matching this
    project's own COLLECTIBLE_CLASSES/NOT_YET_COLLECTED discipline
    (security.py) for the same reason: a "0 vulnerabilities" result must
    never look identical to "the OSV query itself failed" or to "this
    component had no purl to check in the first place". All three are
    real, distinct outcomes and are kept as three separate lists here.
    """

    checked: list[str] = field(default_factory=list)  # purls successfully queried (found or not)
    failed: dict[str, str] = field(default_factory=dict)  # purl -> error string, query itself failed
    vulnerable_purls: list[str] = field(default_factory=list)  # subset of `checked` with >=1 real finding

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerable_purls)


def enrich_bom_with_vulnerabilities(bom: dict, query: QueryFn = default_query) -> tuple[dict, VulnScanResult]:
    """Query OSV.dev for every component that carries a native CycloneDX
    `purl` field (today, only this project's `dependency` components --
    see cyclonedx.py) and populate the document's native `vulnerabilities[]`
    array with real OSV records. Returns a *new* dict (the input is never
    mutated) plus a `VulnScanResult` describing exactly what happened.

    Never raises for a single failed query -- one purl OSV can't reach or
    doesn't recognize doesn't abort the whole enrichment, same "missing
    pieces are never fatal" discipline `scan` itself already follows for
    a missing `hermes`/unreachable Ollama. Every component actually
    queried gets a `harness-aibom:vulnCheck` property (`"checked"` or
    `"failed"`) recording that fact on the document itself, not just in
    this function's return value -- so `report`/anyone reading the raw
    JSON later can still tell "checked, clean" apart from "never checked"
    or "checking it failed" without re-running this command.
    """
    out = copy.deepcopy(bom)
    result = VulnScanResult()
    vulns_by_id: dict[str, dict] = {}

    for comp in out.get("components", []):
        purl = comp.get("purl")
        if not purl:
            continue
        try:
            vulns = query(purl)
        except Exception as exc:  # noqa: BLE001 - any network/parse failure, recorded not raised
            result.failed[purl] = str(exc)
            comp.setdefault("properties", []).append({"name": "harness-aibom:vulnCheck", "value": "failed"})
            continue

        result.checked.append(purl)
        comp.setdefault("properties", []).append({"name": "harness-aibom:vulnCheck", "value": "checked"})
        if vulns:
            result.vulnerable_purls.append(purl)
        for vuln in vulns:
            vid = vuln.get("id")
            if not vid:
                continue
            entry = _build_vulnerability(vuln, comp["bom-ref"])
            if vid in vulns_by_id:
                # Two different components affected by the same published
                # vulnerability (e.g. the same package pinned in two
                # site-packages directories, both vulnerable) -- merge
                # affects[] rather than emitting the same vulnerability
                # id twice, which cyclonedx-python-lib's strict validator
                # would still accept but no reasonable consumer expects.
                existing_refs = {a["ref"] for a in vulns_by_id[vid]["affects"]}
                if comp["bom-ref"] not in existing_refs:
                    vulns_by_id[vid]["affects"].append({"ref": comp["bom-ref"]})
            else:
                vulns_by_id[vid] = entry

    if vulns_by_id:
        out["vulnerabilities"] = list(vulns_by_id.values())
    return out, result
