"""Serialize a HarnessDocument (model.py) into CycloneDX 1.6 JSON.

We stay inside the official CycloneDX schema everywhere except one place:
per-component `properties[]` entries named `harness-aibom:<field>`, which
carry facts CycloneDX has no native slot for (a skill's SHA-256, whether an
MCP server enforces TLS, a hook's approval state, ...). Any CycloneDX-aware
tool that ignores unknown property names still gets a valid, useful BOM;
harness-aibom's own diff/validate commands are the only consumers that need
to understand them. See SPEC.md for the full field list per componentClass.
"""

from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone

from . import __version__
from .model import Component, HarnessDocument

SPEC_VERSION = "1.6"
ROOT_BOM_REF = "harness-root"

#: Exact SPDX license identifiers common enough to appear verbatim in a
#: Python package's METADATA `License:` header. Deliberately a small,
#: fixed allowlist checked by *exact* string match, not a normalization
#: attempt (e.g. mapping "Apache 2.0" or "MIT License" -> "Apache-2.0"/
#: "MIT") -- CycloneDX's schema validates `license.id` against the real
#: SPDX license-id enum (confirmed: spdx.SNAPSHOT.schema.json), so
#: guessing a mapping risks emitting an `id` that isn't actually in that
#: enum and failing strict validation. Anything not an exact match here
#: falls back to `license.name` (free text, no enum constraint) instead
#: of being dropped or guessed -- see _license_dict() below.
_KNOWN_SPDX_IDS = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
    "LGPL-2.1-only", "LGPL-3.0-only", "GPL-2.0-only", "GPL-3.0-only",
    "AGPL-3.0-only", "Unlicense", "0BSD", "Python-2.0", "Zlib", "EPL-2.0",
    "CC0-1.0", "Artistic-2.0", "PSF-2.0", "WTFPL",
})


def _license_dict(license_value: str) -> dict:
    if license_value in _KNOWN_SPDX_IDS:
        return {"license": {"id": license_value}}
    return {"license": {"name": license_value}}


def _registry_url_for_purl(purl: str) -> str | None:
    """A registry-page URL for a `pkg:pypi/...`/`pkg:npm/...` purl this
    scanner already produced -- the exact URL shape each registry itself
    publishes (confirmed real, not invented): `pypi.org/project/<name>/`,
    `npmjs.com/package/<name>`. Only these two ecosystems, matching the
    only two this scanner ever emits a purl for (mcp.py/deps.py) --
    never a guess at a URL shape for a purl type this scanner doesn't
    actually produce.
    """
    if purl.startswith("pkg:pypi/"):
        name = purl.removeprefix("pkg:pypi/").split("@", 1)[0]
        return f"https://pypi.org/project/{name}/" if name else None
    if purl.startswith("pkg:npm/"):
        # purl-spec encodes a scoped package's leading "@" as "%40" in
        # the namespace segment (see mcp.py's _purl_for_npm) -- decoded
        # back here since npmjs.com's own URLs use the real "@".
        name = purl.removeprefix("pkg:npm/").split("@", 1)[0].replace("%40", "@")
        return f"https://www.npmjs.com/package/{name}" if name else None
    return None


def _relationship_properties(relationships: list[tuple[str, str]]) -> list[dict]:
    return [{"name": "harness-aibom:relationship", "value": f"{verb}:{target}"} for verb, target in relationships]


def _shared_properties(component: Component) -> list[dict]:
    properties = [{"name": "harness-aibom:componentClass", "value": component.component_class}]
    if component.version:
        # Mirrors the native top-level `version` field (set in
        # _component_dict below) as a property too. Confirmed real gap:
        # `diff.py` only ever compares `properties[]` entries, never a
        # native top-level field directly -- so a version-only change on
        # a component whose version isn't otherwise embedded in some
        # other compared property (a `dependency` with no `purl` because
        # it has no version yet, `model`/`runtime`, ...) was invisible to
        # `diff` even though the field genuinely changed. Additive, same
        # reasoning as hashes[]/purl above: the native field stays the
        # single source of truth for a generic CycloneDX tool, this
        # property is only for harness-aibom's own diff/report.
        properties.append({"name": "harness-aibom:version", "value": component.version})
    properties += [{"name": f"harness-aibom:{k}", "value": v} for k, v in component.properties.items()]
    properties += _relationship_properties(component.relationships)
    return properties


def _component_dict(component: Component) -> dict:
    out: dict = {
        "type": component.cdx_type,
        "bom-ref": component.bom_ref,
        "name": component.name,
    }
    if component.version:
        out["version"] = component.version
    sha256 = component.properties.get("sha256")
    if sha256:
        # Additive, not a replacement: CycloneDX's own native `hashes[]`
        # slot, alongside the existing harness-aibom:sha256 property
        # (which `diff.py`'s FINGERPRINT_FIELDS and identity fallback
        # both key on by that exact name -- moving the digest out of it
        # would break both). A generic CycloneDX/SBOM tool has no reason
        # to know the `harness-aibom:` namespace exists; it does know
        # `hashes[]`.
        out["hashes"] = [{"alg": "SHA-256", "content": sha256}]
    purl = component.properties.get("purl")
    if purl:
        # Confirmed against the real CycloneDX 1.6 schema before writing
        # this: `purl` IS a native top-level field on a *component* (not
        # on a *service* -- services have no purl slot at all, which is
        # exactly why an MCP server's underlying package is its own
        # `dependency` component in the first place, not just a property
        # on the server). Additive alongside the harness-aibom:purl
        # property, same reasoning as hashes[] above.
        out["purl"] = purl
        # externalReferences (v0.6.0): a deterministic registry-page URL
        # derived from the purl this scanner already produced -- the
        # real, standardized URL shape each registry itself uses
        # (pypi.org/project/<name>/, npmjs.com/package/<name>), not a
        # guess or a network lookup. Version-agnostic on purpose: the
        # registry's own current-release page is more useful here than a
        # version-pinned deep link that may 404 once a package is
        # yanked, and simpler to derive correctly.
        registry_url = _registry_url_for_purl(purl)
        if registry_url:
            out["externalReferences"] = [{"type": "distribution", "url": registry_url}]
    license_value = component.properties.get("license")
    if license_value:
        # Additive, same reasoning as hashes[]/purl above. `license` is
        # currently only ever set by collectors/deps.py, from a Python
        # package's own METADATA `License:` header -- see _license_dict()
        # for why this is `id` only on an exact SPDX match, `name`
        # (free text) otherwise, never a guessed normalization.
        out["licenses"] = [_license_dict(license_value)]
    supplier_name = component.properties.get("supplierName")
    supplier_email = component.properties.get("supplierEmail")
    if supplier_name or supplier_email:
        # Same source (METADATA `Author`/`Author-email`, falling back to
        # `Maintainer`/`Maintainer-email` -- see deps.py) promoted into
        # CycloneDX's native `organizationalEntity` shape. Neither field
        # is required by the schema on its own, so either alone is still
        # a valid (if partial) supplier entry.
        supplier: dict = {}
        if supplier_name:
            supplier["name"] = supplier_name
        if supplier_email:
            supplier["contact"] = [{"email": supplier_email}]
        out["supplier"] = supplier
    out["properties"] = _shared_properties(component)
    return out


def _service_dict(component: Component) -> dict:
    # CycloneDX services have no `type` field -- unlike components, there's
    # nothing to map componentClass onto besides the harness-aibom
    # property below.
    out: dict = {
        "bom-ref": component.bom_ref,
        "name": component.name,
    }
    # model_endpoint stores its URL as the component's own `name` (that IS
    # the identifying value); mcp_server stores it as an `endpoint`
    # property. Either way, surface it via CycloneDX's native `endpoints`
    # field too, not just the harness-aibom property.
    endpoint_url = component.properties.get("endpoint") or (
        component.name if component.component_class == "model_endpoint" else None
    )
    if endpoint_url:
        out["endpoints"] = [endpoint_url]
    out["properties"] = _shared_properties(component)
    return out


#: One entry per self-assessed claim this scanner can actually back with
#: data it already collected -- see `_build_declarations()`. Each tuple is
#: (slug, predicate template, counter function). Deliberately narrow (4
#: entries, matching SPEC.md's own "3-5 real ones, not an exhaustive
#: fabricated list" scope) -- every ratio here is a real `len()` over
#: entries already in the document, the same "nothing invented, nothing
#: scored by an opaque model" discipline security.py's own functions
#: already follow. A claim about a category with zero entries in this
#: document is skipped entirely (see `_build_declarations`) rather than
#: emitted as a vacuous, misleading "0 of 0 (100%)".
def _skill_fingerprint_counts(components: list[dict], services: list[dict]) -> tuple[int, int]:
    skills = [c for c in components if _cdx_component_class(c) == "skill"]
    return sum(1 for c in skills if c.get("hashes")), len(skills)


def _mcp_auth_recorded_counts(components: list[dict], services: list[dict]) -> tuple[int, int]:
    servers = [s for s in services if _cdx_component_class(s) == "mcp_server"]
    recorded = sum(
        1
        for s in servers
        if any(p["name"] == "harness-aibom:authConfigured" for p in s.get("properties", []))
    )
    return recorded, len(servers)


def _model_digest_counts(components: list[dict], services: list[dict]) -> tuple[int, int]:
    models = [c for c in components if _cdx_component_class(c) == "model"]
    recorded = sum(
        1 for c in models if any(p["name"] == "harness-aibom:digest" for p in c.get("properties", []))
    )
    return recorded, len(models)


def _dependency_purl_counts(components: list[dict], services: list[dict]) -> tuple[int, int]:
    deps = [c for c in components if _cdx_component_class(c) == "dependency"]
    return sum(1 for c in deps if c.get("purl")), len(deps)


def _cdx_component_class(entry: dict) -> str:
    for prop in entry.get("properties", []):
        if prop["name"] == "harness-aibom:componentClass":
            return prop["value"]
    return "unknown"


_DECLARATION_CLAIMS = (
    (
        "skill-fingerprint-coverage",
        "{found} of {total} discovered skill component(s) carry a native content hash (hashes[]).",
        "Computed by counting `skill` components in this document's own components[] array whose "
        "native `hashes[]` field is present -- sha256_directory() (fingerprint.py) is called for "
        "every skill this scanner's collectors discover, so a skill missing a hash here means the "
        "whole skill directory was unreadable (a permission error), never that hashing was skipped.",
        _skill_fingerprint_counts,
    ),
    (
        "mcp-auth-posture-recorded",
        "{found} of {total} discovered MCP server(s) have harness-aibom:authConfigured explicitly recorded.",
        "collectors/mcp.py sets authConfigured (true or false) for every mcp_server entry it extracts "
        "from a harness's own config file -- a missing value here would mean this scanner's own "
        "extraction code didn't run for that entry, not that auth posture is merely unknown.",
        _mcp_auth_recorded_counts,
    ),
    (
        "model-digest-provenance",
        "{found} of {total} discovered model(s) carry a real content digest (harness-aibom:digest) "
        "from Ollama's own manifest, not just a tag/name.",
        "digest is taken verbatim from Ollama's GET /api/tags response for every model this scanner "
        "finds -- never recomputed or guessed (SPEC.md section 3). A model missing one means Ollama's "
        "own API response didn't include a digest for that entry, not that this scanner failed to look.",
        _model_digest_counts,
    ),
    (
        "dependency-purl-coverage",
        "{found} of {total} discovered dependency component(s) carry a native purl for a generic "
        "SBOM/vulnerability tool to resolve.",
        "purl is set for every Python package deps.py finds a well-formed METADATA `Name`/`Version` "
        "pair for, and for every MCP launcher package mcp.py recognizes (npx/uvx only) -- see SPEC.md "
        "section 2 for the exact derivation.",
        _dependency_purl_counts,
    ),
)


def _build_declarations(result: dict) -> dict | None:
    """A small, narrowly-scoped CycloneDX 1.6 `declarations` block: this
    scanner's own self-assessed claims about facts it can actually verify
    from data already in this exact document -- never a claim about
    anything this scanner doesn't check (no "compliant", no "passed an
    audit"). See SPEC.md's declarations section for the full reasoning
    and the real vendored-schema fields this follows
    (`cyclonedx.schema._res.bom-1.6.SNAPSHOT.schema.json`).

    Returns None (declarations omitted entirely) when this document has
    zero entries in every one of the four categories above -- an empty
    harness scan has nothing honest to self-assess a coverage ratio
    about, and "0 of 0" would look like a clean 100% rather than "not
    applicable".
    """
    components = result.get("components", [])
    services = result.get("services", [])

    claims = []
    evidence = []
    for slug, predicate_template, reasoning, counter in _DECLARATION_CLAIMS:
        found, total = counter(components, services)
        if total == 0:
            continue
        evidence_ref = f"declaration-evidence:{slug}"
        evidence.append({
            "bom-ref": evidence_ref,
            "propertyName": "harness-aibom:coverageEvidence",
            "description": reasoning,
        })
        claims.append({
            "bom-ref": f"declaration-claim:{slug}",
            "target": ROOT_BOM_REF,
            "predicate": predicate_template.format(found=found, total=total),
            "reasoning": reasoning,
            "evidence": [evidence_ref],
        })

    if not claims:
        return None

    return {
        "assessors": [{
            "bom-ref": "declaration-assessor:agent-harness-aibom",
            "thirdParty": False,
            "organization": {"name": "agent-harness-aibom (self-assessment, not a third-party audit)"},
        }],
        "claims": claims,
        "evidence": evidence,
    }


def current_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-host"


def to_cyclonedx(doc: HarnessDocument, deterministic: bool = False) -> dict:
    """Build the full CycloneDX 1.6 document dict for `doc`. Callers decide
    how to serialize it (json.dumps, write to a file, ...).

    `deterministic=True` omits `serialNumber` (a fresh random UUID on
    every call) and `metadata.timestamp` (wall-clock time of the scan).
    Without it, two scans of an *unchanged* box produce two different
    files byte-for-byte, which rules out hashing or signing the AIBOM
    itself as a stable baseline -- everything else already only reflects
    what was actually found on disk, so with both omitted, the same
    harness state always produces the same document.
    """
    root_properties = [
        {"name": "harness-aibom:componentClass", "value": "harness"},
        {"name": "harness-aibom:runtimeKind", "value": doc.runtime_kind},
        {"name": "harness-aibom:hostname", "value": doc.hostname},
    ]
    # Scan warnings used to reach only stderr, never the document itself
    # -- confirmed real: a reviewer found a scan that missed Ollama and
    # couldn't read a skill produced a report indistinguishable from a
    # complete one. One repeated property per warning, same pattern as
    # `harness-aibom:relationship` -- a plain dict would collapse repeats.
    root_properties += [{"name": "harness-aibom:warning", "value": w} for w in doc.warnings]
    root_properties += _relationship_properties(doc.root_relationships)

    components = [c for c in doc.components if not c.is_service]
    services = [c for c in doc.components if c.is_service]

    metadata: dict = {
        "tools": {
            "components": [
                {"type": "application", "name": "agent-harness-aibom", "version": __version__},
            ],
        },
        "component": {
            "type": "application",
            "bom-ref": ROOT_BOM_REF,
            "name": doc.harness_name,
            "properties": root_properties,
        },
    }
    if not deterministic:
        metadata["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    result: dict = {"bomFormat": "CycloneDX", "specVersion": SPEC_VERSION}
    if not deterministic:
        result["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    result["version"] = 1
    result["metadata"] = metadata
    result["components"] = [_component_dict(c) for c in components]
    if services:
        result["services"] = [_service_dict(c) for c in services]
    # A real, multi-level graph, not a flat star: confirmed real complaint
    # -- every dependency edge used to be "harness-root depends on all N
    # components" regardless of what actually declared what, so
    # `harness-root -> mcp_server -> tool` and `model_endpoint -> model`
    # were indistinguishable from `harness-root -> everything` in one
    # unstructured list. Now: one `dependencies[]` entry for the root
    # (only its *direct* children -- runtime, configuration, skills,
    # hooks, secrets surfaces, per HermesCollector/OpenClawCollector's
    # doc.add() calls), plus one more entry per component that itself has
    # children (configuration -> its model_endpoint/mcp_servers,
    # model_endpoint -> its models, mcp_server -> its tools, added via
    # doc.add_child()). dependsOn references bom-refs from *either* array
    # (CycloneDX's dependency graph isn't components-only), so services
    # need no special handling here.
    dependencies = [{"ref": ROOT_BOM_REF, "dependsOn": [target for _verb, target in doc.root_relationships]}]
    for c in doc.components:
        if c.relationships:
            dependencies.append({"ref": c.bom_ref, "dependsOn": [target for _verb, target in c.relationships]})
    result["dependencies"] = dependencies

    declarations = _build_declarations(result)
    if declarations:
        result["declarations"] = declarations
    return result
