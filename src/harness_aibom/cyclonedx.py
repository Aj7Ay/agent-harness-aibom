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


def _relationship_properties(relationships: list[tuple[str, str]]) -> list[dict]:
    return [{"name": "harness-aibom:relationship", "value": f"{verb}:{target}"} for verb, target in relationships]


def _shared_properties(component: Component) -> list[dict]:
    properties = [{"name": "harness-aibom:componentClass", "value": component.component_class}]
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
    return result
