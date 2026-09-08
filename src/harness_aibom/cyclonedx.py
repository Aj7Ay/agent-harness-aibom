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


def to_cyclonedx(doc: HarnessDocument) -> dict:
    """Build the full CycloneDX 1.6 document dict for `doc`. Callers decide
    how to serialize it (json.dumps, write to a file, ...)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    root_properties = [
        {"name": "harness-aibom:componentClass", "value": "harness"},
        {"name": "harness-aibom:runtimeKind", "value": doc.runtime_kind},
        {"name": "harness-aibom:hostname", "value": doc.hostname},
    ] + _relationship_properties(doc.root_relationships)

    components = [c for c in doc.components if not c.is_service]
    services = [c for c in doc.components if c.is_service]

    result = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
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
        },
        "components": [_component_dict(c) for c in components],
        # dependencies[].dependsOn references bom-refs from *either* array
        # (CycloneDX's dependency graph isn't components-only), so services
        # stay listed here alongside components with no special handling.
        "dependencies": [
            {"ref": ROOT_BOM_REF, "dependsOn": [c.bom_ref for c in doc.components]},
        ],
    }
    if services:
        result["services"] = [_service_dict(c) for c in services]
    return result
