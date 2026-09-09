"""Core in-memory data model for a Harness AIBOM, independent of the
CycloneDX serialization in cyclonedx.py. See SPEC.md for the reasoning
behind the component taxonomy and relationship vocabulary defined here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: The fixed vocabulary of relationship verbs. Keep this small and closed --
#: every verb here must be meaningful to diff.py and to a human reading the
#: harness-aibom:relationship properties in the JSON output.
RELATIONSHIP_VERBS = {"uses", "loads", "invokes", "executes", "accesses", "approves", "pulls"}

#: componentClass values that belong in CycloneDX's top-level `services[]`
#: array instead of `components[]`. CycloneDX has no "service" *component*
#: type -- confirmed against the real 1.6 JSON Schema, whose `type` enum is
#: application/framework/library/container/platform/operating-system/
#: device/device-driver/firmware/file/machine-learning-model/data/
#: cryptographic-asset. A network-reachable thing like a model endpoint or
#: an MCP server is a *service* in CycloneDX's own vocabulary, and belongs
#: in `bom.services[]`, which has no `type` field at all. See SPEC.md §2.
SERVICE_CLASSES = frozenset({"model_endpoint", "mcp_server"})

#: harness-aibom componentClass -> CycloneDX 1.6 native `type`.
#: Only meaningful for classes NOT in SERVICE_CLASSES.
#: See SPEC.md section 2 for the reasoning behind each mapping.
CDX_TYPE_FOR_CLASS = {
    "runtime": "application",
    "model": "machine-learning-model",
    "configuration": "file",
    "skill": "library",
    "hook": "file",
    "secrets_surface": "data",
    # One per MCP tool a server declares -- turns `mcp_server`'s bare
    # `toolCount` into named, individually identifiable parts. `type:
    # application` per the same reasoning as `runtime`: a tool is
    # something the harness can invoke, not a data file. See SPEC.md §2
    # for what this class does and, importantly, does NOT capture (no
    # `definitionSha256`/schema hash -- this scanner only reads static
    # config, never performs a live MCP handshake, so it has no tool
    # description or input schema to hash in the first place; hashing
    # just the bare name would only ever catch a rename, not the actual
    # rug-pull attack a schema hash is meant to catch, and shipping that
    # under a name like "definitionSha256" would be a false sense of
    # security).
    "tool": "application",
}

#: every componentClass this package knows how to emit, service or not.
ALL_COMPONENT_CLASSES = SERVICE_CLASSES | frozenset(CDX_TYPE_FOR_CLASS)


def make_bom_ref(component_class: str, name: str) -> str:
    """Deterministic, human-readable bom-ref: `<class>:<slug(name)>`.

    Not guaranteed unique across an entire document by itself -- two
    same-named components in different directories (e.g. two `.env` files)
    would collide. HarnessDocument.add() disambiguates on insert.
    """
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-").lower() or "unnamed"
    return f"{component_class}:{slug}"


@dataclass
class Component:
    component_class: str
    name: str
    version: str | None = None
    bom_ref: str = ""
    properties: dict[str, str] = field(default_factory=dict)
    relationships: list[tuple[str, str]] = field(default_factory=list)  # (verb, target_bom_ref)

    def __post_init__(self) -> None:
        if self.component_class not in ALL_COMPONENT_CLASSES:
            raise ValueError(f"unknown component_class {self.component_class!r}")
        if not self.bom_ref:
            self.bom_ref = make_bom_ref(self.component_class, self.name)

    @property
    def is_service(self) -> bool:
        """True for a CycloneDX *service* (belongs in bom.services[]),
        False for a CycloneDX *component* (belongs in bom.components[])."""
        return self.component_class in SERVICE_CLASSES

    @property
    def cdx_type(self) -> str:
        """The CycloneDX component `type`. Services have no `type` field at
        all, so this is only meaningful when `is_service` is False."""
        if self.is_service:
            raise ValueError(f"{self.component_class!r} is a CycloneDX service, not a component -- it has no `type`")
        return CDX_TYPE_FOR_CLASS[self.component_class]

    def set(self, name: str, value) -> Component:
        """Set a harness-aibom:<name> property. A no-op for None/"" so
        collectors can call this unconditionally on fields that may be
        missing from whatever they scraped, instead of guarding every call.
        """
        if value is None or value == "":
            return self
        self.properties[name] = str(value)
        return self

    def relate(self, verb: str, target: Component | str) -> Component:
        if verb not in RELATIONSHIP_VERBS:
            raise ValueError(f"unknown relationship verb {verb!r}, expected one of {sorted(RELATIONSHIP_VERBS)}")
        target_ref = target.bom_ref if isinstance(target, Component) else target
        self.relationships.append((verb, target_ref))
        return self


@dataclass
class HarnessDocument:
    """One scanned harness: everything a collector found, plus the edges
    from the harness itself to each top-level thing it uses/loads/etc.

    The harness itself is *not* one more Component in `components` -- it is
    represented separately (as `bom.metadata.component` in cyclonedx.py) so
    it never collides with, say, a `runtime` component for the underlying
    binary. `root_relationships` holds the edges out of that root.
    """

    harness_name: str
    runtime_kind: str  # "hermes" | "openclaw"
    hostname: str
    components: list[Component] = field(default_factory=list)
    root_relationships: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _register(self, component: Component) -> None:
        """Disambiguate `component`'s bom_ref against everything already in
        the document, then add it to `self.components`. Shared by `add()`
        and `add_child()` so both paths get the same collision handling."""
        existing_refs = {c.bom_ref for c in self.components}
        if component.bom_ref in existing_refs:
            base, n = component.bom_ref, 2
            while f"{base}-{n}" in existing_refs:
                n += 1
            component.bom_ref = f"{base}-{n}"
        self.components.append(component)

    def add(self, component: Component, verb: str = "uses") -> Component:
        """Register `component` and relate it to the *harness root* --
        for things the harness touches directly with no more specific
        parent in this data model (runtime, configuration, skill, hook,
        secrets_surface). Use `add_child()` instead when there's a real
        parent component (a model belongs to the endpoint that serves it,
        a tool belongs to the server that declares it, ...) -- rendering
        every relationship as a root edge is what made the dependency
        graph a flat star with no structure a generic SBOM tool could use.
        """
        if verb not in RELATIONSHIP_VERBS:
            raise ValueError(f"unknown relationship verb {verb!r}, expected one of {sorted(RELATIONSHIP_VERBS)}")
        self._register(component)
        self.root_relationships.append((verb, component.bom_ref))
        return component

    def add_child(self, component: Component, parent: Component, verb: str = "uses") -> Component:
        """Register `component` and relate it to `parent` instead of the
        harness root -- `parent` must already be in this document. The
        edge lives on `parent.relationships` (`Component.relate()`), which
        `cyclonedx.py` turns into that parent's own `dependencies[]` entry,
        not the root's."""
        self._register(component)
        parent.relate(verb, component)
        return component

    def warn(self, message: str) -> None:
        self.warnings.append(message)
