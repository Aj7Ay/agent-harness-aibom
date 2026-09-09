"""Security-analysis layer over an already-built harness-aibom CycloneDX
document: an architecture graph, a security summary, explainable risk
observations, secrets confidence tiers, and a coverage checklist.

Deliberately separate from `cyclonedx.py` (serialization) and `report.py`
(HTML rendering) -- every function here is a pure transform of the parsed
`bom` dict, independently testable with no rendering concerns. Every
number is derived directly from data already in the document; nothing is
invented, estimated, or scored by an opaque model. Where a claim can't be
honestly made from a single scan (e.g. "changed since baseline" needs two
documents, which `report` never has), the function says so explicitly
rather than filling in a number that would look verified but isn't --
see `report.py`'s security-summary panel for where that matters.
"""

from __future__ import annotations

import fnmatch
from urllib.parse import urlsplit

#: The synthetic node label for the harness root in the architecture
#: graph -- not a real componentClass, so it can never collide with one.
ROOT_LABEL = "harness"


def _entries(bom: dict) -> list[dict]:
    return bom.get("components", []) + bom.get("services", [])


def _properties(entry: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in entry.get("properties", [])}


def _component_class(entry: dict) -> str:
    return _properties(entry).get("harness-aibom:componentClass", "unknown")


def _group_by_class(entries: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for entry in entries:
        grouped.setdefault(_component_class(entry), []).append(entry)
    return grouped


# ---- 1. Architecture graph --------------------------------------------


def build_architecture_graph(bom: dict) -> dict:
    """{"nodes": {label: count}, "edges": [(from_label, to_label), ...]}
    at the componentClass level, not the instance level. An independent
    reviewer's core complaint about the pre-v0.3 report was exactly this:
    "180 components -> here's what exists" doesn't show *architecture*.
    An instance-level graph wouldn't fix that -- it would mean one box
    per component (up to hundreds, e.g. 73 skills), the same inventory
    problem in diagram form. Grouping by class is what actually shows
    structure: "harness -> skill (73)" as one edge, not 73.

    Every node/edge here is a real aggregation of the document's own
    `dependencies[]` graph (ref -> componentClass, deduplicated), never
    invented -- a class this scanner doesn't know about yet still shows
    up under its own name rather than being dropped, same principle as
    report.py's `_render_groups()`.
    """
    root = bom.get("metadata", {}).get("component", {})
    root_ref = root.get("bom-ref", "harness-root")

    class_by_ref: dict[str, str] = {root_ref: ROOT_LABEL}
    counts: dict[str, int] = {}
    for entry in _entries(bom):
        cls = _component_class(entry)
        class_by_ref[entry.get("bom-ref", "")] = cls
        counts[cls] = counts.get(cls, 0) + 1

    edges: set[tuple[str, str]] = set()
    for dep in bom.get("dependencies", []):
        from_cls = class_by_ref.get(dep.get("ref"))
        if from_cls is None:
            continue
        for target in dep.get("dependsOn", []):
            to_cls = class_by_ref.get(target)
            if to_cls is None or to_cls == from_cls:
                continue
            edges.add((from_cls, to_cls))

    return {"nodes": {ROOT_LABEL: 1, **counts}, "edges": sorted(edges)}


# ---- 2. Security summary ------------------------------------------------


def compute_security_summary(bom: dict) -> dict:
    """Counts for the Security Summary panel -- every value is `len()`
    over entries already grouped by componentClass; nothing here re-scans
    the filesystem or infers anything not already recorded.
    """
    comps = bom.get("components", [])
    svcs = bom.get("services", [])
    by_class = _group_by_class(comps + svcs)

    tools = by_class.get("tool", [])
    executables = [t for t in tools if _properties(t).get("harness-aibom:riskClass") == "exec"]
    fingerprinted = [e for e in comps + svcs if "hashes" in e]

    return {
        "runtime": len(by_class.get("runtime", [])),
        "model_endpoints": len(by_class.get("model_endpoint", [])),
        "models": len(by_class.get("model", [])),
        "skills": len(by_class.get("skill", [])),
        "mcp_servers": len(by_class.get("mcp_server", [])),
        "mcp_tools": len(tools),
        "hooks": len(by_class.get("hook", [])),
        "executable_tools": len(executables),
        "secrets_surfaces": len(by_class.get("secrets_surface", [])),
        "dependencies": len(by_class.get("dependency", [])),
        "fingerprinted": len(fingerprinted),
        "total_components": len(comps),
        "total_services": len(svcs),
    }


# ---- 3. Risk observations (explainable rules, never an opaque score) ----


def compute_risk_observations(bom: dict) -> list[dict]:
    """Rule-based, explainable findings -- deliberately never a single
    numeric "risk score": an independent reviewer specifically asked for
    "explainable rules", not an opaque AI-generated number. Each
    observation names the exact rule that fired, its severity, and the
    bom-refs it matched, so a reader can go verify it against the
    document itself instead of trusting a black box. Absence of an
    observation is not a clean bill of health -- it means none of these
    specific, named rules fired, nothing more (see report.py's rendering
    for how this is phrased to the reader).
    """
    entries = _entries(bom)
    observations: list[dict] = []

    world_readable = [
        e for e in entries
        if _component_class(e) == "secrets_surface" and _properties(e).get("harness-aibom:worldReadable") == "True"
    ]
    if world_readable:
        observations.append({
            "rule": "world_readable_secret",
            "severity": "high",
            "summary": f"{len(world_readable)} secrets-surface file(s) are world-readable",
            "components": [e.get("bom-ref") for e in world_readable],
        })

    mcp_servers = [e for e in entries if _component_class(e) == "mcp_server"]

    plaintext_mcp = [
        e for e in mcp_servers
        if _properties(e).get("harness-aibom:transport") in ("http", "sse")
        and _properties(e).get("harness-aibom:tls") == "False"
    ]
    if plaintext_mcp:
        observations.append({
            "rule": "mcp_plaintext_transport",
            "severity": "medium",
            "summary": f"{len(plaintext_mcp)} MCP server(s) use a network transport without TLS",
            "components": [e.get("bom-ref") for e in plaintext_mcp],
        })

    unauth_mcp = [e for e in mcp_servers if _properties(e).get("harness-aibom:authConfigured") == "False"]
    if unauth_mcp:
        observations.append({
            "rule": "mcp_no_auth",
            "severity": "medium",
            "summary": f"{len(unauth_mcp)} MCP server(s) have no authentication configured",
            "components": [e.get("bom-ref") for e in unauth_mcp],
        })

    # Python packages found via deps.py always carry a version (they're
    # read straight from an already-installed dist-info, which always
    # names its own version) -- a `dependency` component with none is,
    # by construction, an MCP launcher package that resolves "latest" at
    # every invocation (mcp.py only sets `.version` when the launcher
    # spec pinned one).
    unpinned = [e for e in entries if _component_class(e) == "dependency" and "version" not in e]
    if unpinned:
        observations.append({
            "rule": "unpinned_dependency",
            "severity": "low",
            "summary": f"{len(unpinned)} dependency package(s) resolve without a pinned version",
            "components": [e.get("bom-ref") for e in unpinned],
        })

    no_digest_models = [
        e for e in entries
        if _component_class(e) == "model" and "harness-aibom:digest" not in _properties(e)
    ]
    if no_digest_models:
        observations.append({
            "rule": "model_no_digest",
            "severity": "low",
            "summary": f"{len(no_digest_models)} model(s) have no content digest recorded",
            "components": [e.get("bom-ref") for e in no_digest_models],
        })

    return observations


# ---- 4. Secrets-surface confidence tiers --------------------------------

#: Partition of secrets.py's SECRET_NAME_PATTERNS into two confidence
#: tiers. "High": exact/near-exact credential-shaped filenames, low
#: false-positive rate. "Heuristic": broad substring/extension matches an
#: independent reviewer specifically flagged as noisy -- "*token*"
#: matches "tokenize.js" just as happily as a real credential, and
#: "*.sqlite" matches every SQLite database, credential or not.
#: tests/test_security.py asserts these two tuples' union equals
#: secrets.SECRET_NAME_PATTERNS exactly, so this can't silently drift out
#: of sync if that list ever changes.
HIGH_CONFIDENCE_PATTERNS = (".env", "*.env", "*.pem", "*.key")
HEURISTIC_PATTERNS = ("*credentials*", "*token*", "*.sqlite")


def classify_secret_confidence(entry: dict) -> str:
    """"high" or "heuristic" for one secrets_surface entry, by
    re-matching its filename against the two tiers above. Never reads
    file contents -- classification is filename-shape only, same as the
    collector itself; this only re-derives *which* of its own patterns
    actually fired, it doesn't add any new signal.
    """
    filename = entry.get("name", "").rsplit("/", 1)[-1]
    if any(fnmatch.fnmatch(filename, p) for p in HIGH_CONFIDENCE_PATTERNS):
        return "high"
    return "heuristic"


# ---- 5. Coverage / completeness -----------------------------------------

#: Every componentClass this scanner can currently emit. Listed here
#: explicitly (not imported from model.ALL_COMPONENT_CLASSES) since
#: coverage is about what a *document* actually reports having found,
#: independent of whether that set's shape changes later.
COLLECTIBLE_CLASSES = (
    "runtime", "model_endpoint", "model", "configuration", "skill",
    "mcp_server", "tool", "hook", "secrets_surface", "dependency",
)

#: Real, named gaps this scanner does not collect at all yet -- see
#: SPEC.md's "deliberately deferred" notes. Listed here so "coverage"
#: means something honest (out of everything this project has scoped to
#: collect), not just "out of whatever happens to be present in this one
#: document".
NOT_YET_COLLECTED = ("prompt_surface", "memory_store")


def compute_coverage(bom: dict) -> dict:
    present = {_component_class(e) for e in _entries(bom)}
    found = [c for c in COLLECTIBLE_CLASSES if c in present]
    empty = [c for c in COLLECTIBLE_CLASSES if c not in present]
    total = len(COLLECTIBLE_CLASSES) + len(NOT_YET_COLLECTED)
    return {
        "found": found,
        "empty": empty,
        "not_collected": list(NOT_YET_COLLECTED),
        "score": (len(found), total),
    }


# ---- 6. Capabilities (v0.5.0) --------------------------------------------

#: Fixed, explainable capability tag per componentClass -- what that kind
#: of thing inherently *is*, not a guess at its actual runtime behavior.
#: `tool` is deliberately absent here: it already has a real, specific
#: signal (`riskClass`, from mcp.py's own name-heuristic) more precise
#: than a fixed per-class default would be -- see `classify_capabilities`.
_CLASS_CAPABILITY = {
    "runtime": "execute",
    "configuration": "read",
    "model": "inference",
    "skill": "read",
    "hook": "execute",
    "secrets_surface": "credential",
    "dependency": "read",
    "model_endpoint": "network",
    "mcp_server": "network",
}

#: `tool`'s riskClass (mcp.py, a name-only heuristic -- see model.py's
#: CDX_TYPE_FOR_CLASS entry for `tool`) maps directly onto a capability;
#: this is a relabeling, not a second independent classification, so the
#: two can never disagree with each other.
_TOOL_RISK_TO_CAPABILITY = {"read": "read", "write": "write", "exec": "execute", "network": "network"}


def classify_capabilities(entry: dict) -> str:
    """One capability tag: read / write / execute / network / credential
    / inference / unknown. Explainable by construction -- every class's
    tag is a fixed, documented mapping (above), never inferred from
    behavior this scanner didn't observe. `tool` reuses its own
    `riskClass` instead of the class-level default, since that's already
    a more specific, per-instance signal.
    """
    cls = _component_class(entry)
    if cls == "tool":
        risk = _properties(entry).get("harness-aibom:riskClass", "unknown")
        return _TOOL_RISK_TO_CAPABILITY.get(risk, "unknown")
    return _CLASS_CAPABILITY.get(cls, "unknown")


# ---- 7. Reachability / attack surface (v0.5.0) ---------------------------

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "0.0.0.0"})


def _endpoint_url(entry: dict, props: dict[str, str]) -> str | None:
    cls = _component_class(entry)
    if cls == "model_endpoint":
        # model_endpoint stores its URL as the component's own `name`
        # (see cyclonedx.py's _service_dict) -- `endpoint` property is
        # mcp_server's own field, checked first in case a future
        # collector sets both.
        return props.get("harness-aibom:endpoint") or entry.get("name")
    if cls == "mcp_server":
        return props.get("harness-aibom:endpoint")
    return None


def classify_reachability(entry: dict) -> str:
    """Where this component sits, in terms an attack-surface map cares
    about: filesystem / process / loopback / network / credential-store
    / model-provider / unknown. Deliberately conservative about
    "network": a non-loopback hostname could be a private LAN address or
    a real internet host, and this scanner has no way to tell which from
    the string alone (no DNS/routing check is performed) -- so it's
    labeled "network", never "internet-reachable", which would be a
    claim this scanner can't actually back up.
    """
    cls = _component_class(entry)
    props = _properties(entry)

    if cls == "secrets_surface":
        return "credential-store"
    if cls in ("configuration", "skill", "dependency"):
        return "filesystem"
    if cls == "hook":
        return "filesystem+process"
    if cls == "runtime":
        return "process"
    if cls == "model":
        return "model-provider"
    if cls == "tool":
        return {"execute": "process", "network": "network"}.get(classify_capabilities(entry), "filesystem")
    if cls in ("model_endpoint", "mcp_server"):
        if props.get("harness-aibom:transport") == "stdio":
            return "process"
        url = _endpoint_url(entry, props)
        if not url:
            return "unknown"
        host = urlsplit(url).hostname
        return "loopback" if host in _LOOPBACK_HOSTS else "network"
    return "unknown"


def compute_attack_surface(bom: dict) -> dict:
    """Every entry grouped by `classify_reachability()`, plus which
    network-tier entries actually cross a trust boundary (a non-loopback
    endpoint) -- the "TRUST ZONE: LOCAL HOST" vs "TRUST ZONE: MODEL
    SERVICE" distinction an independent reviewer asked for, expressed as
    real, checkable groupings rather than another hand-drawn diagram.
    """
    by_tier: dict[str, list[str]] = {}
    for entry in _entries(bom):
        tier = classify_reachability(entry)
        by_tier.setdefault(tier, []).append(entry.get("bom-ref", ""))
    return {"by_tier": by_tier, "crosses_network_boundary": sorted(by_tier.get("network", []))}


# ---- 8. Blast radius (v0.5.0) --------------------------------------------


def build_dependency_children(bom: dict) -> dict[str, list[str]]:
    """ref -> its direct `dependsOn` targets, built once from
    `bom["dependencies"]`. A caller computing blast radius for many refs
    from the same document (report.py renders one per component) should
    build this once and pass it to every `compute_blast_radius()` call,
    rather than paying the O(edges) cost again on every single call.
    """
    return {dep.get("ref", ""): dep.get("dependsOn", []) for dep in bom.get("dependencies", [])}


def compute_blast_radius(bom: dict, bom_ref: str, children: dict[str, list[str]] | None = None) -> dict:
    """Everything reachable from `bom_ref` by following the document's
    own real `dependencies[]` edges (a plain BFS) -- direct children and
    the full transitive set. Every result here is labeled "observed" by
    construction: these are edges a collector actually recorded (via
    `HarnessDocument.add()`/`add_child()`), never a guessed or inferred
    path. There is no "inferred" tier yet -- that needs something like
    skill-content parsing (linking a skill to servers/models its own
    `SKILL.md` prose references), which this scanner doesn't do (SPEC.md
    section 5) -- so blast radius is complete only up to what the
    dependency graph itself already contains.

    `children` is optional -- built fresh from `bom` via
    `build_dependency_children()` if omitted, for a single-call use.
    """
    if children is None:
        children = build_dependency_children(bom)

    direct = children.get(bom_ref, [])
    visited: set[str] = set()
    queue = list(direct)
    while queue:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        queue.extend(children.get(node, []))

    return {"direct_children": direct, "reachable": sorted(visited)}
