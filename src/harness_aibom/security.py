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
        "prompt_surfaces": len(by_class.get("prompt_surface", [])),
        "memory_stores": len(by_class.get("memory_store", [])),
        "fingerprinted": len(fingerprinted),
        "total_components": len(comps),
        "total_services": len(svcs),
    }


# ---- 3. Risk observations (explainable rules, never an opaque score) ----


#: Fixed severity ranking `compute_risk_observations()` sorts its result
#: by -- lower rank first (highest attention first). Confirmed real bug
#: fixed here: observations were appended in the fixed order the rules
#: happen to be checked in this function, so a HIGH-severity rule
#: appended late (e.g. world_readable_memory_store, v0.6.0) rendered
#: below several LOW-severity ones -- a reader scanning top-down saw the
#: least important findings first and the most important one last.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


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

    The returned list is sorted by severity (`_SEVERITY_RANK`), highest
    first -- a stable sort, so within one severity tier, observations
    still appear in the same fixed rule-check order as before.
    """
    entries = _entries(bom)
    observations: list[dict] = []

    world_readable = [
        e for e in entries
        if _component_class(e) == "secrets_surface" and _properties(e).get("harness-aibom:worldReadable") == "True"
    ]
    # Split by classify_secret_confidence() instead of one rule over all
    # of them -- confirmed real bug fixed here: `*token*`/`*.sqlite`
    # heuristic matches (secrets.py's own noisy tier, see
    # HEURISTIC_PATTERNS) were reported at the same "high" severity as an
    # exact `.env`/`*.pem`/`*.key` match, and classify_secret_confidence()
    # -- written for exactly this distinction -- was never actually
    # called anywhere. A heuristic-tier match is real evidence, just
    # weaker evidence, so it still gets its own observation (never
    # silently dropped), at a lower severity and under its own rule name.
    world_readable_high = [e for e in world_readable if classify_secret_confidence(e) == "high"]
    world_readable_heuristic = [e for e in world_readable if classify_secret_confidence(e) == "heuristic"]
    if world_readable_high:
        observations.append({
            "rule": "world_readable_secret_high_confidence",
            "severity": "high",
            "summary": f"{len(world_readable_high)} secrets-surface file(s) (high-confidence match) are world-readable",
            "components": [e.get("bom-ref") for e in world_readable_high],
        })
    if world_readable_heuristic:
        observations.append({
            "rule": "world_readable_secret_heuristic",
            "severity": "medium",
            "summary": f"{len(world_readable_heuristic)} secrets-surface file(s) (heuristic filename match, e.g. "
                       "*token*/*.sqlite -- verify before acting) are world-readable",
            "components": [e.get("bom-ref") for e in world_readable_heuristic],
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

    # `origin` (mcp.py / deps.py, both set it) distinguishes an MCP
    # launcher package from a Python package found via deps.py --
    # confirmed real bug fixed here: this used to infer "MCP launcher,
    # resolves latest every invocation" purely from *absence* of a
    # version field, on the false assumption that a deps.py-discovered
    # Python package (read from an already-installed dist-info) could
    # never lack one -- a METADATA file missing its own Version: header
    # is malformed but real, and would have been silently merged into
    # the same "floating launcher" finding. The two are now genuinely
    # different rules: an unpinned MCP launcher is a real "resolves
    # differently every run" risk; a Python package with no version is a
    # data-quality problem (this scanner couldn't read a version that's
    # supposed to exist), not the same finding at all.
    dependencies = [e for e in entries if _component_class(e) == "dependency"]
    unpinned_launchers = [
        e for e in dependencies
        if _properties(e).get("harness-aibom:origin") == "mcp-launcher" and "version" not in e
    ]
    if unpinned_launchers:
        observations.append({
            "rule": "unpinned_mcp_launcher",
            "severity": "low",
            "summary": f"{len(unpinned_launchers)} MCP launcher package(s) resolve without a pinned version",
            "components": [e.get("bom-ref") for e in unpinned_launchers],
        })
    unversioned_python_packages = [
        e for e in dependencies
        if _properties(e).get("harness-aibom:origin") == "python-package" and "version" not in e
    ]
    if unversioned_python_packages:
        observations.append({
            "rule": "python_package_missing_version",
            "severity": "low",
            "summary": f"{len(unversioned_python_packages)} Python package(s) had no Version: header in their own "
                       "METADATA (malformed metadata, not a floating dependency)",
            "components": [e.get("bom-ref") for e in unversioned_python_packages],
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

    # A memory store can carry conversation history, which can itself
    # contain anything a user or the agent ever discussed -- same
    # underlying risk as a world-readable secret, just a different
    # componentClass (v0.6.0).
    world_readable_memory = [
        e for e in entries
        if _component_class(e) == "memory_store" and _properties(e).get("harness-aibom:worldReadable") == "True"
    ]
    if world_readable_memory:
        observations.append({
            "rule": "world_readable_memory_store",
            "severity": "high",
            "summary": f"{len(world_readable_memory)} memory-store file(s) are world-readable",
            "components": [e.get("bom-ref") for e in world_readable_memory],
        })

    observations.sort(key=lambda o: _SEVERITY_RANK.get(o["severity"], 99))
    return observations


def diff_risk_observations(baseline: dict, current: dict) -> dict:
    """Which named risk-rule findings are new, resolved, or still
    persisting since a `baseline` scan -- keyed on `(rule, component
    bom-ref)`, the same identity `policy --baseline` (cli.py, v0.7.0)
    originally computed ad hoc, inline, once for its own use only.
    Pulled out here (v0.8.2) so `policy --baseline` and the new `diff
    --security` (cli.py) share one implementation and can never disagree
    about what counts as "new since baseline" -- the same "one function,
    multiple consumers" discipline `report --baseline` already applies
    to `diff.diff_documents()` itself (v0.7.0).

    Each returned list (`new`, `resolved`, `persisting`) is shaped like
    `compute_risk_observations()`'s own output (same keys), except
    `components` is narrowed to only the bom-refs relevant to that
    bucket -- an observation with some new and some persisting matches
    appears, correctly, in both `new` and `persisting`, each with only
    its own subset. Order is inherited from `compute_risk_observations()`
    (severity first), never re-sorted here.
    """
    baseline_obs = compute_risk_observations(baseline)
    current_obs = compute_risk_observations(current)
    baseline_keys = {(o["rule"], ref) for o in baseline_obs for ref in o["components"]}
    current_keys = {(o["rule"], ref) for o in current_obs for ref in o["components"]}

    def _narrowed(obs_list: list[dict], keep) -> list[dict]:
        out = []
        for o in obs_list:
            refs = [ref for ref in o["components"] if keep((o["rule"], ref))]
            if refs:
                out.append({**o, "components": refs})
        return out

    return {
        "new": _narrowed(current_obs, lambda k: k not in baseline_keys),
        "persisting": _narrowed(current_obs, lambda k: k in baseline_keys),
        "resolved": _narrowed(baseline_obs, lambda k: k not in current_keys),
    }


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
    # v0.6.0 -- both real, named gaps as of v0.2.0's SPEC.md, now closed:
    # collectors/prompt_surface.py, collectors/memory_store.py.
    "prompt_surface", "memory_store",
)

#: Real, named gaps this scanner does not collect at all yet -- see
#: SPEC.md's "deliberately deferred" notes. Listed here so "coverage"
#: means something honest (out of everything this project has scoped to
#: collect), not just "out of whatever happens to be present in this one
#: document". Empty as of v0.6.0 -- kept as a real tuple, not removed
#: outright, so a future genuinely-uncollected gap has an obvious place
#: to go.
NOT_YET_COLLECTED: tuple[str, ...] = ()


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
#: `tool` and `mcp_server` are deliberately absent here: both have a
#: real, per-instance signal more precise than a fixed per-class default
#: would be -- see `classify_capabilities`.
_CLASS_CAPABILITY = {
    "runtime": "execute",
    "configuration": "read",
    "model": "inference",
    "skill": "read",
    "hook": "execute",
    "secrets_surface": "credential",
    "dependency": "read",
    "model_endpoint": "network",
    "prompt_surface": "read",
    "memory_store": "read",
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
    behavior this scanner didn't observe.

    Two classes consult their own recorded properties instead of the
    fixed per-class default, since both already carry something more
    specific: `tool` reuses its own `riskClass`. `mcp_server` reuses its
    own `transport` -- confirmed real bug fixed here: the fixed map used
    to say "network" unconditionally, contradicting a stdio server's own
    `classify_reachability()` result ("process") on the very same row. A
    stdio server has no network capability at all; only an http/sse one
    does.
    """
    cls = _component_class(entry)
    props = _properties(entry)
    if cls == "tool":
        return _TOOL_RISK_TO_CAPABILITY.get(props.get("harness-aibom:riskClass", "unknown"), "unknown")
    if cls == "mcp_server":
        return "process" if props.get("harness-aibom:transport") == "stdio" else "network"
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


def index_mcp_servers(bom: dict) -> dict[str, dict]:
    """MCP server name -> its own raw entry, for `classify_reachability()`
    to look up a `tool`'s parent. Built once per `compute_attack_surface()`
    call (or by a caller rendering many entries, e.g. report.py) rather
    than once per tool, same reasoning as `build_dependency_children()`.
    """
    return {e.get("name", ""): e for e in _entries(bom) if _component_class(e) == "mcp_server"}


def classify_reachability(entry: dict, mcp_servers: dict[str, dict] | None = None) -> str:
    """Where this component sits, in terms an attack-surface map cares
    about: filesystem / process / loopback / network / credential-store
    / model-provider / unknown. Deliberately conservative about
    "network": a non-loopback hostname could be a private LAN address or
    a real internet host, and this scanner has no way to tell which from
    the string alone (no DNS/routing check is performed) -- so it's
    labeled "network", never "internet-reachable", which would be a
    claim this scanner can't actually back up.

    `mcp_servers` (name -> entry, from `index_mcp_servers()`) is how a
    `tool`'s reachability is decided -- confirmed real bug fixed here: a
    `tool` used to get a fixed guess from its own `riskClass` alone (a
    remote HTTPS server's `read`/`write` tools read as "filesystem",
    while a local stdio server's `network`-tagged tool read as
    "network" -- both backwards). Reachability and capability are
    different axes: capability says *what* a tool does; reachability
    says *how it's reached*, which is entirely a property of the MCP
    server it belongs to, not of the tool itself -- so a `tool` simply
    inherits its parent server's own reachability.
    """
    cls = _component_class(entry)
    props = _properties(entry)

    if cls == "secrets_surface":
        return "credential-store"
    if cls in ("configuration", "skill", "dependency", "prompt_surface", "memory_store"):
        return "filesystem"
    if cls == "hook":
        return "filesystem+process"
    if cls == "runtime":
        return "process"
    if cls == "model":
        return "model-provider"
    if cls == "tool":
        server = (mcp_servers or {}).get(props.get("harness-aibom:server", ""))
        return classify_reachability(server, mcp_servers) if server is not None else "unknown"
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
    mcp_servers = index_mcp_servers(bom)
    by_tier: dict[str, list[str]] = {}
    for entry in _entries(bom):
        tier = classify_reachability(entry, mcp_servers)
        by_tier.setdefault(tier, []).append(entry.get("bom-ref", ""))
    return {"by_tier": by_tier, "crosses_network_boundary": sorted(by_tier.get("network", []))}


# ---- 8. Supply chain and blast radius (v0.5.0, direction fixed in v0.5.1) --


def build_dependency_children(bom: dict) -> dict[str, list[str]]:
    """ref -> its direct `dependsOn` targets, built once from
    `bom["dependencies"]`. A caller computing supply chain for many refs
    from the same document (report.py renders one per component) should
    build this once and pass it to every `compute_supply_chain()` call,
    rather than paying the O(edges) cost again on every single call.
    """
    return {dep.get("ref", ""): dep.get("dependsOn", []) for dep in bom.get("dependencies", [])}


def build_dependency_parents(bom: dict) -> dict[str, list[str]]:
    """ref -> every ref that directly `dependsOn` it -- the inverse of
    `build_dependency_children()`. Built once and reused the same way,
    for `compute_blast_radius()`.
    """
    parents: dict[str, list[str]] = {}
    for dep in bom.get("dependencies", []):
        ref = dep.get("ref", "")
        for target in dep.get("dependsOn", []):
            parents.setdefault(target, []).append(ref)
    return parents


def _bfs(adjacency: dict[str, list[str]], start: str) -> tuple[list[str], list[str]]:
    direct = adjacency.get(start, [])
    visited: set[str] = set()
    queue = list(direct)
    while queue:
        node = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        queue.extend(adjacency.get(node, []))
    return direct, sorted(visited)


def compute_supply_chain(bom: dict, bom_ref: str, children: dict[str, list[str]] | None = None) -> dict:
    """Everything `bom_ref` itself depends on, transitively -- a plain
    BFS forward over the document's own real `dependencies[]` edges.
    This answers "what does this rely on", i.e. this component's own
    supply chain -- see `compute_blast_radius()` for the (different,
    security-relevant) reverse question. `children` is optional, built
    fresh via `build_dependency_children()` if omitted.
    """
    if children is None:
        children = build_dependency_children(bom)
    direct, reachable = _bfs(children, bom_ref)
    return {"direct_children": direct, "reachable": reachable}


def compute_blast_radius(bom: dict, bom_ref: str, parents: dict[str, list[str]] | None = None) -> dict:
    """Everything that would be affected if `bom_ref` were compromised --
    a plain BFS *backward* over the document's own real `dependencies[]`
    edges (who depends on this, transitively). This is what "blast
    radius" means in a security context, and confirmed real bug fixed
    here: the original v0.5.0 implementation traversed `dependsOn`
    forward instead (a component's own supply chain, see
    `compute_supply_chain()` above) -- every leaf (a skill, a
    secrets_surface file, most dependencies) reported zero reachable,
    when leaves are exactly what gets compromised first and a poisoned
    skill or a leaked credential file having "zero blast radius" is the
    least useful possible answer. Every result here is still labeled
    "observed" by construction -- these are edges a collector actually
    recorded (`HarnessDocument.add()`/`add_child()`), never a guessed or
    inferred path; there is no "inferred" tier yet (that needs
    skill-content parsing, SPEC.md section 5, still not done).

    `parents` is optional, built fresh via `build_dependency_parents()`
    if omitted.
    """
    if parents is None:
        parents = build_dependency_parents(bom)
    direct, reachable = _bfs(parents, bom_ref)
    return {"direct_dependents": direct, "reachable": reachable}
