"""Compare two harness-aibom CycloneDX documents by (componentClass, name),
surfacing what was added, removed, or changed between them.

This is the mechanism behind supply-chain drift detection: scan a harness,
scan it again later (or after a suspected compromise), and diff the two
documents to see exactly what changed -- a skill's SHA-256, a model's
digest, a newly-registered MCP server, a hook that lost its allowlist
approval.
"""

from __future__ import annotations

#: properties whose change gets flagged with `fingerprint_changed: true`;
#: everything else still shows up under "changed" but without that flag.
FINGERPRINT_FIELDS = ("harness-aibom:sha256", "harness-aibom:digest")

#: fields never compared for a matched entry, even though they're real
#: properties -- "harness-aibom:path" is the absolute filesystem path, and
#: once relPath exists as the identity two entries were matched *on*, the
#: absolute path is inherently host-specific: comparing two different
#: machines (a golden baseline vs. a lab VM, one student's box vs.
#: another's) would otherwise flag every single unchanged file as
#: "changed" purely because /home/alice != /home/bob, which isn't a real
#: finding. Safe to exclude unconditionally: when a pair was matched on
#: `path` itself (no relPath available), their path values are equal by
#: construction anyway, so this never hides a real path-only difference.
IGNORED_FIELDS = frozenset({"harness-aibom:path"})


def _raw_entries(doc: dict) -> list[dict]:
    # model_endpoint and mcp_server live in "services", not "components"
    # (see model.py SERVICE_CLASSES) -- both arrays get read the same way,
    # keyed by componentClass, so a diff doesn't silently go blind to a
    # changed MCP server just because of which array it's stored in.
    return doc.get("components", []) + doc.get("services", [])


def _base_identity(props: dict[str, str], entry: dict) -> tuple[str, str]:
    # Prefer relPath (path relative to --home) over the absolute path,
    # over `name`, in that order:
    #   - `name` alone isn't unique: the recursive secrets scan means
    #     two different `.env` files in different directories both
    #     have `name == ".env"` -- keying on `name` collapsed them
    #     into one dict entry, silently hiding a real change to
    #     whichever one lost that collision.
    #   - the absolute `path` fixes that, but breaks comparing two
    #     different machines against each other (a golden baseline vs.
    #     a lab VM, or student A's box vs. student B's) -- `/home/alice`
    #     and `/home/bob` share no absolute paths, so every entry would
    #     read as both added and removed.
    #   - relPath fixes both: unique like `path`, but host-independent.
    #     Not every entry has one (OpenClaw's env_dir defaults to
    #     /opt/openclaw, entirely outside --home) -- those fall back to
    #     `path`, which is still unique, just not portable.
    # Deliberately NOT bom-ref: its numeric "-2" disambiguation suffix
    # is insertion-order-dependent, so a new component added earlier in
    # a later scan can shift every following bom-ref and make
    # untouched files look renamed.
    identity = props.get("harness-aibom:relPath") or props.get("harness-aibom:path") or entry.get("name", "")
    return (props.get("harness-aibom:componentClass", "unknown"), identity)


def _ambiguous_keys(before: dict, after: dict) -> set[tuple[str, str]]:
    """Base identities that need disambiguating (see `_index`) -- computed
    once, jointly, from *both* documents, not separately per document.

    Confirmed real bug fixed here: computing this per document meant a
    name unique in `before` (one entry, no disambiguator) but duplicated
    in `after` (two entries, both disambiguated) never matched at all --
    the unchanged server read as "removed", and *both* after-side entries
    read as "added", even though one of them was the exact same server
    persisting unchanged. Deciding ambiguity from the union of both scans
    means the same logical key gets the same treatment on both sides.
    """
    ambiguous: set[tuple[str, str]] = set()
    for doc in (before, after):
        counts: dict[tuple[str, str], int] = {}
        for entry in _raw_entries(doc):
            props = {p["name"]: p["value"] for p in entry.get("properties", [])}
            key = _base_identity(props, entry)
            counts[key] = counts.get(key, 0) + 1
        ambiguous |= {key for key, n in counts.items() if n > 1}
    return ambiguous


def _index(doc: dict, ambiguous_keys: set[tuple[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    for entry in _raw_entries(doc):
        props = {p["name"]: p["value"] for p in entry.get("properties", [])}
        grouped.setdefault(_base_identity(props, entry), []).append(props)

    out: dict[tuple[str, str], dict[str, str]] = {}
    for key, props_list in grouped.items():
        if key not in ambiguous_keys:
            # Not ambiguous in *either* document -- always exactly one
            # entry here in that case anyway.
            out[key] = props_list[0]
            continue
        # This base identity is shared by more than one entry in at least
        # one of the two documents -- confirmed real for mcp_server: it's
        # a *service* (§1), so it has neither `path` nor `relPath` to
        # fall back on, and two servers can share a config `name` the
        # same way two `.env` files could share a basename. Disambiguate
        # each with whatever distinguishing, content-derived property it
        # has -- `endpoint` for a URL-based server, `command`+`args` for
        # a stdio one -- falling back to position only as a last resort
        # so nothing is silently dropped. If a server's own `endpoint`
        # happens to be the only thing that changed between scans, that
        # reads as one entry removed and one added rather than one
        # changed -- still visible, which is what matters, just not as
        # precise as an unambiguous name would allow. See SPEC.md §4.
        cls, base_identity = key
        for i, props in enumerate(props_list):
            command_str = " ".join(filter(None, [props.get("harness-aibom:command"), props.get("harness-aibom:args")]))
            disambiguator = props.get("harness-aibom:endpoint") or command_str or str(i)
            out[(cls, f"{base_identity}#{disambiguator}")] = props
    return out


def diff_documents(before: dict, after: dict) -> dict:
    ambiguous_keys = _ambiguous_keys(before, after)
    before_index = _index(before, ambiguous_keys)
    after_index = _index(after, ambiguous_keys)
    before_keys, after_keys = set(before_index), set(after_index)

    added = sorted(f"{k[0]}:{k[1]}" for k in after_keys - before_keys)
    removed = sorted(f"{k[0]}:{k[1]}" for k in before_keys - after_keys)

    changed = []
    for key in sorted(before_keys & after_keys):
        b, a = before_index[key], after_index[key]
        field_diffs = {
            name: {"before": b.get(name), "after": a.get(name)}
            for name in (set(b) | set(a)) - IGNORED_FIELDS
            if b.get(name) != a.get(name)
        }
        if not field_diffs:
            continue
        entry = {"component": f"{key[0]}:{key[1]}", "fields": field_diffs}
        if any(f in field_diffs for f in FINGERPRINT_FIELDS):
            entry["fingerprint_changed"] = True
        changed.append(entry)

    return {"added": added, "removed": removed, "changed": changed}


def diff_documents_with_properties(before: dict, after: dict) -> dict:
    """Same result as `diff_documents()` -- same identity, same
    added/removed/changed entries, so `report --diff` (report.py) and
    plain `diff`/`policy --baseline` can never disagree about what
    counts as a change -- plus each `added`/`removed` identity's own
    full property dict attached, keyed by that identity string.

    `diff_documents()` itself only ever needed the *identity* of an
    added/removed entry (a bare "componentClass:identity" string) --
    `_index()` already builds the full properties dict for exactly this
    purpose internally (used for `changed`'s field-level diff), it just
    never surfaced it for `added`/`removed` before, since nothing needed
    to render *why* an added component matters until v0.10.0's severity-
    sorted `report --diff` (e.g. "this newly-added mcp_server uses http
    with no TLS" needs the new entry's own `transport`/`tls` properties,
    not just its identity).
    """
    ambiguous_keys = _ambiguous_keys(before, after)
    before_index = _index(before, ambiguous_keys)
    after_index = _index(after, ambiguous_keys)
    before_keys, after_keys = set(before_index), set(after_index)

    base = diff_documents(before, after)
    added_properties = {f"{k[0]}:{k[1]}": after_index[k] for k in after_keys - before_keys}
    removed_properties = {f"{k[0]}:{k[1]}": before_index[k] for k in before_keys - after_keys}

    return {**base, "added_properties": added_properties, "removed_properties": removed_properties}
