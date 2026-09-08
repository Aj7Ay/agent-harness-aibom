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


def _index(doc: dict) -> dict[tuple[str, str], dict[str, str]]:
    # Group first, key second: a base identity that turns out to be
    # shared by more than one entry within *this* document needs
    # disambiguating (see below) before it can become a dict key at all.
    grouped: dict[tuple[str, str], list[dict[str, str]]] = {}
    # model_endpoint and mcp_server live in "services", not "components"
    # (see model.py SERVICE_CLASSES) -- both arrays get indexed the same
    # way, keyed by componentClass, so a diff doesn't silently go blind to
    # a changed MCP server just because of which array it's stored in.
    for entry in doc.get("components", []) + doc.get("services", []):
        props = {p["name"]: p["value"] for p in entry.get("properties", [])}
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
        identity = (
            props.get("harness-aibom:relPath") or props.get("harness-aibom:path") or entry.get("name", "")
        )
        key = (props.get("harness-aibom:componentClass", "unknown"), identity)
        grouped.setdefault(key, []).append(props)

    out: dict[tuple[str, str], dict[str, str]] = {}
    for key, props_list in grouped.items():
        if len(props_list) == 1:
            out[key] = props_list[0]
            continue
        # Two or more entries share this identity within the same
        # document -- confirmed real for mcp_server: it's a *service*
        # (§1), so it has neither `path` nor `relPath` to fall back on,
        # and two servers can share a config `name` the same way two
        # `.env` files could share a basename. Disambiguate each with
        # whatever distinguishing, content-derived property it has --
        # `endpoint` for a URL-based server, `command`+`args` for a
        # stdio one -- falling back to position only as a last resort so
        # nothing is silently dropped. This is a per-document grouping,
        # not a stable cross-scan id: if a server's own `endpoint`
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
    before_index = _index(before)
    after_index = _index(after)
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
