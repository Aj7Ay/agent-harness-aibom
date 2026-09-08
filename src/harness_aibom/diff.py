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


def _index(doc: dict) -> dict[tuple[str, str], dict[str, str]]:
    out: dict[tuple[str, str], dict[str, str]] = {}
    # model_endpoint and mcp_server live in "services", not "components"
    # (see model.py SERVICE_CLASSES) -- both arrays get indexed the same
    # way, keyed by componentClass, so a diff doesn't silently go blind to
    # a changed MCP server just because of which array it's stored in.
    for entry in doc.get("components", []) + doc.get("services", []):
        props = {p["name"]: p["value"] for p in entry.get("properties", [])}
        # Key on the full path when there is one, falling back to `name`
        # only for classes that don't carry a path (model, runtime, ...).
        # `name` alone isn't unique: the recursive secrets scan means two
        # different `.env` files in different directories both have
        # `name == ".env"` -- keying on `name` collapsed them into one
        # dict entry, silently hiding a real change to whichever one lost
        # that collision. Deliberately NOT bom-ref: its numeric "-2"
        # disambiguation suffix is insertion-order-dependent, so a new
        # component added earlier in a later scan can shift every
        # following bom-ref and make untouched files look renamed.
        identity = props.get("harness-aibom:path") or entry.get("name", "")
        key = (props.get("harness-aibom:componentClass", "unknown"), identity)
        out[key] = props
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
            for name in set(b) | set(a)
            if b.get(name) != a.get(name)
        }
        if not field_diffs:
            continue
        entry = {"component": f"{key[0]}:{key[1]}", "fields": field_diffs}
        if any(f in field_diffs for f in FINGERPRINT_FIELDS):
            entry["fingerprint_changed"] = True
        changed.append(entry)

    return {"added": added, "removed": removed, "changed": changed}
