"""Shared MCP-server extraction from a harness's already-parsed config dict.

Both Hermes and OpenClaw configs may carry an `mcp_servers` list, or a
nested `mcp.servers` list, of entries like
{name, url/endpoint, auth/token/apiKey, tools}, or a *stdio* entry like
{name, command, args, env, tools} instead -- confirmed a real gap by an
independent reviewer: a stdio entry has no url/endpoint/auth/token/apiKey
at all, so it used to come out as `tls=False, authConfigured=False` --
both actively wrong (there's no network transport for "no TLS" to
describe, and `env` routinely carries the actual credential), and the
dangerous part (what command, with what arguments) wasn't recorded at
all. `transport` now says which shape an entry is; `tls` is only ever set
for a URL-based transport (`"n/a"` has no meaning for stdio); `env`'s
*names* (never values, same rule as secrets_surface) count toward
`authConfigured` and are recorded in `envKeys`.

This is the shape audited in the CAASP "auditing-hermes-mcp-connections"
lab, generalized across both config layouts and both transport shapes.
Returns [] rather than raising when the key is absent -- not every
harness/config version has MCP configured.

Two more defects an independent reviewer found and confirmed:
  - `authConfigured` used to be true for *any* non-empty `env`, so a
    stdio server with only e.g. `NODE_ENV`/`LOG_LEVEL` read as
    credential-bearing -- a false positive that hides the real question.
    Now only env var *names* matching a credential-shaped pattern count;
    `envKeys` still records every name as raw evidence either way,
    `authEnvKeys` the matched subset.
  - transport inference used to test `"sse" in endpoint` as a plain
    substring anywhere in the URL, so e.g. `https://assets.example.com/mcp`
    (which merely contains "sse" inside "assets") misread as an SSE
    transport. Now checks the URL's actual path.

`tool` components: one per declared tool name, not just a bare
`toolCount`. See model.py's CDX_TYPE_FOR_CLASS entry for `tool` for what
this class does and does NOT capture (no schema hash -- this scanner
never performs a live MCP handshake).

`purl` + a native `dependency` component: a best-effort Package URL for a
stdio server's underlying package, parsed from `command`/`args` (`npx -y
@scope/pkg@1.2.3` -> `pkg:npm/%40scope/pkg@1.2.3`). Only `npx` (npm) and
`uvx` (PyPI) are recognized; anything else gets no purl rather than a
guess. Confirmed real gap: `purl` used to live *only* as a
`harness-aibom:*` property on the server component -- readable by this
package's own tooling, invisible to any generic SBOM tool, license
checker, or OSV lookup, which is the entire reason to extract a purl in
the first place. Now *also* emitted as its own `dependency` component
(CDX `type: library`) that the server depends on (`mcp_server ->
dependency` in the graph), a real, walkable node a generic tool can
actually find -- and unlike the server itself (a *service*, with no
`purl` slot at all -- see model.py's SERVICE_CLASSES), this `dependency`
component IS a real `component`, so `purl` reaches it as CycloneDX's own
native top-level `purl` field (confirmed present on `component` in the
real 1.6 schema), not just a `harness-aibom:purl` property -- see
cyclonedx.py's `_component_dict`.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..model import Component

#: env var *names* (never values) that look like they hold a credential --
#: matched case-insensitively against the whole name, not required to be
#: the whole name (e.g. "GITHUB_TOKEN" matches on "TOKEN").
_CREDENTIAL_ENV_PATTERN = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)

#: Tool-name keyword -> riskClass, checked in this order (most dangerous
#: first) so a name matching more than one category gets the safer-to-
#: assume, more dangerous label. Heuristic, not authoritative: derived from
#: the tool's *name* alone, since that's all a static config ever gives us
#: -- no live schema to classify parameters against. A tool matching none
#: of these gets riskClass "unknown", not a guessed default. Expanded once
#: already after an independent reviewer found real MCP tool names
#: (`git_commit`, `git_status`) that the original list missed entirely.
_RISK_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("exec", ("exec", "execute", "run", "spawn", "shell", "eval", "command")),
    ("network", ("fetch", "http", "request", "curl", "download", "upload", "browse", "url")),
    (
        "write",
        (
            "write",
            "create",
            "delete",
            "remove",
            "update",
            "move",
            "rename",
            "modify",
            "send",
            "put",
            "post",
            "commit",
            "push",
            "apply",
            "patch",
            "install",
            "set",
        ),
    ),
    ("read", ("read", "get", "list", "search", "query", "view", "show", "fetch", "status")),
)


def _risk_class(tool_name: str) -> str:
    lname = tool_name.lower()
    for risk, keywords in _RISK_KEYWORDS:
        if any(keyword in lname for keyword in keywords):
            return risk
    return "unknown"


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    """(package name, version|None) from an npm package spec that may be
    scoped (`@scope/name`) and may carry an explicit `@version` suffix.
    The leading `@` of a scope is never mistaken for the version
    separator -- only an `@` appearing after the scope's own `/` can start
    a version (`@scope/name@1.2.3`, not `@scope@1.2.3/name`).
    """
    if spec.startswith("@"):
        scope_end = spec.find("/")
        if scope_end == -1:
            return spec, None  # malformed scope (no "/") -- treat whole thing as the name
        rest = spec[scope_end + 1 :]
        if "@" in rest:
            name_part, _, version = rest.partition("@")
            return f"{spec[: scope_end + 1]}{name_part}", version
        return spec, None
    if "@" in spec:
        name, _, version = spec.partition("@")
        return name, version
    return spec, None


def _purl_for_npm(name: str, version: str | None) -> str:
    # purl-spec encodes a scoped package's leading "@" as "%40" in the
    # namespace segment: pkg:npm/%40scope/name, not pkg:npm/@scope/name.
    encoded = name
    if name.startswith("@"):
        scope, _, pkg = name[1:].partition("/")
        encoded = f"%40{scope}/{pkg}"
    purl = f"pkg:npm/{encoded}"
    return f"{purl}@{version}" if version else purl


def _normalize_pypi_name(name: str) -> str:
    # Best-effort per the purl-spec's pypi normalization (lowercase,
    # underscores to dashes) -- not the full PEP 503 rule (dots are left
    # alone), which is more normalization than a best-effort scanner needs.
    return name.lower().replace("_", "-")


def _parse_launcher_spec(command: str | None, args: list) -> tuple[str, str | None, str] | None:
    """(display name, version|None, purl) parsed from a stdio server's
    `command`/`args` for a recognized launcher, or None otherwise. Never
    guesses at a purl for an unrecognized command -- better no identity
    than a wrong one. Shared by the server's own `purl` property and the
    standalone `dependency` component below, so both come from the exact
    same parse instead of two implementations that could disagree.
    """
    if not command or not args:
        return None
    non_flag_args = [str(a) for a in args if not str(a).startswith("-")]
    if not non_flag_args:
        return None
    spec = non_flag_args[0]

    if command == "npx":
        name, version = _split_npm_spec(spec)
        return name, version, _purl_for_npm(name, version)
    if command == "uvx":
        for sep in ("==", "@"):
            if sep in spec:
                raw_name, _, version = spec.partition(sep)
                name = _normalize_pypi_name(raw_name)
                return name, version, f"pkg:pypi/{name}@{version}"
        name = _normalize_pypi_name(spec)
        return name, None, f"pkg:pypi/{name}"

    return None


def _servers_list(config: dict) -> list[dict]:
    if "mcp_servers" in config:
        return config["mcp_servers"] or []
    mcp = config.get("mcp") or {}
    return mcp.get("servers") or []


def _looks_like_sse(endpoint: str) -> bool:
    # The URL's path, not a substring test on the whole string -- a host
    # or query string merely containing "sse" (e.g. "assets.example.com")
    # isn't an SSE transport.
    return urlsplit(endpoint).path.rstrip("/").endswith("/sse")


def extract_mcp_servers(config: dict) -> list[tuple[Component, list[Component], Component | None]]:
    """One (server, its tool components, its underlying package
    component or None) triple per configured MCP server. The caller adds
    the server as a child of whatever parent it belongs to, each tool as
    a child of that server, and the package (when present) also as a
    child of that server -- see collectors/hermes.py / collectors/openclaw.py.
    """
    out: list[tuple[Component, list[Component], Component | None]] = []
    for entry in _servers_list(config):
        name = entry.get("name") or entry.get("id") or "unknown-mcp-server"
        endpoint = entry.get("url") or entry.get("endpoint") or ""
        command = entry.get("command")
        args = entry.get("args") or []

        comp = Component(component_class="mcp_server", name=name)

        transport = entry.get("transport") or (
            "stdio" if command and not endpoint else ("sse" if _looks_like_sse(endpoint) else "http")
        )
        comp.set("transport", transport)

        if endpoint:
            comp.set("endpoint", endpoint)
            comp.set("tls", endpoint.startswith("https://"))
        elif transport == "stdio":
            comp.set("tls", "n/a")

        if command:
            comp.set("command", command)
        if args:
            comp.set("args", " ".join(str(a) for a in args))

        package: Component | None = None
        parsed = _parse_launcher_spec(command, args)
        if parsed:
            pkg_name, pkg_version, purl = parsed
            # Kept on the server itself too (quick glance, no graph walk
            # needed) as well as on the standalone component below --
            # confirmed real gap: living *only* here made the identity
            # invisible to any generic SBOM tool, license checker, or OSV
            # lookup, since none of them know the harness-aibom: namespace.
            comp.set("purl", purl)
            comp.set("versionPinned", bool(pkg_version))

            package = Component(component_class="dependency", name=pkg_name)
            if pkg_version:
                package.version = pkg_version
            package.set("purl", purl)
            # Distinguishes this from a deps.py-discovered Python package
            # (origin="python-package") -- confirmed real bug this fixes:
            # security.py's unpinned_dependency risk rule used to infer
            # "this is an MCP launcher with no pinned version" purely
            # from the *absence* of a `version` field, on the assumption
            # that a Python package (always read from an already-
            # installed dist-info) could never lack one. A METADATA file
            # missing its own Version: header is malformed but real, and
            # would have been silently misreported as a floating MCP
            # launcher. `origin` makes the two cases distinguishable by
            # a real, recorded fact instead of an inferred absence.
            package.set("origin", "mcp-launcher")

        env = entry.get("env") or {}
        auth_env_keys = sorted(k for k in env if _CREDENTIAL_ENV_PATTERN.search(k))
        has_declared_auth = bool(entry.get("auth") or entry.get("token") or entry.get("apiKey"))
        comp.set("authConfigured", has_declared_auth or bool(auth_env_keys))
        if env:
            comp.set("envKeys", ",".join(sorted(env)))
        if auth_env_keys:
            comp.set("authEnvKeys", ",".join(auth_env_keys))

        tool_names = entry.get("tools")
        comp.set("toolCount", len(tool_names) if tool_names is not None else None)

        tools = []
        for tool_name in tool_names or []:
            tool_name = str(tool_name)
            tool = Component(component_class="tool", name=f"{name}/{tool_name}")
            tool.set("server", name)
            tool.set("riskClass", _risk_class(tool_name))
            tools.append(tool)

        out.append((comp, tools, package))
    return out
