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
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..model import Component

#: env var *names* (never values) that look like they hold a credential --
#: matched case-insensitively against the whole name, not required to be
#: the whole name (e.g. "GITHUB_TOKEN" matches on "TOKEN").
_CREDENTIAL_ENV_PATTERN = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)


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


def extract_mcp_servers(config: dict) -> list[Component]:
    out = []
    for entry in _servers_list(config):
        name = entry.get("name") or entry.get("id") or "unknown-mcp-server"
        endpoint = entry.get("url") or entry.get("endpoint") or ""
        command = entry.get("command")

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
            # Not hashed: a stdio command is very often `npx`/`uvx`
            # resolving a package name at invocation time, not a single
            # static file on disk that exists to hash before the server
            # ever runs -- a hash here would be misleading more often
            # than useful. `command`/`args` are still recorded verbatim,
            # since that's the auditable fact ("what does this actually
            # run"), just not fingerprinted.
            comp.set("command", command)
        args = entry.get("args")
        if args:
            comp.set("args", " ".join(str(a) for a in args))

        env = entry.get("env") or {}
        auth_env_keys = sorted(k for k in env if _CREDENTIAL_ENV_PATTERN.search(k))
        has_declared_auth = bool(entry.get("auth") or entry.get("token") or entry.get("apiKey"))
        comp.set("authConfigured", has_declared_auth or bool(auth_env_keys))
        if env:
            comp.set("envKeys", ",".join(sorted(env)))
        if auth_env_keys:
            comp.set("authEnvKeys", ",".join(auth_env_keys))

        tools = entry.get("tools")
        if tools is not None:
            comp.set("toolCount", len(tools))

        out.append(comp)
    return out
