"""Shared MCP-server extraction from a harness's already-parsed config dict.

Both Hermes and OpenClaw configs may carry an `mcp_servers` list, or a
nested `mcp.servers` list, of entries like
{name, url/endpoint, auth/token/apiKey, tools}. This is the shape audited
in the CAASP "auditing-hermes-mcp-connections" lab, generalized across
both config layouts. Returns [] rather than raising when the key is
absent -- not every harness/config version has MCP configured.
"""

from __future__ import annotations

from ..model import Component


def _servers_list(config: dict) -> list[dict]:
    if "mcp_servers" in config:
        return config["mcp_servers"] or []
    mcp = config.get("mcp") or {}
    return mcp.get("servers") or []


def extract_mcp_servers(config: dict) -> list[Component]:
    out = []
    for entry in _servers_list(config):
        name = entry.get("name") or entry.get("id") or "unknown-mcp-server"
        endpoint = entry.get("url") or entry.get("endpoint") or ""
        comp = Component(component_class="mcp_server", name=name)
        comp.set("endpoint", endpoint)
        comp.set("tls", endpoint.startswith("https://"))
        comp.set("authConfigured", bool(entry.get("auth") or entry.get("token") or entry.get("apiKey")))
        tools = entry.get("tools")
        if tools is not None:
            comp.set("toolCount", len(tools))
        out.append(comp)
    return out
