"""Live MCP tool probing over HTTP transports only (v0.12.0) -- opt-in,
network-requiring enrichment, deliberately separate from `scan`'s own
otherwise fully offline collection. Same "opt-in extra step, never on
by default" discipline vex.py's OSV enrichment already established for
`scan-vulns`.

Implements the REAL MCP wire protocol (2025-06-18 specification,
confirmed against the official spec at modelcontextprotocol.io before
writing a line of this file -- not assumed), Streamable HTTP transport
only:

    1. POST `initialize`                 -- MUST happen first, no skipping it
    2. POST `notifications/initialized`  -- completes the mandatory handshake
    3. POST `tools/list` (paginated via cursor/nextCursor)

`stdio` and legacy SSE-framed transports are explicitly out of scope --
see collectors/mcp.py's own `transport` field. stdio needs subprocess
management (deferred to 0.13.0 per SPEC.md's own staged plan); legacy
SSE is a different wire framing than the Streamable HTTP this module
speaks, and guessing at it would be exactly the kind of unconfirmed
protocol shape this project refuses to ship.

Auth: deliberately NEVER sent. This project never reads a credential
*value* anywhere, only env var *names* (see collectors/mcp.py's own
`_CREDENTIAL_ENV_PATTERN` docstring) -- there is no real credential
value on hand to send even if this module wanted to. An authenticated
server simply answers 401/403, which surfaces as an ordinary probe
failure below, same as any other unreachable server -- never a reason
to go looking for a credential this project has deliberately never
collected.

Every failure (timeout, connection refused, malformed response, a
cross-host redirect refused below) is a warning, never fatal -- same
"missing pieces are never invisible, but never fatal either" discipline
`scan-vulns` (vex.py, v0.9.1) already established. `apply_mcp_probing()`
is the single entry point cli.py calls; it mutates an already-collected
HarnessDocument in place and returns nothing -- callers read the result
off `doc.warnings` and the document's own components afterward.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .collectors.mcp import _risk_class
from .fingerprint import canonical_json_sha256, sha256_text
from .model import Component, HarnessDocument

MCP_PROTOCOL_VERSION = "2025-06-18"

#: Fixed, explainable keyword list for `_has_imperative_language()` --
#: never a model judgment call, same "named rule, not an opaque score"
#: discipline security.py's own risk rules already follow. Matched
#: case-insensitively as substrings. Deliberately narrow and literal:
#: false negatives (a cleverly-worded injection this list misses) are
#: expected and acceptable -- this is one honest signal, not a detector.
_IMPERATIVE_PHRASES = (
    "always", "never", "ignore", "before you", "do not tell", "don't tell",
    "do not reveal", "don't reveal", "do not mention", "don't mention",
    "must not", "you must", "before calling any other tool",
    "before using any other tool",
)


def _has_imperative_language(description: str) -> bool:
    lname = description.lower()
    return any(phrase in lname for phrase in _IMPERATIVE_PHRASES)


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses a redirect whose target host differs from the request's
    own original host -- an explicit, security-relevant requirement
    (never let a configured MCP endpoint silently redirect this probe
    to a different host), not an oversight. A same-host redirect (path-
    only, or a scheme change on the same host) is still followed
    normally -- only the cross-host case is refused.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        original_host = urlsplit(req.full_url).hostname
        new_host = urlsplit(newurl).hostname
        if new_host != original_host:
            raise urllib.error.URLError(
                f"refusing to follow redirect from {original_host!r} to a different host {new_host!r}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _post_jsonrpc(opener, url: str, payload: dict, session_id: str | None, timeout: float):
    """One JSON-RPC-over-HTTP round trip. Returns (parsed_body_or_None,
    session_id). `parsed_body` is None for a *notification*'s reply (no
    `id`, no JSON-RPC body expected -- the spec says the server answers
    202 with an empty body). Raises on any transport-level failure
    (timeout, connection refused, non-2xx, malformed JSON, an
    unsupported event-stream response) -- `probe_mcp_server()` wraps the
    whole handshake in one try/except, never per-request, so a failure
    partway through never leaves a component half-updated.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with opener.open(req, timeout=timeout) as resp:
        new_session_id = resp.headers.get("Mcp-Session-Id") or session_id
        raw = resp.read()
        if resp.status == 202 or not raw:
            return None, new_session_id
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            # Streamable HTTP allows a server to answer with either a
            # single JSON body or a text/event-stream -- this probe only
            # speaks the plain-JSON half of that, honestly: an event-
            # stream response is treated as a probe failure rather than
            # guessed at or partially parsed.
            raise ValueError(f"unsupported response Content-Type {content_type!r} (event-stream not supported)")
        return json.loads(raw), new_session_id


def probe_mcp_server(url: str, timeout: float) -> dict:
    """One server's full probe: the mandatory initialize -> initialized
    -> tools/list handshake (paginated), against Streamable HTTP only.
    Never raises -- always returns a dict with a `status` key
    ("succeeded" | "failed"); a failure carries `error` (a short, safe-
    to-print string, no credential ever touched) instead of `tools`.
    """
    opener = urllib.request.build_opener(_SameHostRedirectHandler)
    try:
        init_result, session_id = _post_jsonrpc(
            opener,
            url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "agent-harness-aibom", "version": "0.12.0"},
                },
            },
            None,
            timeout,
        )
        if not init_result or "result" not in init_result:
            return {"status": "failed", "error": "initialize did not return a result"}

        # Fire-and-forget per spec (a notification carries no `id`, and
        # gets no JSON-RPC reply) -- still sent through the same
        # try/except as everything else, so a server that errors on it
        # still surfaces as an honest probe failure instead of silently
        # continuing to tools/list against a handshake that never
        # actually completed.
        _post_jsonrpc(opener, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id, timeout)

        tools: list[dict] = []
        cursor = None
        # A misbehaving server could paginate forever -- capped, not
        # unbounded, same "never trust a remote peer to be well-behaved"
        # reasoning as every other network call in this project (see
        # vex.py's own OSV query handling).
        for _ in range(50):
            params = {"cursor": cursor} if cursor else {}
            list_result, session_id = _post_jsonrpc(
                opener,
                url,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": params},
                session_id,
                timeout,
            )
            if not list_result or "result" not in list_result:
                return {"status": "failed", "error": "tools/list did not return a result"}
            page = list_result["result"]
            tools.extend(page.get("tools", []))
            cursor = page.get("nextCursor")
            if not cursor:
                break

        return {"status": "succeeded", "tools": tools}
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as exc:
        return {"status": "failed", "error": str(exc)}


def _tool_hashes(tool: dict) -> dict:
    """The real, probed identity of one live tool -- extends v0.11.0's
    `definitionSha256` recipe (fingerprint.py's `canonical_json_sha256`,
    never changed, only ever given more to cover) from `{"name": ...}`
    to `{"name", "description", "inputSchema"}`, so a document produced
    before and after a probe stays comparable on the same axis instead
    of switching hash families.
    """
    name = tool.get("name", "")
    description = tool.get("description") or ""
    input_schema = tool.get("inputSchema")
    result = {
        "definitionSha256": canonical_json_sha256(
            {"name": name, "description": description, "inputSchema": input_schema}
        ),
        "descriptionSha256": sha256_text(description),
        "descriptionLength": len(description),
        "hasImperativeLanguage": _has_imperative_language(description),
    }
    if input_schema is not None:
        result["schemaSha256"] = canonical_json_sha256(input_schema)
    return result


def apply_mcp_probing(doc: HarnessDocument, timeout: float) -> None:
    """Probes every already-collected `mcp_server` component whose
    transport is plain HTTP (Streamable HTTP -- not stdio, not legacy
    SSE, see this module's own docstring), and updates its `tool`
    children in place. Mutates `doc`; returns nothing.

    A live tool the static config never declared is added as a new
    `tool` child -- the entire point of a live probe is ground truth,
    and a config's own `tools` list can be stale, incomplete, or simply
    absent. A statically-declared tool the live server no longer lists
    is left untouched (still `name-only`, not removed) -- its absence
    from one live response is not proof it was removed, just that this
    probe didn't see it right now.
    """
    servers = [c for c in doc.components if c.component_class == "mcp_server"]
    for server in servers:
        transport = server.properties.get("transport")
        endpoint = server.properties.get("endpoint")
        if transport != "http" or not endpoint:
            continue  # stdio and sse are out of scope for this release -- see module docstring

        outcome = probe_mcp_server(endpoint, timeout)
        server.set("probeStatus", outcome["status"])
        if outcome["status"] != "succeeded":
            server.set("probeError", outcome.get("error", "unknown error"))
            doc.warn(f"MCP probe failed for {server.name} ({endpoint}): {outcome.get('error', 'unknown error')}")
            continue

        existing_tools = {
            c.name: c
            for c in doc.components
            if c.component_class == "tool" and c.properties.get("server") == server.name
        }
        live_count = 0
        for live_tool in outcome["tools"]:
            tool_name = str(live_tool.get("name") or "")
            if not tool_name:
                continue
            live_count += 1
            full_name = f"{server.name}/{tool_name}"
            hashes = _tool_hashes(live_tool)

            existing = existing_tools.get(full_name)
            # v1.0.0: whether the static config actually named this tool
            # is itself a real, security-relevant signal -- a server
            # advertising a tool the operator never configured is one of
            # the strongest things a live probe can surface, and it used
            # to be indistinguishable from an ordinary, expected tool.
            # `declaredInConfig` is recorded explicitly either way (never
            # only on the interesting case), so its *absence* still means
            # exactly one thing: this tool was never live-probed at all,
            # not "presumed declared".
            declared_in_config = existing is not None
            if existing is None:
                existing = Component(component_class="tool", name=full_name)
                existing.set("server", server.name)
                existing.set("riskClass", _risk_class(tool_name))
                doc.add_child(existing, server, "uses")

            existing.set("definitionScope", "probed")
            existing.set("declaredInConfig", declared_in_config)
            for key, value in hashes.items():
                existing.set(key, value)

        server.set("probedToolCount", live_count)
