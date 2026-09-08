from harness_aibom.collectors.mcp import extract_mcp_servers


def by_name(servers, name):
    return next(s for s in servers if s.name == name)


def test_http_server_with_no_auth():
    config = {"mcp_servers": [{"name": "local-time", "url": "http://127.0.0.1:8001"}]}
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "http"
    assert server.properties["tls"] == "False"
    assert server.properties["authConfigured"] == "False"
    assert "command" not in server.properties


def test_https_server_with_token_auth():
    config = {
        "mcp_servers": [
            {"name": "corp-docs", "url": "https://mcp.corp.lab:8443", "auth": {"token": "x"}, "tools": ["a", "b"]}
        ]
    }
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "http"
    assert server.properties["tls"] == "True"
    assert server.properties["authConfigured"] == "True"
    assert server.properties["toolCount"] == "2"


def test_stdio_server_gets_correct_transport_and_no_misleading_tls():
    # Regression test: a stdio entry (command/args/env, no url) used to
    # come out as tls=False and authConfigured=False, both wrong -- there
    # is no network transport for "no TLS" to describe, and the env var
    # is a real credential the old code never looked at.
    config = {
        "mcp_servers": [
            {
                "name": "local-fs",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                "env": {"API_KEY": "secret"},
                "tools": ["read_file", "write_file", "move_file"],
            }
        ]
    }
    [server] = extract_mcp_servers(config)

    assert server.properties["transport"] == "stdio"
    assert server.properties["tls"] == "n/a"
    assert server.properties["authConfigured"] == "True"
    assert server.properties["envKeys"] == "API_KEY"
    # never the credential value, only that the env var exists
    assert all("secret" not in v for v in server.properties.values())

    assert server.properties["command"] == "npx"
    assert server.properties["args"] == "-y @modelcontextprotocol/server-filesystem /"
    assert server.properties["toolCount"] == "3"


def test_stdio_server_with_no_env_has_no_declared_auth():
    config = {"mcp_servers": [{"name": "local-calc", "command": "calc-mcp"}]}
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "stdio"
    assert server.properties["authConfigured"] == "False"
    assert "envKeys" not in server.properties


def test_explicit_transport_overrides_inference():
    config = {"mcp_servers": [{"name": "streamed", "url": "https://mcp.example/sse", "transport": "sse"}]}
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "sse"


def test_no_mcp_servers_key_returns_empty():
    assert extract_mcp_servers({}) == []


def test_non_credential_env_names_do_not_set_authconfigured():
    # Regression test: an independent reviewer found `authConfigured` was
    # true for *any* non-empty env dict -- a stdio server with only
    # NODE_ENV/LOG_LEVEL read as credential-bearing, a false positive
    # hiding the real question.
    config = {
        "mcp_servers": [
            {"name": "no-secret-env", "command": "x", "env": {"NODE_ENV": "production", "LOG_LEVEL": "debug"}}
        ]
    }
    [server] = extract_mcp_servers(config)
    assert server.properties["authConfigured"] == "False"
    assert server.properties["envKeys"] == "LOG_LEVEL,NODE_ENV"
    assert "authEnvKeys" not in server.properties


def test_credential_shaped_env_names_do_set_authconfigured():
    config = {
        "mcp_servers": [
            {"name": "with-secret", "command": "x", "env": {"NODE_ENV": "production", "GITHUB_TOKEN": "x"}}
        ]
    }
    [server] = extract_mcp_servers(config)
    assert server.properties["authConfigured"] == "True"
    assert server.properties["authEnvKeys"] == "GITHUB_TOKEN"


def test_sse_substring_in_hostname_does_not_misdetect_transport():
    # Regression test: an independent reviewer found "sse" in endpoint
    # (a plain substring test) misread "https://assets.example.com/mcp"
    # as an SSE transport, because "assets" contains "sse".
    config = {"mcp_servers": [{"name": "assets-host", "url": "https://assets.example.com/mcp"}]}
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "http"


def test_sse_path_suffix_is_still_detected():
    config = {"mcp_servers": [{"name": "streamed", "url": "https://mcp.example/events/sse"}]}
    [server] = extract_mcp_servers(config)
    assert server.properties["transport"] == "sse"
