from harness_aibom.collectors.mcp import extract_mcp_servers


def only_server(config):
    """extract_mcp_servers now returns [(server, tools, package)] triples
    -- most tests here only care about the server itself."""
    [(server, _tools, _package)] = extract_mcp_servers(config)
    return server


def test_http_server_with_no_auth():
    config = {"mcp_servers": [{"name": "local-time", "url": "http://127.0.0.1:8001"}]}
    server = only_server(config)
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
    server = only_server(config)
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
    server = only_server(config)

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
    server = only_server(config)
    assert server.properties["transport"] == "stdio"
    assert server.properties["authConfigured"] == "False"
    assert "envKeys" not in server.properties


def test_explicit_transport_overrides_inference():
    config = {"mcp_servers": [{"name": "streamed", "url": "https://mcp.example/sse", "transport": "sse"}]}
    server = only_server(config)
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
    server = only_server(config)
    assert server.properties["authConfigured"] == "False"
    assert server.properties["envKeys"] == "LOG_LEVEL,NODE_ENV"
    assert "authEnvKeys" not in server.properties


def test_credential_shaped_env_names_do_set_authconfigured():
    config = {
        "mcp_servers": [
            {"name": "with-secret", "command": "x", "env": {"NODE_ENV": "production", "GITHUB_TOKEN": "x"}}
        ]
    }
    server = only_server(config)
    assert server.properties["authConfigured"] == "True"
    assert server.properties["authEnvKeys"] == "GITHUB_TOKEN"


def test_sse_substring_in_hostname_does_not_misdetect_transport():
    # Regression test: an independent reviewer found "sse" in endpoint
    # (a plain substring test) misread "https://assets.example.com/mcp"
    # as an SSE transport, because "assets" contains "sse".
    config = {"mcp_servers": [{"name": "assets-host", "url": "https://assets.example.com/mcp"}]}
    server = only_server(config)
    assert server.properties["transport"] == "http"


def test_sse_path_suffix_is_still_detected():
    config = {"mcp_servers": [{"name": "streamed", "url": "https://mcp.example/events/sse"}]}
    server = only_server(config)
    assert server.properties["transport"] == "sse"


# --- purl extraction -------------------------------------------------------


def test_npx_scoped_package_with_pinned_version():
    config = {
        "mcp_servers": [
            {"name": "fs", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0"]}
        ]
    }
    server = only_server(config)
    assert server.properties["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem@2.1.0"
    assert server.properties["versionPinned"] == "True"


def test_npx_scoped_package_unpinned():
    # The common real shape (confirmed from a live scan): no version at
    # all -- npx resolves "latest" fresh on every invocation.
    config = {"mcp_servers": [{"name": "fs", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]}]}
    server = only_server(config)
    assert server.properties["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem"
    assert server.properties["versionPinned"] == "False"


def test_npx_unscoped_package_with_version():
    config = {"mcp_servers": [{"name": "x", "command": "npx", "args": ["some-package@1.2.3"]}]}
    server = only_server(config)
    assert server.properties["purl"] == "pkg:npm/some-package@1.2.3"
    assert server.properties["versionPinned"] == "True"


def test_uvx_package_with_pinned_version():
    config = {"mcp_servers": [{"name": "x", "command": "uvx", "args": ["some_pkg==1.4.0"]}]}
    server = only_server(config)
    assert server.properties["purl"] == "pkg:pypi/some-pkg@1.4.0"
    assert server.properties["versionPinned"] == "True"


def test_uvx_package_unpinned():
    config = {"mcp_servers": [{"name": "x", "command": "uvx", "args": ["some_pkg"]}]}
    server = only_server(config)
    assert server.properties["purl"] == "pkg:pypi/some-pkg"
    assert server.properties["versionPinned"] == "False"


def test_unrecognized_launcher_gets_no_purl():
    config = {"mcp_servers": [{"name": "x", "command": "deno", "args": ["run", "server.ts"]}]}
    server = only_server(config)
    assert "purl" not in server.properties
    assert "versionPinned" not in server.properties


def test_no_args_gets_no_purl():
    config = {"mcp_servers": [{"name": "x", "command": "some-binary"}]}
    server = only_server(config)
    assert "purl" not in server.properties


# --- tool components --------------------------------------------------------


def test_one_tool_component_per_declared_tool_name():
    config = {
        "mcp_servers": [
            {"name": "local-fs", "command": "npx", "args": ["-y", "pkg"], "tools": ["read_file", "write_file", "move_file"]}
        ]
    }
    [(server, tools, _package)] = extract_mcp_servers(config)
    assert len(tools) == 3
    names = {t.name for t in tools}
    assert names == {"local-fs/read_file", "local-fs/write_file", "local-fs/move_file"}
    for tool in tools:
        assert tool.component_class == "tool"
        assert tool.properties["server"] == "local-fs"


def test_tool_risk_classification():
    config = {
        "mcp_servers": [
            {
                "name": "srv",
                "tools": ["read_file", "write_file", "execute_command", "fetch_url", "totally_unclear_thing"],
            }
        ]
    }
    [(_server, tools, _package)] = extract_mcp_servers(config)
    by_name = {t.name.split("/", 1)[1]: t for t in tools}
    assert by_name["read_file"].properties["riskClass"] == "read"
    assert by_name["write_file"].properties["riskClass"] == "write"
    assert by_name["execute_command"].properties["riskClass"] == "exec"
    assert by_name["fetch_url"].properties["riskClass"] == "network"
    assert by_name["totally_unclear_thing"].properties["riskClass"] == "unknown"


def test_no_tools_declared_gives_no_tool_components():
    config = {"mcp_servers": [{"name": "srv", "url": "https://x.example"}]}
    [(_server, tools, _package)] = extract_mcp_servers(config)
    assert tools == []


# --- the standalone `dependency` component (issue: purl was invisible to a
# generic SBOM tool as long as it lived only in a harness-aibom: property) ---


def test_recognized_launcher_also_returns_a_standalone_package_component():
    config = {
        "mcp_servers": [
            {"name": "fs", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0"]}
        ]
    }
    [(_server, _tools, package)] = extract_mcp_servers(config)
    assert package is not None
    assert package.component_class == "dependency"
    assert package.name == "@modelcontextprotocol/server-filesystem"
    assert package.version == "2.1.0"
    assert package.properties["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem@2.1.0"


def test_unpinned_package_component_has_no_version():
    config = {"mcp_servers": [{"name": "fs", "command": "npx", "args": ["-y", "some-package"]}]}
    [(_server, _tools, package)] = extract_mcp_servers(config)
    assert package is not None
    assert package.version is None
    assert package.properties["purl"] == "pkg:npm/some-package"


def test_url_based_server_has_no_package_component():
    config = {"mcp_servers": [{"name": "srv", "url": "https://x.example"}]}
    [(_server, _tools, package)] = extract_mcp_servers(config)
    assert package is None


# --- expanded risk keywords (a real reviewer probe found git_commit/
# git_status both misclassified as "unknown") ---------------------------


def test_expanded_risk_keywords_cover_common_git_style_tool_names():
    config = {"mcp_servers": [{"name": "git", "tools": ["git_status", "git_commit", "git_push"]}]}
    [(_server, tools, _package)] = extract_mcp_servers(config)
    by_name = {t.name.split("/", 1)[1]: t for t in tools}
    assert by_name["git_status"].properties["riskClass"] == "read"
    assert by_name["git_commit"].properties["riskClass"] == "write"
    assert by_name["git_push"].properties["riskClass"] == "write"
