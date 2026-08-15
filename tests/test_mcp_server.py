from __future__ import annotations

import mcp
from addons import osint_addons
from mcp import TOOL_REGISTRY, create_server


EXPECTED_TOOLS = {
    "web_search": "clearnet",
    "searxng_search": "clearnet",
    "tor_fetch": "tor",
    "content_analyzer": "local-llm",
    "aia_verify": "governed",
    "aia_signals_ingest": "governed",
}


def test_public_exports() -> None:
    assert mcp.MCPToolServer is not None
    assert mcp.create_server is create_server
    assert isinstance(mcp.TOOL_REGISTRY, dict)
    assert callable(mcp._tool_schema)
    assert callable(mcp.mcp_tool)


def test_tool_schema_builder() -> None:
    schema = mcp._tool_schema(
        {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 5},
        },
        required=["query"],
    )
    assert schema["type"] == "object"
    assert schema["properties"]["limit"]["default"] == 5
    assert schema["required"] == ["query"]


def test_registered_tool_metadata() -> None:
    for tool_name, capability_level in EXPECTED_TOOLS.items():
        assert tool_name in TOOL_REGISTRY
        assert TOOL_REGISTRY[tool_name]["capability_level"] == capability_level
        assert TOOL_REGISTRY[tool_name]["input_schema"]["type"] == "object"
        assert TOOL_REGISTRY[tool_name]["output_schema"]["type"] == "object"


def test_server_discovers_and_lists_all_tools() -> None:
    server = create_server(name="test-mcp")
    tools = server.list_tools()
    names = {tool["name"] for tool in tools}

    assert EXPECTED_TOOLS.keys() <= names

    by_name = {tool["name"]: tool for tool in tools}
    for tool_name, capability_level in EXPECTED_TOOLS.items():
        assert by_name[tool_name]["capability_level"] == capability_level


def test_web_search_bounds_and_defaults() -> None:
    bounded = osint_addons.web_search("unit test", max_results=999)
    assert bounded["query"] == "unit test"
    assert len(bounded["results"]) == 5
    assert bounded["capability_level"] == "clearnet"

    minimum = osint_addons.web_search("unit test", max_results=0)
    assert len(minimum["results"]) == 1


def test_tor_fetch_preview_limit() -> None:
    payload = osint_addons.tor_fetch("http://exampleonion.onion", max_bytes=12)
    assert payload["status"] == "ok"
    assert len(payload["content_preview"]) <= 12
    assert payload["capability_level"] == "tor"


def test_fallback_environment_server_creation() -> None:
    server = create_server(name="fallback-check")
    assert server.server is not None
    assert isinstance(server.list_tools(), list)
