from mcp.server import create_server


def test_mcp_server_lists_all_addons():
    server = create_server()
    tools = server.list_tools()
    names = {tool["name"] for tool in tools}

    expected = {
        "web_search",
        "searxng_search",
        "tor_fetch",
        "content_analyzer",
        "aia_verify",
        "aia_signals_ingest",
    }

    assert expected.issubset(names)
    assert {tool["capability_level"] for tool in tools if tool["name"] in expected} == {
        "clearnet",
        "tor",
        "local-llm",
        "governed",
    }

    assert all("inputSchema" in tool for tool in tools)
    assert all("outputSchema" in tool for tool in tools)

