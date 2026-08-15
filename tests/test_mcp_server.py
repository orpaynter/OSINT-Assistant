from __future__ import annotations

import asyncio
import importlib
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from addons import osint_addons
from mcp import __main__ as mcp_main
from mcp import server as mcp_server


class RecordingFastMCP:
    def __init__(self, name: str):
        self.name = name
        self._tools = {}

    def tool(self, *, name=None, description=None, input_schema=None, output_schema=None, capability_level=None):
        def decorator(func):
            tool_name = name or func.__name__
            self._tools[tool_name] = {
                "name": tool_name,
                "description": description,
                "inputSchema": input_schema,
                "outputSchema": output_schema,
                "capability_level": capability_level,
                "function": func,
            }
            return func

        return decorator

    def list_tools(self):
        return [{"name": name, "description": metadata["description"], "inputSchema": metadata.get("inputSchema"), "outputSchema": metadata.get("outputSchema"), "capability_level": metadata.get("capability_level")} for name, metadata in self._tools.items()]


class MCPAddonSchemaTests(unittest.TestCase):
    def test_web_search_max_results_bounds_schema_and_behavior(self):
        max_results_schema = osint_addons.WEB_SEARCH_INPUT["properties"]["max_results"]
        self.assertEqual(max_results_schema["minimum"], 1)
        self.assertEqual(max_results_schema["maximum"], 11)
        self.assertEqual(len(osint_addons.web_search("query", max_results=0)["results"]), 1)
        self.assertEqual(len(osint_addons.web_search("query", max_results=999)["results"]), 11)

    def test_aia_verify_output_schema_matches_payload(self):
        payload = osint_addons.aia_verify("https://example.org")
        schema = osint_addons.AIA_VERIFY_OUTPUT
        self.assertIn("policy", schema["properties"])
        for key in schema["required"]:
            self.assertIn(key, payload)


class MCPCLITests(unittest.TestCase):
    def test_stdio_main_writes_no_stdout(self):
        class StdIOServer:
            def __init__(self):
                self.calls = []

            def run(self, *, transport):
                self.calls.append({"transport": transport})

        fake_wrapper = SimpleNamespace(
            list_tools=lambda: [{"name": "web_search", "capability_level": "clearnet"}],
            server=StdIOServer(),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("mcp.__main__.create_server", return_value=fake_wrapper):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = mcp_main.main(["--transport", "stdio"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(fake_wrapper.server.calls, [{"transport": "stdio"}])

    def test_missing_run_diagnostic_is_stderr_only(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            mcp_main._run_server(object(), transport="stdio", host="127.0.0.1", port=8000)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("does not expose a run()", stderr.getvalue())

    def test_run_server_stdio_signature(self):
        class Server:
            def __init__(self):
                self.received = None

            def run(self, *, transport):
                self.received = transport

        server = Server()
        mcp_main._run_server(server, transport="stdio", host="127.0.0.1", port=8000)
        self.assertEqual(server.received, "stdio")

    def test_run_server_sse_signature(self):
        class Server:
            def __init__(self):
                self.received = None

            def run(self, *, transport, host, port):
                self.received = (transport, host, port)

        server = Server()
        mcp_main._run_server(server, transport="sse", host="0.0.0.0", port=9000)
        self.assertEqual(server.received, ("sse", "0.0.0.0", 9000))

    def test_run_server_typeerror_bubbles_up(self):
        class Server:
            def run(self, *, transport):
                raise TypeError("internal failure")

        with self.assertRaises(TypeError):
            mcp_main._run_server(Server(), transport="stdio", host="127.0.0.1", port=8000)


class MCPServerTests(unittest.TestCase):
    def test_each_server_instance_registers_tools_on_its_own_server(self):
        with mock.patch("mcp.server._resolve_fastmcp_class", return_value=RecordingFastMCP):
            server_one = mcp_server.MCPToolServer(name="one")
            server_two = mcp_server.MCPToolServer(name="two")

        expected_names = set(mcp_server.TOOL_REGISTRY.keys())
        self.assertTrue(expected_names)
        self.assertTrue(expected_names.issubset(set(server_one.server._tools.keys())))
        self.assertTrue(expected_names.issubset(set(server_two.server._tools.keys())))
        for tool_name in expected_names:
            self.assertTrue(callable(server_one.server._tools[tool_name]["function"]))
            self.assertTrue(callable(server_two.server._tools[tool_name]["function"]))

    def test_list_tools_does_not_fallback_to_registry_when_backend_is_empty(self):
        class EmptyListFastMCP(RecordingFastMCP):
            def list_tools(self):
                return []

        with mock.patch("mcp.server._resolve_fastmcp_class", return_value=EmptyListFastMCP):
            server = mcp_server.MCPToolServer(name="empty")
            self.assertEqual(server.list_tools(), [])

    def test_list_tools_normalizes_dict_entries(self):
        class DictListFastMCP(RecordingFastMCP):
            def list_tools(self):
                return [{"name": "web_search"}]

        with mock.patch("mcp.server._resolve_fastmcp_class", return_value=DictListFastMCP):
            server = mcp_server.MCPToolServer(name="dict")
            tools = server.list_tools()

        self.assertEqual(tools[0]["name"], "web_search")
        self.assertEqual(tools[0]["capability_level"], "clearnet")
        self.assertIn("inputSchema", tools[0])

    def test_list_tools_normalizes_object_entries(self):
        class ObjectListFastMCP(RecordingFastMCP):
            def list_tools(self):
                return [SimpleNamespace(name="web_search", description=None, inputSchema=None, outputSchema=None, capability_level=None)]

        with mock.patch("mcp.server._resolve_fastmcp_class", return_value=ObjectListFastMCP):
            server = mcp_server.MCPToolServer(name="object")
            tools = server.list_tools()

        self.assertEqual(tools[0]["name"], "web_search")
        self.assertEqual(tools[0]["capability_level"], "clearnet")
        self.assertIsNotNone(tools[0]["outputSchema"])

    def test_list_tools_supports_async_backend(self):
        class AsyncListFastMCP(RecordingFastMCP):
            async def list_tools(self):
                return [{"name": "web_search"}]

        with mock.patch("mcp.server._resolve_fastmcp_class", return_value=AsyncListFastMCP):
            server = mcp_server.MCPToolServer(name="async")
            tools_sync = server.list_tools()
            tools_async = asyncio.run(server.list_tools_async())

        self.assertEqual(tools_sync[0]["name"], "web_search")
        self.assertEqual(tools_async[0]["capability_level"], "clearnet")

    def test_sdk_resolution_prefers_non_colliding_import_path(self):
        class ExternalFastMCP:
            pass

        with mock.patch("mcp.server._load_fastmcp_from_fastmcp_package", return_value=ExternalFastMCP), mock.patch(
            "mcp.server._load_fastmcp_from_external_mcp_sdk", return_value=None
        ):
            self.assertIs(mcp_server._resolve_fastmcp_class(), ExternalFastMCP)

    def test_sdk_resolution_falls_back_cleanly(self):
        with mock.patch("mcp.server._load_fastmcp_from_fastmcp_package", return_value=None), mock.patch(
            "mcp.server._load_fastmcp_from_external_mcp_sdk", return_value=None
        ):
            self.assertIs(mcp_server._resolve_fastmcp_class(), mcp_server._FallbackFastMCP)

    def test_external_sdk_loader_returns_none_when_distribution_missing(self):
        with mock.patch("mcp.server.importlib.metadata.distribution", side_effect=importlib.metadata.PackageNotFoundError):
            self.assertIsNone(mcp_server._load_fastmcp_from_external_mcp_sdk())


if __name__ == "__main__":
    unittest.main()
