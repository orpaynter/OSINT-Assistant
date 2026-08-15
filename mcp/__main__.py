from __future__ import annotations

import argparse
import inspect
import sys
from typing import Any, Dict

from .server import create_server


def _run_server(server: Any, *, transport: str, host: str, port: int) -> Any:
    run_callable = getattr(server, "run", None)
    if not callable(run_callable):
        print("The installed MCP SDK does not expose a run() method in this environment.", file=sys.stderr)
        return None

    signature = inspect.signature(run_callable)
    supports_kwargs = any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values())

    def _supports(name: str) -> bool:
        return supports_kwargs or name in signature.parameters

    run_kwargs: Dict[str, Any] = {}
    if _supports("transport"):
        run_kwargs["transport"] = transport
    if transport != "stdio":
        if _supports("host"):
            run_kwargs["host"] = host
        if _supports("port"):
            run_kwargs["port"] = port
    return run_callable(**run_kwargs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the OSINT Assistant MCP server")
    parser.add_argument("--host", default="127.0.0.1", help="Host for HTTP transport if enabled")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP transport if enabled")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"], help="MCP transport")
    args = parser.parse_args(argv)

    server = create_server(name="OSINT Assistant MCP")
    if args.transport != "stdio":
        tools = server.list_tools()
        print(f"Loaded {len(tools)} MCP tools:", file=sys.stderr)
        for tool in tools:
            print(f"- {tool.get('name', '<unknown>')} [{tool.get('capability_level', 'unknown')}]", file=sys.stderr)

    run_callable = getattr(server.server, "run", None)
    if not callable(run_callable):
        print(
            "No runnable MCP backend available. Install fastmcp: pip install fastmcp",
            file=sys.stderr,
        )
        return 1

    _run_server(server.server, transport=args.transport, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
