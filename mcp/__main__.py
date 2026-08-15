import argparse

from .server import create_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the OSINT Assistant MCP server")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for HTTP transport if enabled",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for HTTP transport if enabled",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse"],
        help="MCP transport",
    )
    args = parser.parse_args()

    server = create_server(name="OSINT Assistant MCP")
    tools = server.list_tools()
    print(f"Loaded {len(tools)} MCP tools:")
    for tool in tools:
        print(f"- {tool['name']} [{tool.get('capability_level', 'unknown')}]")

    run = getattr(server.server, "run", None)
    if not callable(run):
        print("The installed MCP SDK does not expose a run() method in this environment.")
        return

    run_kwargs = {"transport": args.transport}
    if args.transport != "stdio":
        run_kwargs.update({"host": args.host, "port": args.port})

    try:
        run(**run_kwargs)
    except TypeError:
        run(transport=args.transport)


if __name__ == "__main__":
    main()
