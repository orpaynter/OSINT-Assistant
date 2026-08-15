from __future__ import annotations

import asyncio
import importlib
import inspect
import pkgutil
import threading
from typing import Any, Callable, Dict, Iterable, Optional


try:
    from fastmcp import FastMCP
except Exception:  # pragma: no cover - fallback for minimal local test environments
    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, name: str):
            self.name = name
            self._tools: Dict[str, Dict[str, Any]] = {}

        def tool(
            self,
            *,
            name: Optional[str] = None,
            description: Optional[str] = None,
        ):
            def decorator(func: Callable[..., Any]):
                tool_name = name or func.__name__
                self._tools[tool_name] = {
                    "name": tool_name,
                    "description": description or func.__doc__ or tool_name,
                    "function": func,
                }
                return func

            return decorator

        def list_tools(self):
            return [
                {
                    "name": metadata["name"],
                    "description": metadata["description"],
                    "inputSchema": metadata.get("input_schema"),
                    "outputSchema": metadata.get("output_schema"),
                    "capability_level": metadata.get("capability_level"),
                }
                for metadata in self._tools.values()
            ]


TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}


def mcp_tool(
    *,
    name: str,
    description: str,
    input_schema: Optional[Dict[str, Any]] = None,
    output_schema: Optional[Dict[str, Any]] = None,
    capability_level: str = "clearnet",
):
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        TOOL_REGISTRY[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema or {"type": "object", "properties": {}},
            "output_schema": output_schema or {"type": "object", "properties": {}},
            "capability_level": capability_level,
            "function": func,
            "registered": False,
        }
        return func

    return decorator


def _tool_schema(
    properties: Optional[Dict[str, Any]] = None,
    required: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required is not None:
        schema["required"] = list(required)
    return schema


def _discover_modules() -> None:
    for package_name in ("addons", "providers"):
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            continue

        if not hasattr(package, "__path__"):
            continue

        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            full_name = f"{package_name}.{module_name}"
            try:
                importlib.import_module(full_name)
            except Exception:
                continue


def _resolve_maybe_awaitable(value: Any) -> Any:
    if not inspect.isawaitable(value):
        return value

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(value)

    result: Dict[str, Any] = {}

    def _runner() -> None:
        result["value"] = asyncio.run(value)

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    return result.get("value")


class MCPToolServer:
    def __init__(self, name: str = "OSINT Assistant MCP"):
        self.server = FastMCP(name)
        self._tool_names: Dict[str, Dict[str, Any]] = {}
        self._load_registered_tools()

    def _load_registered_tools(self) -> None:
        _discover_modules()
        for metadata in sorted(TOOL_REGISTRY.values(), key=lambda item: item["name"]):
            if metadata["registered"]:
                self._tool_names[metadata["name"]] = metadata
                continue
            self.register_tool(metadata)

    def register_tool(self, metadata: Dict[str, Any]) -> None:
        func = metadata["function"]
        self.server.tool(name=metadata["name"], description=metadata["description"])(func)
        metadata["registered"] = True
        self._tool_names[metadata["name"]] = metadata

    def list_tools(self) -> list[Dict[str, Any]]:
        try:
            server_tools = _resolve_maybe_awaitable(self.server.list_tools())
        except Exception:
            server_tools = []

        if server_tools:
            tools: list[Dict[str, Any]] = []
            for tool in server_tools:
                if isinstance(tool, dict):
                    tool_name = tool.get("name")
                    metadata = self._tool_names.get(tool_name, {}) if tool_name else {}
                    tools.append(
                        {
                            "name": tool_name,
                            "description": tool.get("description") or metadata.get("description"),
                            "inputSchema": tool.get("inputSchema") or metadata.get("input_schema"),
                            "outputSchema": tool.get("outputSchema") or metadata.get("output_schema"),
                            "capability_level": tool.get("capability_level")
                            or metadata.get("capability_level"),
                        }
                    )
                else:
                    tool_func = getattr(tool, "func", None)
                    name = getattr(tool, "name", None) or (
                        getattr(tool_func, "__name__", None) if tool_func is not None else None
                    )
                    metadata = self._tool_names.get(name, {}) if name else {}
                    tools.append(
                        {
                            "name": name,
                            "description": getattr(tool, "description", None)
                            or metadata.get("description"),
                            "inputSchema": getattr(tool, "inputSchema", None)
                            or metadata.get("input_schema"),
                            "outputSchema": getattr(tool, "outputSchema", None)
                            or metadata.get("output_schema"),
                            "capability_level": getattr(tool, "capability_level", None)
                            or metadata.get("capability_level"),
                        }
                    )
            return tools

        return [
            {
                "name": metadata["name"],
                "description": metadata["description"],
                "inputSchema": metadata["input_schema"],
                "outputSchema": metadata["output_schema"],
                "capability_level": metadata["capability_level"],
            }
            for metadata in sorted(TOOL_REGISTRY.values(), key=lambda item: item["name"])
        ]


def create_server(name: str = "OSINT Assistant MCP") -> MCPToolServer:
    return MCPToolServer(name=name)


__all__ = [
    "MCPToolServer",
    "TOOL_REGISTRY",
    "_tool_schema",
    "create_server",
    "mcp_tool",
]
