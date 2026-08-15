from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional


class _FallbackFastMCP:
    def __init__(self, name: str):
        self.name = name
        self._tools: Dict[str, Dict[str, Any]] = {}

    def tool(self, *, name: Optional[str] = None, description: Optional[str] = None):
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
            }
            for metadata in self._tools.values()
        ]


def _load_fastmcp_from_fastmcp_package() -> Optional[type]:
    try:
        module = importlib.import_module("fastmcp")
    except Exception:
        return None
    return getattr(module, "FastMCP", None)


def _load_fastmcp_from_external_mcp_sdk() -> Optional[type]:
    try:
        dist = importlib.metadata.distribution("mcp")
    except importlib.metadata.PackageNotFoundError:
        return None

    repo_root = Path(__file__).resolve().parents[1]
    dist_root = str(dist.locate_file(""))
    original_sys_path = sys.path[:]
    local_modules = {name: module for name, module in sys.modules.items() if name == "mcp" or name.startswith("mcp.")}

    try:
        filtered_path = []
        for entry in original_sys_path:
            try:
                resolved = Path(entry or ".").resolve()
            except Exception:
                resolved = None
            if resolved == repo_root:
                continue
            filtered_path.append(entry)

        if dist_root not in filtered_path:
            filtered_path.insert(0, dist_root)

        for module_name in local_modules:
            sys.modules.pop(module_name, None)
        sys.path = filtered_path
        module = importlib.import_module("mcp.server.fastmcp")
        return getattr(module, "FastMCP", None)
    except Exception:
        return None
    finally:
        sys.path = original_sys_path
        for module_name, module in local_modules.items():
            sys.modules[module_name] = module


def _resolve_fastmcp_class() -> type:
    for loader in (_load_fastmcp_from_fastmcp_package, _load_fastmcp_from_external_mcp_sdk):
        fastmcp_class = loader()
        if fastmcp_class is not None:
            return fastmcp_class
    return _FallbackFastMCP


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
        }
        return func

    return decorator


def _tool_schema(properties: Optional[Dict[str, Any]] = None, required: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    schema = {"type": "object", "properties": properties or {}}
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


def _normalize_tool(tool: Any) -> Dict[str, Any]:
    if isinstance(tool, dict):
        return {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema"),
            "outputSchema": tool.get("outputSchema"),
            "capability_level": tool.get("capability_level"),
        }

    func = getattr(tool, "func", None)
    default_name = func.__name__ if callable(func) and hasattr(func, "__name__") else None
    return {
        "name": getattr(tool, "name", None) or default_name,
        "description": getattr(tool, "description", None),
        "inputSchema": getattr(tool, "inputSchema", None),
        "outputSchema": getattr(tool, "outputSchema", None),
        "capability_level": getattr(tool, "capability_level", None),
    }


class MCPToolServer:
    def __init__(self, name: str = "OSINT Assistant MCP"):
        self.server = _resolve_fastmcp_class()(name)
        self._registered_tools: Dict[str, Dict[str, Any]] = {}
        self._load_registered_tools()

    def _load_registered_tools(self) -> None:
        _discover_modules()
        for metadata in sorted(TOOL_REGISTRY.values(), key=lambda item: item["name"]):
            self.register_tool(metadata)

    def register_tool(self, metadata: Dict[str, Any]) -> None:
        if metadata["name"] in self._registered_tools:
            return
        func = metadata["function"]
        self.server.tool(name=metadata["name"], description=metadata["description"])(func)
        self._registered_tools[metadata["name"]] = metadata

    async def list_tools_async(self) -> list[Dict[str, Any]]:
        try:
            server_tools = self.server.list_tools()
            if inspect.isawaitable(server_tools):
                server_tools = await server_tools
        except Exception:
            return []

        normalized_tools = [_normalize_tool(tool) for tool in (server_tools or [])]
        for tool in normalized_tools:
            metadata = TOOL_REGISTRY.get(tool.get("name"))
            if metadata is None:
                continue
            if tool.get("description") is None:
                tool["description"] = metadata["description"]
            if tool.get("inputSchema") is None:
                tool["inputSchema"] = metadata["input_schema"]
            if tool.get("outputSchema") is None:
                tool["outputSchema"] = metadata["output_schema"]
            if tool.get("capability_level") is None:
                tool["capability_level"] = metadata["capability_level"]
        return normalized_tools

    def list_tools(self) -> list[Dict[str, Any]]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.list_tools_async())
        raise RuntimeError("list_tools() cannot run inside an active event loop; use list_tools_async() instead.")


def create_server(name: str = "OSINT Assistant MCP") -> MCPToolServer:
    return MCPToolServer(name=name)


__all__ = [
    "MCPToolServer",
    "TOOL_REGISTRY",
    "_tool_schema",
    "create_server",
    "mcp_tool",
]
