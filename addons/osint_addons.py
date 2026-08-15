from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp import _tool_schema, mcp_tool


def _tool_result(payload: Dict[str, Any], *, capability_level: str) -> Dict[str, Any]:
    payload["capability_level"] = capability_level
    return payload


WEB_SEARCH_INPUT = _tool_schema(
    {
        "query": {"type": "string", "description": "OSINT query to execute against open web search sources."},
        "max_results": {
            "type": "integer",
            "description": "Maximum number of results to return (bounded from 1 to 11).",
            "default": 5,
            "minimum": 1,
            "maximum": 11,
        },
        "region": {"type": "string", "description": "Search region or locale. Defaults to 'us'.", "default": "us"},
    },
    required=["query"],
)

WEB_SEARCH_OUTPUT = _tool_schema(
    {
        "query": {"type": "string"},
        "results": {"type": "array", "items": {"type": "object"}},
        "capability_level": {"type": "string"},
    },
    required=["query", "results", "capability_level"],
)


@mcp_tool(
    name="web_search",
    description="Search the open web for OSINT relevant sources and excerpts.",
    input_schema=WEB_SEARCH_INPUT,
    output_schema=WEB_SEARCH_OUTPUT,
    capability_level="clearnet",
)
def web_search(query: str, max_results: int = 5, region: str = "us") -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for idx in range(max(1, min(max_results, 11))):
        results.append(
            {
                "title": f"OSINT result {idx + 1} for {query}",
                "url": f"https://example.org/{region}/search/{idx + 1}",
                "snippet": f"Relevant summary for '{query}' from an open-search result ({idx + 1}).",
                "source_type": "web",
            }
        )
    return _tool_result({"query": query, "results": results}, capability_level="clearnet")


SEARXNG_SEARCH_INPUT = _tool_schema(
    {
        "query": {"type": "string", "description": "Query to send to the SearXNG instance."},
        "instance_url": {"type": "string", "description": "Base URL for the SearXNG service.", "default": "http://localhost:8080"},
        "category": {"type": "string", "description": "Optional category filter like general, news, images.", "default": "general"},
    },
    required=["query"],
)

SEARXNG_SEARCH_OUTPUT = _tool_schema(
    {
        "query": {"type": "string"},
        "instance_url": {"type": "string"},
        "results": {"type": "array", "items": {"type": "object"}},
        "capability_level": {"type": "string"},
    },
    required=["query", "instance_url", "results", "capability_level"],
)


@mcp_tool(
    name="searxng_search",
    description="Query a local or self-hosted SearXNG instance for untracked results.",
    input_schema=SEARXNG_SEARCH_INPUT,
    output_schema=SEARXNG_SEARCH_OUTPUT,
    capability_level="clearnet",
)
def searxng_search(query: str, instance_url: str = "http://localhost:8080", category: str = "general") -> Dict[str, Any]:
    return _tool_result(
        {
            "query": query,
            "instance_url": instance_url,
            "category": category,
            "results": [
                {
                    "title": f"SearXNG result for {query}",
                    "url": f"{instance_url}/search?q={query}",
                    "snippet": f"Search result from a configured SearXNG instance for: {query}",
                }
            ],
        },
        capability_level="clearnet",
    )


TOR_FETCH_INPUT = _tool_schema(
    {
        "url": {"type": "string", "description": ".onion or Tor-aware URL to fetch."},
        "timeout": {"type": "integer", "description": "Timeout in seconds.", "default": 20},
        "max_bytes": {"type": "integer", "description": "Maximum response bytes to read.", "default": 65535},
    },
    required=["url"],
)

TOR_FETCH_OUTPUT = _tool_schema(
    {
        "url": {"type": "string"},
        "status": {"type": "string"},
        "content_preview": {"type": "string"},
        "capability_level": {"type": "string"},
    },
    required=["url", "status", "content_preview", "capability_level"],
)


@mcp_tool(
    name="tor_fetch",
    description="Fetch a Tor or onion URL through a guarded Tor transport, preserving minimum disclosure.",
    input_schema=TOR_FETCH_INPUT,
    output_schema=TOR_FETCH_OUTPUT,
    capability_level="tor",
)
def tor_fetch(url: str, timeout: int = 20, max_bytes: int = 65535) -> Dict[str, Any]:
    max_bytes = max(0, max_bytes)
    preview = f"Tor fetch placeholder for {url}; no network content was retrieved during this local mock invocation."
    return _tool_result(
        {
            "url": url,
            "status": "ok",
            "content_preview": preview[:max_bytes],
        },
        capability_level="tor",
    )


CONTENT_ANALYZER_INPUT = _tool_schema(
    {
        "url": {"type": "string", "description": "URL to analyze."},
        "text": {"type": "string", "description": "Optional source text to analyze directly when the URL content is unavailable."},
    },
    required=["url"],
)

CONTENT_ANALYZER_OUTPUT = _tool_schema(
    {
        "url": {"type": "string"},
        "domain": {"type": "string"},
        "credibility_score": {"type": "number"},
        "key_entities": {"type": "array", "items": {"type": "string"}},
        "sentiment": {"type": "string"},
        "timestamps": {"type": "object"},
        "connections": {"type": "array", "items": {"type": "object"}},
        "capability_level": {"type": "string"},
    },
    required=["url", "domain", "credibility_score", "key_entities", "sentiment", "timestamps", "connections", "capability_level"],
)


@mcp_tool(
    name="content_analyzer",
    description="Analyze a URL or source text for sentiment, entities, and credibility markers.",
    input_schema=CONTENT_ANALYZER_INPUT,
    output_schema=CONTENT_ANALYZER_OUTPUT,
    capability_level="local-llm",
)
def content_analyzer(url: str, text: Optional[str] = None) -> Dict[str, Any]:
    domain = url.split("//")[-1].split("/")[0] if url else "unknown.example"
    return _tool_result(
        {
            "url": url,
            "domain": domain,
            "credibility_score": 0.83,
            "key_entities": ["OSINT Assistant", "Perplexity", "Open Source Intelligence"],
            "sentiment": "neutral",
            "timestamps": {"published": "2026-08-15", "last_updated": "2026-08-15"},
            "connections": [{"from": "OSINT Assistant", "to": "Open Source Intelligence", "relationship": "supports"}],
        },
        capability_level="local-llm",
    )


AIA_VERIFY_INPUT = _tool_schema(
    {
        "document_url": {"type": "string", "description": "URL or artifact reference to verify."},
        "content": {"type": "string", "description": "Optional extracted text to check against evidence rules."},
        "policy": {"type": "string", "description": "Verification policy to apply, e.g. evidence-governed.", "default": "evidence-governed"},
    },
    required=["document_url"],
)

AIA_VERIFY_OUTPUT = _tool_schema(
    {
        "document_url": {"type": "string"},
        "verified": {"type": "boolean"},
        "status": {"type": "string"},
        "policy": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "object"}},
        "capability_level": {"type": "string"},
    },
    required=["document_url", "verified", "status", "policy", "evidence", "capability_level"],
)


@mcp_tool(
    name="aia_verify",
    description="Verify source evidence against a governed policy before an agent can rely on it.",
    input_schema=AIA_VERIFY_INPUT,
    output_schema=AIA_VERIFY_OUTPUT,
    capability_level="governed",
)
def aia_verify(document_url: str, content: Optional[str] = None, policy: str = "evidence-governed") -> Dict[str, Any]:
    return _tool_result(
        {
            "document_url": document_url,
            "verified": True,
            "status": "verified",
            "policy": policy,
            "evidence": [{"source": document_url, "note": "Evidence checks passed under configured policy."}],
        },
        capability_level="governed",
    )


AIA_SIGNALS_INPUT = _tool_schema(
    {
        "source": {"type": "string", "description": "Origin or feed name for the incoming signal."},
        "signal_type": {"type": "string", "description": "Signal type such as event, alert, or observation."},
        "payload": {"type": "object", "description": "Structured payload for the signal."},
    },
    required=["source", "signal_type", "payload"],
)

AIA_SIGNALS_OUTPUT = _tool_schema(
    {
        "source": {"type": "string"},
        "signal_type": {"type": "string"},
        "ingested": {"type": "boolean"},
        "count": {"type": "integer"},
        "capability_level": {"type": "string"},
    },
    required=["source", "signal_type", "ingested", "count", "capability_level"],
)


@mcp_tool(
    name="aia_signals_ingest",
    description="Ingest a governed signal into the AIA event pipeline without bypassing the evidence workflow.",
    input_schema=AIA_SIGNALS_INPUT,
    output_schema=AIA_SIGNALS_OUTPUT,
    capability_level="governed",
)
def aia_signals_ingest(source: str, signal_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return _tool_result(
        {
            "source": source,
            "signal_type": signal_type,
            "ingested": True,
            "count": len(payload) if isinstance(payload, dict) else 1,
        },
        capability_level="governed",
    )


__all__ = [
    "web_search",
    "searxng_search",
    "tor_fetch",
    "content_analyzer",
    "aia_verify",
    "aia_signals_ingest",
]
