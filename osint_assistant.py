import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import quote_plus, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum bytes to read from a remote source before truncating.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB
# Allowed content-type prefixes for source fetching (rejects binary/media).
ALLOWED_CONTENT_TYPE_PREFIXES = ("text/", "application/json", "application/xml", "application/xhtml")
# Generic browser user-agent (configurable via OSINT_USER_AGENT).
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; local-research-tool/1.0)"
# Cloud metadata service IPs that must never be contacted.
CLOUD_METADATA_NETS = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure IMDS
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 IMDS
    ipaddress.ip_network("192.0.0.192/32"),      # Azure IMDS alt
]

DEFAULT_SYSTEM_PROMPT = """
You are a local OSINT (Open Source Intelligence) research assistant.
Use only authorized, public-source research. Separate facts from inference,
cite sources where possible, and do not invent proof.
"""

# ---------------------------------------------------------------------------
# Secret redaction helpers
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = re.compile(
    r"(Bearer\s+|token[=:]\s*|key[=:]\s*|password[=:]\s*|secret[=:]\s*|Authorization:\s*)([A-Za-z0-9\-_.~+/]{8,})",
    re.IGNORECASE,
)


def redact_secrets(text: str) -> str:
    """Replace likely credential values in a string with [REDACTED]."""
    return _SECRET_PATTERNS.sub(r"\1[REDACTED]", str(text))


def _strip_url_credentials(url: str) -> str:
    """Remove username/password from a URL."""
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        cleaned = parsed._replace(netloc=parsed.hostname + (f":{parsed.port}" if parsed.port else ""))
        return urlunparse(cleaned)
    return url


# ---------------------------------------------------------------------------
# SSRF / IP safety helpers
# ---------------------------------------------------------------------------

def _is_safe_remote_url(url: str, *, allow_loopback: bool = False) -> tuple[bool, str]:
    """
    Return (True, '') if the URL is safe to fetch as a user-supplied source.
    Return (False, reason) otherwise.

    Blocks: non-http(s) schemes, loopback (unless allow_loopback), private,
    link-local, multicast, reserved, and cloud-metadata ranges.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, f"Unsupported scheme '{parsed.scheme}'; only http/https allowed."
    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname."
    # For .onion addresses, skip IP resolution — safe to route through Tor.
    if hostname.endswith(".onion"):
        return True, ""
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # DNS hostname — resolve to check.
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, ValueError):
            # Can't resolve; allow and let the HTTP layer handle it.
            return True, ""
    if addr.is_loopback and not allow_loopback:
        return False, f"SSRF: loopback address '{addr}' is not allowed for source URLs."
    if addr.is_private:
        return False, f"SSRF: private address '{addr}' is not allowed for source URLs."
    if addr.is_link_local:
        return False, f"SSRF: link-local address '{addr}' is not allowed for source URLs."
    if addr.is_multicast:
        return False, f"SSRF: multicast address '{addr}' is not allowed for source URLs."
    if addr.is_reserved:
        return False, f"SSRF: reserved address '{addr}' is not allowed for source URLs."
    for net in CLOUD_METADATA_NETS:
        if addr in net:
            return False, f"SSRF: cloud metadata address '{addr}' is blocked."
    return True, ""


def _is_loopback_url(url: str) -> bool:
    """Return True if the URL hostname resolves to a loopback address."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_loopback
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(hostname)).is_loopback
    except (socket.gaierror, ValueError):
        return False


def _enforce_local_endpoint(url: str, name: str) -> None:
    """Raise ValueError if url is not a loopback endpoint, unless OSINT_ALLOW_REMOTE_ENDPOINTS=true."""
    if os.getenv("OSINT_ALLOW_REMOTE_ENDPOINTS", "false").lower() == "true":
        return
    if not _is_loopback_url(url):
        raise ValueError(
            f"{name} endpoint '{_strip_url_credentials(url)}' is not a local/loopback address. "
            "Set OSINT_ALLOW_REMOTE_ENDPOINTS=true to permit remote endpoints."
        )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str
    source_type: str
    timestamp: str


class ContentAnalysis(BaseModel):
    domain: str
    credibility_score: float
    key_entities: List[str]
    sentiment: str
    timestamps: Dict[str, str]
    connections: List[Dict[str, str]]


class ProviderRun(BaseModel):
    provider: str
    model: str
    status: str
    error: Optional[str] = None


class AIAReceipt(BaseModel):
    enabled: bool
    base_url: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    signals_ingested: int = 0
    error: Optional[str] = None


class SourceFetch(BaseModel):
    url: str
    status: str
    http_status: Optional[int] = None
    title: Optional[str] = None
    text_excerpt: Optional[str] = None
    error: Optional[str] = None
    via_tor: bool = False
    route: str = "direct"           # "tor", "direct", or "local"


class OSINTReport(BaseModel):
    collected_data: List[SearchResult]
    analysis_results: Dict[str, Any]
    timestamp: str
    query_info: Dict[str, Any]
    source_fetches: List[SourceFetch] = Field(default_factory=list)
    provider_runs: List[ProviderRun] = Field(default_factory=list)
    aia_receipt: Optional[AIAReceipt] = None
    privacy_receipt: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pydantic compatibility shims
# ---------------------------------------------------------------------------

def model_dump(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()  # type: ignore[attr-defined]
    return model.dict()


def model_dump_json(model: BaseModel, indent: int = 2) -> str:
    if hasattr(model, "model_dump_json"):
        return model.model_dump_json(indent=indent)  # type: ignore[attr-defined]
    return model.json(indent=indent)


def split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


# ---------------------------------------------------------------------------
# Provider config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderConfig:
    name: str
    api_key_env: str
    base_url: str
    default_model: str


LOCAL_PROVIDER = ProviderConfig("local", "LOCAL_LLM_API_KEY", "http://localhost:11434/v1", "llama3.1")
PROVIDERS: Dict[str, ProviderConfig] = {"local": LOCAL_PROVIDER}


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class ApiClient:
    """Routes requests to a local OpenAI-compatible LLM endpoint only."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        providers: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        requested = list(providers or split_csv(os.getenv("OSINT_LLM_PROVIDERS")) or ["local"])
        self.providers = [name for name in requested if name.lower().strip() == "local"] or ["local"]
        self.model_override = model or os.getenv("LOCAL_MODEL") or os.getenv("OSINT_LLM_MODEL")
        self.base_url_override = base_url or os.getenv("LOCAL_BASE_URL") or os.getenv("OSINT_LLM_BASE_URL")
        self.api_key_override = api_key
        self.provider_runs: List[ProviderRun] = []
        self.console = Console()
        # Validate that the LLM endpoint is local.
        effective_url = self.base_url_override or LOCAL_PROVIDER.base_url
        _enforce_local_endpoint(effective_url, "LLM")

    @staticmethod
    def available_provider_names() -> List[str]:
        return ["local"]

    def call_api(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> Optional[str]:
        self.provider_runs = []
        selected_model = model or self.model_override or LOCAL_PROVIDER.default_model
        base_url = self.base_url_override or LOCAL_PROVIDER.base_url
        api_key = self.api_key_override or os.getenv(LOCAL_PROVIDER.api_key_env) or "local-dev-key"
        try:
            content = self._call_openai_compatible(api_key, base_url, messages, selected_model, temperature, max_tokens)
            self.provider_runs.append(ProviderRun(provider="local", model=selected_model, status="ok"))
            return content
        except Exception as exc:  # noqa: BLE001
            safe_msg = redact_secrets(str(exc))
            self.provider_runs.append(ProviderRun(provider="local", model=selected_model, status="error", error=safe_msg))
            self.console.print(f"[yellow]Local LLM failed: {safe_msg}[/yellow]")
            return None

    def _call_openai_compatible(
        self,
        api_key: str,
        base_url: str,
        messages: List[Dict[str, str]],
        model: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        endpoint = base_url.rstrip("/")
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"
        response = requests.post(
            endpoint,
            headers={"Authorization": f"******", "content-type": "application/json"},
            json={"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens},
            timeout=90,
        )
        response.raise_for_status()
        payload = response.json()
        return payload["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Source client (privacy-first)
# ---------------------------------------------------------------------------

class SourceClient:
    """
    Clearnet + Tor source fetcher for local OSINT.

    Privacy modes
    -------------
    strict (default)  – All clearnet/onion traffic routes through the local Tor
                        SOCKS proxy using socks5h (remote DNS).  Loopback
                        services (LLM, SearXNG, AIA) remain direct.  If Tor is
                        unreachable the request fails closed — no silent fallback
                        to a direct connection.
    direct            – Clear-net requests go directly without a proxy.  A
                        warning is emitted on every request.

    NOTE: Tor reduces direct source exposure but does NOT guarantee anonymity.
    """

    STRICT = "strict"
    DIRECT = "direct"

    def __init__(
        self,
        internet_enabled: Optional[bool] = None,
        allow_onion: Optional[bool] = None,
        tor_proxy: Optional[str] = None,
        searxng_url: Optional[str] = None,
        privacy_mode: Optional[str] = None,
    ):
        self.internet_enabled = internet_enabled if internet_enabled is not None else os.getenv("INTERNET_ENABLED", "true").lower() == "true"
        self.allow_onion = allow_onion if allow_onion is not None else os.getenv("ALLOW_ONION", "false").lower() == "true"
        self.tor_proxy = tor_proxy or os.getenv("TOR_PROXY", "socks5h://127.0.0.1:9050")
        self.searxng_url = (searxng_url or os.getenv("SEARXNG_URL") or "").rstrip("/")
        raw_mode = privacy_mode or os.getenv("PRIVACY_MODE", self.STRICT)
        self.privacy_mode: str = self.STRICT if raw_mode.lower() != self.DIRECT else self.DIRECT
        self.user_agent = os.getenv("OSINT_USER_AGENT", DEFAULT_USER_AGENT)
        self.console = Console()

    # ------------------------------------------------------------------
    # Proxy selection
    # ------------------------------------------------------------------

    def proxies_for(self, url: str) -> Optional[Dict[str, str]]:
        """
        Return the proxy dict to use for *url*.

        - Loopback URLs → None (direct, always)
        - .onion → Tor proxy (if onion access is enabled)
        - clearnet in strict mode → Tor proxy
        - clearnet in direct mode → None
        """
        if _is_loopback_url(url):
            return None
        host = urlparse(url).hostname or ""
        if host.endswith(".onion"):
            if not self.allow_onion:
                raise ValueError(".onion access is disabled. Set ALLOW_ONION=true to enable.")
            return {"http": self.tor_proxy, "https": self.tor_proxy}
        if self.privacy_mode == self.STRICT:
            return {"http": self.tor_proxy, "https": self.tor_proxy}
        return None

    def route_label(self, url: str) -> str:
        """Return a human-readable route label for receipt/logging."""
        if _is_loopback_url(url):
            return "local"
        host = urlparse(url).hostname or ""
        if host.endswith(".onion") or self.privacy_mode == self.STRICT:
            return "tor"
        return "direct"

    # ------------------------------------------------------------------
    # URL safety validation
    # ------------------------------------------------------------------

    def _validate_source_url(self, url: str) -> None:
        """
        Raise ValueError if url is not safe to fetch as a user-supplied source.
        Loopback addresses are blocked for source URLs (they are only safe as
        trusted service endpoints).
        """
        safe, reason = _is_safe_remote_url(url, allow_loopback=False)
        if not safe:
            raise ValueError(f"Blocked unsafe URL ({_strip_url_credentials(url)}): {reason}")

    # ------------------------------------------------------------------
    # HTTP fetch with privacy enforcement
    # ------------------------------------------------------------------

    def fetch_url(self, url: str, timeout: int = 45) -> SourceFetch:
        if not self.internet_enabled:
            return SourceFetch(url=url, status="disabled", error="Internet access disabled", route="local")
        clean_url = _strip_url_credentials(url)
        try:
            self._validate_source_url(clean_url)
        except ValueError as exc:
            return SourceFetch(url=clean_url, status="error", error=str(exc), route="blocked")
        try:
            proxies = self.proxies_for(clean_url)
        except ValueError as exc:
            return SourceFetch(url=clean_url, status="error", error=str(exc), route="blocked")
        if self.privacy_mode == self.STRICT and proxies is None and not _is_loopback_url(clean_url):
            # Strict mode: no direct clearnet allowed; fail closed.
            return SourceFetch(
                url=clean_url,
                status="error",
                error="Strict privacy mode: direct clearnet connection refused. Ensure Tor is running.",
                route="tor",
                via_tor=False,
            )
        if self.privacy_mode == self.DIRECT:
            self.console.print("[bold yellow]WARNING: direct clearnet mode — network traffic is NOT routed through Tor.[/bold yellow]")
        route = self.route_label(clean_url)
        via_tor = route == "tor"
        try:
            response = requests.get(
                clean_url,
                headers={"User-Agent": self.user_agent},
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,  # validate redirects manually
                stream=True,
            )
            # Follow redirects manually with SSRF validation at each hop.
            hops = 0
            while response.is_redirect and hops < 5:
                redirect_url = response.headers.get("Location", "")
                if not redirect_url:
                    break
                # Make absolute if relative.
                if not redirect_url.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    redirect_url = urljoin(clean_url, redirect_url)
                safe, reason = _is_safe_remote_url(redirect_url, allow_loopback=False)
                if not safe:
                    return SourceFetch(url=clean_url, status="error", error=f"Redirect blocked: {reason}", route=route, via_tor=via_tor)
                clean_url = _strip_url_credentials(redirect_url)
                proxies = self.proxies_for(clean_url)
                response = requests.get(
                    clean_url,
                    headers={"User-Agent": self.user_agent},
                    proxies=proxies,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                )
                hops += 1
            response.raise_for_status()
            # Content-type check.
            ct = response.headers.get("content-type", "")
            if not any(ct.lower().startswith(p) for p in ALLOWED_CONTENT_TYPE_PREFIXES):
                return SourceFetch(url=clean_url, status="error", error=f"Rejected content-type: {ct}", route=route, via_tor=via_tor)
            # Size limit.
            raw = response.raw.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return SourceFetch(url=clean_url, status="error", error=f"Response exceeds {MAX_RESPONSE_BYTES} byte limit.", route=route, via_tor=via_tor)
            html = raw.decode("utf-8", errors="replace")
            title, excerpt = self.extract_text(html)
            return SourceFetch(
                url=clean_url,
                status="ok",
                http_status=response.status_code,
                title=title,
                text_excerpt=excerpt,
                via_tor=via_tor,
                route=route,
            )
        except Exception as exc:  # noqa: BLE001
            safe_err = redact_secrets(str(exc))
            # In strict mode, never silently fall back — propagate the error.
            if self.privacy_mode == self.STRICT:
                return SourceFetch(url=clean_url, status="error", error=f"[strict-fail-closed] {safe_err}", route=route, via_tor=via_tor)
            return SourceFetch(url=clean_url, status="error", error=safe_err, route=route, via_tor=via_tor)

    def search(self, query: str, limit: int = 10) -> List["SearchResult"]:
        if not self.internet_enabled or not self.searxng_url:
            return []
        # SearXNG may be local or remote; validate accordingly.
        searxng_is_local = _is_loopback_url(self.searxng_url)
        if not searxng_is_local:
            # Remote SearXNG — validate as a source URL.
            safe, reason = _is_safe_remote_url(self.searxng_url, allow_loopback=False)
            if not safe:
                self.console.print(f"[yellow]SearXNG URL blocked: {reason}[/yellow]")
                return []
        proxies = None if searxng_is_local else self.proxies_for(self.searxng_url)
        if self.privacy_mode == self.DIRECT and not searxng_is_local:
            self.console.print("[bold yellow]WARNING: SearXNG search is direct (not Tor-routed).[/bold yellow]")
        try:
            response = requests.get(
                f"{self.searxng_url}/search",
                params={"q": query, "format": "json"},
                headers={"User-Agent": self.user_agent},
                proxies=proxies,
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return []
        results: List[SearchResult] = []
        for item in payload.get("results", [])[:limit]:
            url = item.get("url")
            if not url:
                continue
            results.append(
                SearchResult(
                    title=item.get("title") or "Untitled result",
                    url=url,
                    snippet=item.get("content") or item.get("snippet") or "",
                    source_type="SearXNG",
                    timestamp=datetime.now().strftime("%Y-%m-%d"),
                )
            )
        return results

    @staticmethod
    def extract_text(html: str) -> tuple:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled source"
        text = " ".join(soup.get_text(" ").split())
        return title[:300], text[:2500]


# ---------------------------------------------------------------------------
# AIA client
# ---------------------------------------------------------------------------

class AIAClient:
    """Connects OSINT output to local AIA verification and signal capture."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or os.getenv("AIA_BASE_URL") or "http://localhost:3001").rstrip("/")
        self.api_key = api_key or os.getenv("AIA_API_KEY")
        # Validate that the AIA endpoint is local.
        _enforce_local_endpoint(self.base_url, "AIA")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def headers(self) -> Dict[str, str]:
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"******"
        return headers

    def verify(self, statement: str) -> Dict[str, Any]:
        response = requests.post(f"{self.base_url}/verify", headers=self.headers(), json={"statement": statement}, timeout=45)
        response.raise_for_status()
        return response.json()

    def ingest_results(self, query: str, results: Sequence[Dict[str, Any]]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        signals = []
        for index, result in enumerate(results):
            url = str(result.get("url") or f"missing-url-{index}")
            digest = hashlib.sha256(f"{query}|{url}|{index}".encode("utf-8")).hexdigest()[:24]
            signals.append(
                {
                    "id": f"osint:{digest}",
                    "source": "OSINT-Assistant",
                    "domain": "osint.research",
                    "entity_id": urlparse(url).netloc or "unknown",
                    "timestamp": now,
                    "value": {
                        "query": query,
                        "title": result.get("title"),
                        "url": url,
                        "snippet": result.get("snippet"),
                        "source_type": result.get("source_type"),
                    },
                    "value_type": "json",
                    "confidence": 0.5,
                    "metadata": {"source_url": url, "tool": "OSINT-Assistant", "llm_mode": "local-only"},
                }
            )
        response = requests.post(f"{self.base_url}/signals/ingest", headers=self.headers(), json={"signals": signals}, timeout=45)
        response.raise_for_status()
        return int(response.json().get("inserted", len(signals)))


# ---------------------------------------------------------------------------
# JSON helper
# ---------------------------------------------------------------------------

class JsonHelper:
    @staticmethod
    def extract_json_from_text(text: str, console: Optional[Console] = None) -> Union[Dict[str, Any], List[Any], str]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        for pattern in ["```json", "```"]:
            if pattern in text:
                try:
                    fragment = text.split(pattern, 1)[1].split("```", 1)[0].strip()
                    return json.loads(fragment)
                except (IndexError, json.JSONDecodeError):
                    pass
        for regex in [r"\[\s*{[\s\S]*}\s*\]", r"{[\s\S]*}"]:
            for match in re.findall(regex, text):
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue
        if console:
            console.print("[yellow]Could not extract valid JSON from local model response.[/yellow]")
        return text


# ---------------------------------------------------------------------------
# OSINT assistant orchestrator
# ---------------------------------------------------------------------------

class OSINTAssistant:
    def __init__(
        self,
        api_key: Optional[str] = None,
        providers: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        aia_base_url: Optional[str] = None,
        aia_api_key: Optional[str] = None,
        enable_aia: bool = True,
        source_client: Optional[SourceClient] = None,
    ):
        self.console = Console()
        self.api_client = ApiClient(api_key=api_key, providers=providers, model=model, base_url=llm_base_url)
        self.source_client = source_client or SourceClient()
        self.aia_client = AIAClient(aia_base_url, aia_api_key) if enable_aia else None
        self.collected_data: List[Dict[str, Any]] = []
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self.source_fetches: List[SourceFetch] = []
        self.provider_runs: List[ProviderRun] = []
        self.aia_receipt: Optional[AIAReceipt] = None

    def ask_ai(self, query: str, system_prompt: Optional[str] = None, max_tokens: int = 2000) -> Optional[str]:
        messages = [{"role": "system", "content": system_prompt or DEFAULT_SYSTEM_PROMPT}, {"role": "user", "content": query}]
        response = self.api_client.call_api(messages, max_tokens=max_tokens)
        self.provider_runs.extend(self.api_client.provider_runs)
        return response

    def search_web(self, query: str, num_results: int = 10) -> List[SearchResult]:
        self.console.print(f"[bold blue]Searching locally with internet/Tor enabled for:[/bold blue] {query}")
        if is_url(query):
            fetch = self.source_client.fetch_url(query)
            self.source_fetches.append(fetch)
            results = [self.result_from_fetch(fetch)]
        else:
            results = self.source_client.search(query, num_results)
            if not results:
                results = self._perform_local_candidate_search(query, num_results)
        self.collected_data = [model_dump(result) for result in results[:num_results]]
        self._send_to_aia(query)
        self.console.print(f"[green]Found {len(self.collected_data)} results[/green]")
        return results

    def _perform_local_candidate_search(self, query: str, num_results: int) -> List[SearchResult]:
        system_prompt = f"""
Return ONLY a valid JSON array with up to {num_results} OSINT source candidates.
Each object must include: title, url, snippet, source_type, timestamp.
Prefer primary clearnet or .onion sources when known. Do not invent URLs; if a URL
is unknown, use https://example.invalid/source-needed and say source lookup is required.
"""
        content = self.ask_ai(f"Find OSINT source candidates for: {query}", system_prompt, max_tokens=4000)
        parsed = JsonHelper.extract_json_from_text(content or "", self.console) if content else []
        if not isinstance(parsed, list):
            parsed = []
        results = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            item.setdefault("title", "Untitled result")
            item.setdefault("url", "https://example.invalid/source-needed")
            item.setdefault("snippet", "")
            item.setdefault("source_type", "Local model candidate")
            item.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d"))
            try:
                results.append(SearchResult(**item))
            except Exception as exc:  # noqa: BLE001
                self.console.print(f"[yellow]Skipping malformed local result: {redact_secrets(str(exc))}[/yellow]")
        if results:
            return results
        return [SearchResult(**item) for item in self._generate_local_placeholders(query, num_results)]

    @staticmethod
    def result_from_fetch(fetch: SourceFetch) -> SearchResult:
        return SearchResult(
            title=fetch.title or f"Fetched source: {fetch.url}",
            url=fetch.url,
            snippet=fetch.text_excerpt or fetch.error or "",
            source_type="Tor/.onion" if fetch.via_tor else "Internet URL",
            timestamp=datetime.now().strftime("%Y-%m-%d"),
        )

    def analyze_content(self, url: str) -> Optional[ContentAnalysis]:
        self.console.print(f"[bold blue]Analyzing source:[/bold blue] {url}")
        fetch = self.source_client.fetch_url(url) if is_url(url) else None
        if fetch:
            self.source_fetches.append(fetch)
        source_text = fetch.text_excerpt if fetch and fetch.text_excerpt else ""
        system_prompt = """
Return ONLY JSON with: domain, credibility_score, key_entities, sentiment,
timestamps {published,last_updated}, and connections [{from,to,relationship}].
Use UNKNOWN/N/A where the source does not support a claim.
"""
        content = self.ask_ai(f"Analyze this OSINT source URL: {url}\n\nSource excerpt:\n{source_text[:2500]}", system_prompt)
        parsed = JsonHelper.extract_json_from_text(content or "", self.console) if content else None
        analysis = parsed if isinstance(parsed, dict) else self._generate_local_analysis(url, urlparse(url).netloc)
        normalized = self._normalize_analysis(analysis, url)
        content_analysis = ContentAnalysis(**normalized)
        self.analysis_results[url] = model_dump(content_analysis)
        return content_analysis

    def _send_to_aia(self, query: str) -> None:
        if not self.aia_client or not self.aia_client.enabled:
            self.aia_receipt = AIAReceipt(enabled=False)
            return
        try:
            verification = self.aia_client.verify(
                f"Local OSINT Assistant collected {len(self.collected_data)} candidate sources for query: {query}"[:4000]
            )
            inserted = self.aia_client.ingest_results(query, self.collected_data)
            self.aia_receipt = AIAReceipt(True, self.aia_client.base_url, verification, inserted)
        except Exception as exc:  # noqa: BLE001
            safe_err = redact_secrets(str(exc))
            self.aia_receipt = AIAReceipt(enabled=True, base_url=self.aia_client.base_url, error=safe_err)
            self.console.print(f"[yellow]Local AIA integration failed: {safe_err}[/yellow]")

    def _build_privacy_receipt(self) -> Dict[str, Any]:
        mode = self.source_client.privacy_mode
        return {
            "privacy_mode": mode,
            "route": "tor" if mode == SourceClient.STRICT else "direct",
            "remote_dns_via_tor": mode == SourceClient.STRICT,
            "fail_closed_on_proxy_error": mode == SourceClient.STRICT,
            "tor_proxy": self.source_client.tor_proxy if mode == SourceClient.STRICT else None,
            "anonymity_disclaimer": (
                "Tor reduces direct source exposure but does NOT guarantee anonymity. "
                "This software is for authorized, lawful public-source research only."
            ),
        }

    def build_report(self, query: Optional[str] = None, results_requested: Optional[int] = None) -> OSINTReport:
        return OSINTReport(
            collected_data=[SearchResult(**item) for item in self.collected_data],
            analysis_results=self.analysis_results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            query_info={"query": query, "results_requested": results_requested, "results_found": len(self.collected_data), "mode": "local-llm-internet-tor"},
            source_fetches=self.source_fetches,
            provider_runs=self.provider_runs,
            aia_receipt=self.aia_receipt,
            privacy_receipt=self._build_privacy_receipt(),
        )

    def generate_report(self) -> None:
        mode = self.source_client.privacy_mode
        if mode == SourceClient.DIRECT:
            self.console.print("[bold red]WARNING: Running in DIRECT mode — outbound requests are NOT Tor-routed.[/bold red]")
        self.console.print("\n[bold yellow]===== LOCAL OSINT ANALYSIS REPORT =====[/bold yellow]")
        self.console.print(f"[dim]Privacy mode: {mode} | Route: {'tor' if mode == SourceClient.STRICT else 'direct'}[/dim]")
        table = Table(title="Data Collection Summary")
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Credibility", style="yellow")
        for item in self.collected_data:
            domain = urlparse(item["url"]).netloc
            table.add_row(domain, item["source_type"], f"{self._calculate_credibility(domain):.2f}")
        self.console.print(table)
        self.console.print("\n[bold blue]Local / Internet / Tor / AIA Status:[/bold blue]")
        for run in self.provider_runs[-12:]:
            detail = f" — {run.error}" if run.error else ""
            self.console.print(f"- {run.provider}:{run.model} — {run.status.upper()}{detail}")
        for fetch in self.source_fetches[-12:]:
            detail = f" — {fetch.error}" if fetch.error else ""
            self.console.print(f"- [{fetch.route}] fetch {fetch.url} — {fetch.status.upper()}{detail}")
        if self.aia_receipt:
            if self.aia_receipt.enabled and not self.aia_receipt.error:
                self.console.print(f"- AIA — OK; signals ingested: {self.aia_receipt.signals_ingested}")
            elif self.aia_receipt.enabled:
                self.console.print(f"- AIA — ERROR: {self.aia_receipt.error}")
            else:
                self.console.print("- AIA — disabled")

    def save_data(self, filename: str = "osint_data.json") -> None:
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(model_dump_json(self.build_report(), indent=4))
        self.console.print(f"[green]Data saved to {filename}[/green]")

    def _normalize_analysis(self, analysis: Dict[str, Any], url: str) -> Dict[str, Any]:
        domain = analysis.get("domain") if isinstance(analysis.get("domain"), str) else urlparse(url).netloc
        try:
            score = max(0.0, min(1.0, float(analysis.get("credibility_score", 0.5))))
        except (TypeError, ValueError):
            score = 0.5
        entities = analysis.get("key_entities") if isinstance(analysis.get("key_entities"), list) else ["UNKNOWN"]
        sentiment = analysis.get("sentiment") if analysis.get("sentiment") in {"positive", "negative", "neutral"} else "neutral"
        timestamps = analysis.get("timestamps") if isinstance(analysis.get("timestamps"), dict) else {}
        connections = analysis.get("connections") if isinstance(analysis.get("connections"), list) else []
        return {
            "domain": domain or "unknown",
            "credibility_score": score,
            "key_entities": [str(entity) for entity in entities],
            "sentiment": sentiment,
            "timestamps": {"published": str(timestamps.get("published", "N/A")), "last_updated": str(timestamps.get("last_updated", "N/A"))},
            "connections": [conn for conn in connections if isinstance(conn, dict)] or [{"from": "UNKNOWN", "to": "UNKNOWN", "relationship": "source did not verify"}],
        }

    def _calculate_credibility(self, domain: str) -> float:
        if domain.endswith(".gov") or domain.endswith(".edu"):
            return 0.8
        if domain.endswith(".onion"):
            return 0.35
        return 0.5

    def _generate_local_analysis(self, url: str, domain: str) -> Dict[str, Any]:
        return {
            "domain": domain or "unknown",
            "credibility_score": self._calculate_credibility(domain),
            "key_entities": ["UNKNOWN"],
            "sentiment": "neutral",
            "timestamps": {"published": "N/A", "last_updated": datetime.now().strftime("%Y-%m-%d")},
            "connections": [{"from": "UNKNOWN", "to": "UNKNOWN", "relationship": "source did not verify"}],
        }

    def _generate_local_placeholders(self, query: str, count: int) -> List[Dict[str, str]]:
        encoded = quote_plus(query)
        return [
            {
                "title": f"Source lookup required for {query}",
                "url": f"https://example.invalid/source-needed?q={encoded}&n={index + 1}",
                "snippet": "Configure SEARXNG_URL for clearnet search, provide a direct URL, or provide a .onion URL with Tor running on TOR_PROXY.",
                "source_type": "Source lookup required",
                "timestamp": datetime.now().strftime("%Y-%m-%d"),
            }
            for index in range(count)
        ]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Local OSINT Assistant with internet/Tor source access and local AIA integration")
    parser.add_argument("--query", "-q", type=str, help="Search query or direct http(s)/.onion URL")
    parser.add_argument("--results", "-r", type=int, default=10, help="Number of results to collect")
    parser.add_argument("--save", "-s", action="store_true", help="Save collected data to JSON")
    parser.add_argument("--api-key", "-k", type=str, help="Optional local endpoint API key")
    parser.add_argument("--providers", type=str, help="Accepted for compatibility; only 'local' is used")
    parser.add_argument("--model", type=str, help="Local model name, e.g. llama3.1")
    parser.add_argument("--llm-base-url", type=str, help="Local OpenAI-compatible base URL")
    parser.add_argument("--aia-base-url", type=str, help="Local AIA FastAPI base URL")
    parser.add_argument("--aia-api-key", type=str, help="Optional AIA API bearer token")
    parser.add_argument("--skip-aia", action="store_true", help="Disable local AIA verification/signal ingest")
    parser.add_argument("--json", "-j", action="store_true", help="Output results as JSON")
    parser.add_argument("--list-providers", action="store_true", help="List supported providers")
    args = parser.parse_args()

    if args.list_providers:
        print("local")
        return
    if not args.query:
        print("Please provide a search query or URL using --query or -q")
        return

    privacy_mode = os.getenv("PRIVACY_MODE", SourceClient.STRICT)
    if privacy_mode == SourceClient.DIRECT:
        console = Console()
        console.print("[bold red]WARNING: PRIVACY_MODE=direct — outbound requests will NOT be Tor-routed.[/bold red]")

    assistant = OSINTAssistant(
        api_key=args.api_key,
        providers=split_csv(args.providers),
        model=args.model,
        llm_base_url=args.llm_base_url,
        aia_base_url=args.aia_base_url,
        aia_api_key=args.aia_api_key,
        enable_aia=not args.skip_aia,
    )
    assistant.search_web(args.query, args.results)
    for item in assistant.collected_data:
        assistant.analyze_content(item["url"])
    if args.json:
        print(model_dump_json(assistant.build_report(args.query, args.results), indent=2))
    else:
        assistant.generate_report()
    if args.save:
        assistant.save_data()


if __name__ == "__main__":
    main()
