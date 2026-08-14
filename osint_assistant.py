import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import quote_plus, urlparse

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

from siw_core import SIWRuntime, model_to_dict

load_dotenv()

DEFAULT_SYSTEM_PROMPT = """
You are a local OSINT (Open Source Intelligence) research assistant.
Use only authorized, public-source research. Separate facts from inference,
cite sources where possible, and do not invent proof.
"""


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str
    source_type: str
    timestamp: str
    evidence_id: Optional[str] = None


class ContentAnalysis(BaseModel):
    domain: str
    credibility_score: float
    key_entities: List[str]
    sentiment: str
    timestamps: Dict[str, str]
    connections: List[Dict[str, str]]
    evidence_ids: List[str] = Field(default_factory=list)


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
    content_hash_sha256: Optional[str] = None
    evidence_id: Optional[str] = None
    error: Optional[str] = None
    via_tor: bool = False


class OSINTReport(BaseModel):
    collected_data: List[SearchResult]
    analysis_results: Dict[str, Any]
    timestamp: str
    query_info: Dict[str, Any]
    source_fetches: List[SourceFetch] = Field(default_factory=list)
    provider_runs: List[ProviderRun] = Field(default_factory=list)
    aia_receipt: Optional[AIAReceipt] = None


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


def route_for_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    return "tor" if host.endswith(".onion") else "clearnet"


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    api_key_env: str
    base_url: str
    default_model: str


LOCAL_PROVIDER = ProviderConfig("local", "LOCAL_LLM_API_KEY", "http://localhost:11434/v1", "llama3.1")
PROVIDERS: Dict[str, ProviderConfig] = {"local": LOCAL_PROVIDER}


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
            self.provider_runs.append(ProviderRun(provider="local", model=selected_model, status="error", error=str(exc)))
            self.console.print(f"[yellow]Local LLM failed: {exc}[/yellow]")
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
            headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
            json={"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens},
            timeout=90,
        )
        response.raise_for_status()
        payload = response.json()
        return payload["choices"][0]["message"]["content"]


class SourceClient:
    """Clearnet + Tor source fetcher for local OSINT."""

    def __init__(
        self,
        internet_enabled: Optional[bool] = None,
        allow_onion: Optional[bool] = None,
        tor_proxy: Optional[str] = None,
        searxng_url: Optional[str] = None,
    ):
        self.internet_enabled = internet_enabled if internet_enabled is not None else os.getenv("INTERNET_ENABLED", "true").lower() == "true"
        self.allow_onion = allow_onion if allow_onion is not None else os.getenv("ALLOW_ONION", "true").lower() == "true"
        self.tor_proxy = tor_proxy or os.getenv("TOR_PROXY", "socks5h://127.0.0.1:9050")
        self.searxng_url = (searxng_url or os.getenv("SEARXNG_URL") or "").rstrip("/")
        self.user_agent = os.getenv("OSINT_USER_AGENT", "OSINT-Assistant/1.0 (+authorized research)")

    def proxies_for(self, url: str) -> Optional[Dict[str, str]]:
        if route_for_url(url) == "tor":
            if not self.allow_onion:
                raise ValueError(".onion access is disabled. Set ALLOW_ONION=true to enable.")
            return {"http": self.tor_proxy, "https": self.tor_proxy}
        return None

    def fetch_url(self, url: str, timeout: int = 45) -> SourceFetch:
        if not self.internet_enabled:
            return SourceFetch(url=url, status="disabled", error="Internet access disabled", via_tor=route_for_url(url) == "tor")
        try:
            proxies = self.proxies_for(url)
            response = requests.get(url, headers={"User-Agent": self.user_agent}, proxies=proxies, timeout=timeout)
            response.raise_for_status()
            title, excerpt = self.extract_text(response.text)
            return SourceFetch(
                url=url,
                status="ok",
                http_status=response.status_code,
                title=title,
                text_excerpt=excerpt,
                content_hash_sha256=hashlib.sha256(response.content).hexdigest(),
                via_tor=bool(proxies),
            )
        except Exception as exc:  # noqa: BLE001
            return SourceFetch(url=url, status="error", error=str(exc), via_tor=route_for_url(url) == "tor")

    def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        if not self.internet_enabled or not self.searxng_url:
            return []
        try:
            response = requests.get(
                f"{self.searxng_url}/search",
                params={"q": query, "format": "json"},
                headers={"User-Agent": self.user_agent},
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return []
        results = []
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
    def extract_text(html: str) -> tuple[str, str]:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled source"
        text = " ".join(soup.get_text(" ").split())
        return title[:300], text[:2500]


class AIAClient:
    """Connects OSINT output to local AIA verification and signal capture."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or os.getenv("AIA_BASE_URL") or "http://localhost:3001").rstrip("/")
        self.api_key = api_key or os.getenv("AIA_API_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def headers(self) -> Dict[str, str]:
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
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
                    "value": result,
                    "value_type": "json",
                    "confidence": 0.5,
                    "metadata": {"source_url": url, "tool": "OSINT-Assistant", "llm_mode": "local-only"},
                }
            )
        response = requests.post(f"{self.base_url}/signals/ingest", headers=self.headers(), json={"signals": signals}, timeout=45)
        response.raise_for_status()
        return int(response.json().get("inserted", len(signals)))


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


class OSINTAssistant:
    def __init__(
        self,
        case_id: Optional[str] = None,
        runtime: Optional[SIWRuntime] = None,
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
        self.case_id = case_id
        self.runtime = runtime or SIWRuntime()
        self.api_client = ApiClient(api_key=api_key, providers=providers, model=model, base_url=llm_base_url)
        self.source_client = source_client or SourceClient()
        self.aia_client = AIAClient(aia_base_url, aia_api_key) if enable_aia else None
        self.collected_data: List[Dict[str, Any]] = []
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self.source_fetches: List[SourceFetch] = []
        self.provider_runs: List[ProviderRun] = []
        self.aia_receipt: Optional[AIAReceipt] = None

    def ask_ai(self, query: str, system_prompt: Optional[str] = None, max_tokens: int = 2000) -> Optional[str]:
        self.runtime.policy_decision_for(self.case_id, "model_inference", "local-llm", "none")
        messages = [{"role": "system", "content": system_prompt or DEFAULT_SYSTEM_PROMPT}, {"role": "user", "content": query}]
        response = self.api_client.call_api(messages, max_tokens=max_tokens)
        self.provider_runs.extend(self.api_client.provider_runs)
        return response

    def search_web(self, query: str, num_results: int = 10) -> List[SearchResult]:
        self.runtime.require_case(self.case_id)
        self.console.print(f"[bold blue]Searching with SIW policy gate for:[/bold blue] {query}")
        if is_url(query):
            results = [self.fetch_as_result(query)]
        else:
            self.runtime.policy_decision_for(self.case_id, "search", query, "clearnet")
            results = self.source_client.search(query, num_results)
            if not results:
                results = self._perform_local_candidate_search(query, num_results)
        self.collected_data = [model_dump(result) for result in results[:num_results]]
        self._send_to_aia(query)
        self.console.print(f"[green]Found {len(self.collected_data)} results[/green]")
        return results

    def fetch_as_result(self, url: str) -> SearchResult:
        route = route_for_url(url)
        action = "tor_fetch" if route == "tor" else "fetch"
        decision = self.runtime.policy_decision_for(self.case_id, action, url, route)  # type: ignore[arg-type]
        fetch = self.source_client.fetch_url(url)
        if fetch.status == "ok":
            evidence = self.runtime.record_evidence(
                case_id=self.case_id,  # type: ignore[arg-type]
                source_locator=url,
                route_type=route,  # type: ignore[arg-type]
                content=(fetch.text_excerpt or "").encode("utf-8"),
                normalized_text=fetch.text_excerpt or "",
                policy_decision_id=decision.decision_id,
            )
            fetch.evidence_id = evidence.evidence_id
        self.source_fetches.append(fetch)
        return self.result_from_fetch(fetch)

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
                self.console.print(f"[yellow]Skipping malformed local result: {exc}[/yellow]")
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
            evidence_id=fetch.evidence_id,
        )

    def analyze_content(self, url: str) -> Optional[ContentAnalysis]:
        self.runtime.require_case(self.case_id)
        self.console.print(f"[bold blue]Analyzing source:[/bold blue] {url}")
        evidence_ids = []
        source_text = ""
        if is_url(url):
            result = self.fetch_as_result(url)
            source_text = result.snippet
            if result.evidence_id:
                evidence_ids.append(result.evidence_id)
        system_prompt = """
Return ONLY JSON with: domain, credibility_score, key_entities, sentiment,
timestamps {published,last_updated}, and connections [{from,to,relationship}].
Use UNKNOWN/N/A where the source does not support a claim.
"""
        content = self.ask_ai(f"Analyze this OSINT source URL: {url}\n\nSource excerpt:\n{source_text[:2500]}", system_prompt)
        parsed = JsonHelper.extract_json_from_text(content or "", self.console) if content else None
        analysis = parsed if isinstance(parsed, dict) else self._generate_local_analysis(url, urlparse(url).netloc)
        normalized = self._normalize_analysis(analysis, url, evidence_ids)
        content_analysis = ContentAnalysis(**normalized)
        self.analysis_results[url] = model_dump(content_analysis)
        return content_analysis

    def create_claim(self, statement: str, evidence_ids: List[str], confidence: float, contradictions: Optional[List[str]] = None):
        return self.runtime.create_claim(
            case_id=self.case_id,  # type: ignore[arg-type]
            statement=statement,
            evidence_ids=evidence_ids,
            confidence=confidence,
            created_by="local-llm",
            contradictions=contradictions or [],
            model_metadata={"provider": "local", "runs": [model_dump(run) for run in self.provider_runs[-3:]]},
        )

    def export_decision_package(self, approved_by: str, reason: str):
        return self.runtime.export_decision_package(self.case_id, approved_by, reason)  # type: ignore[arg-type]

    def _send_to_aia(self, query: str) -> None:
        if not self.aia_client or not self.aia_client.enabled:
            self.aia_receipt = AIAReceipt(enabled=False)
            return
        try:
            verification = self.aia_client.verify(
                f"SIW case {self.case_id} collected {len(self.collected_data)} candidate sources for query: {query}"[:4000]
            )
            inserted = self.aia_client.ingest_results(query, self.collected_data)
            self.aia_receipt = AIAReceipt(True, self.aia_client.base_url, verification, inserted)
        except Exception as exc:  # noqa: BLE001
            self.aia_receipt = AIAReceipt(enabled=True, base_url=self.aia_client.base_url, error=str(exc))
            self.console.print(f"[yellow]Local AIA integration failed: {exc}[/yellow]")

    def build_report(self, query: Optional[str] = None, results_requested: Optional[int] = None) -> OSINTReport:
        return OSINTReport(
            collected_data=[SearchResult(**item) for item in self.collected_data],
            analysis_results=self.analysis_results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            query_info={"query": query, "case_id": self.case_id, "results_requested": results_requested, "results_found": len(self.collected_data), "mode": "siw-local-llm-internet-tor"},
            source_fetches=self.source_fetches,
            provider_runs=self.provider_runs,
            aia_receipt=self.aia_receipt,
        )

    def generate_report(self) -> None:
        self.console.print("\n[bold yellow]===== SIW LOCAL OSINT ANALYSIS REPORT =====[/bold yellow]")
        table = Table(title="Data Collection Summary")
        table.add_column("Evidence", style="magenta")
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Credibility", style="yellow")
        for item in self.collected_data:
            domain = urlparse(item["url"]).netloc
            table.add_row(str(item.get("evidence_id") or "—"), domain, item["source_type"], f"{self._calculate_credibility(domain):.2f}")
        self.console.print(table)
        self.console.print("\n[bold blue]Local / Internet / Tor / AIA Status:[/bold blue]")
        for run in self.provider_runs[-12:]:
            detail = f" — {run.error}" if run.error else ""
            self.console.print(f"- {run.provider}:{run.model} — {run.status.upper()}{detail}")
        for fetch in self.source_fetches[-12:]:
            detail = f" — {fetch.error}" if fetch.error else ""
            route = "Tor" if fetch.via_tor else "Internet"
            self.console.print(f"- {route} fetch {fetch.url} — {fetch.status.upper()} evidence={fetch.evidence_id or '—'}{detail}")
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

    def _normalize_analysis(self, analysis: Dict[str, Any], url: str, evidence_ids: List[str]) -> Dict[str, Any]:
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
            "evidence_ids": evidence_ids,
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
                "url": f"{{https://example.invalid/source-needed?q={encoded}}}&n={index + 1}",
                "snippet": "Configure SEARXNG_URL for clearnet search, provide a direct URL, or provide a .onion URL with Tor running on TOR_PROXY.",
                "source_type": "Source lookup required",
                "timestamp": datetime.now().strftime("%Y-%m-%d"),
            }
            for index in range(count)
        ]


def create_or_load_case(args: argparse.Namespace, runtime: SIWRuntime) -> Optional[str]:
    if args.case_id:
        runtime.require_case(args.case_id)
        return args.case_id
    if args.create_case:
        if not args.authorized_purpose:
            raise ValueError("--authorized-purpose is required with --create-case")
        case = runtime.create_case(
            title=args.case_title or args.query or "SIW Investigation",
            authorized_purpose=args.authorized_purpose,
            owner=args.owner,
            policy_profile=args.policy_profile,
            scope={"source_rules": args.source_rules, "target": args.query},
        )
        return case.case_id
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Sovereign Intelligence Workstation local OSINT runtime")
    parser.add_argument("--query", "-q", type=str, help="Search query or direct http(s)/.onion URL")
    parser.add_argument("--case-id", type=str, help="Existing SIW case ID. Required unless --create-case is used")
    parser.add_argument("--create-case", action="store_true", help="Create a case before running")
    parser.add_argument("--case-title", type=str, help="Case title when creating a case")
    parser.add_argument("--authorized-purpose", type=str, help="Authorized purpose statement for the case")
    parser.add_argument("--owner", type=str, default=os.getenv("USER", "local_operator"), help="Case owner/operator")
    parser.add_argument("--policy-profile", choices=["local_only", "clearnet_authorized", "tor_authorized", "airgapped_review"], default="clearnet_authorized")
    parser.add_argument("--source-rules", type=str, default="authorized public-source collection only")
    parser.add_argument("--results", "-r", type=int, default=10, help="Number of results to collect")
    parser.add_argument("--save", "-s", action="store_true", help="Save collected data to JSON")
    parser.add_argument("--export-package", action="store_true", help="Export a DecisionPackage after the run")
    parser.add_argument("--approved-by", type=str, default=os.getenv("USER", "local_operator"))
    parser.add_argument("--approval-reason", type=str, default="Operator-approved export")
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

    runtime = SIWRuntime(requested_by=args.owner)
    case_id = create_or_load_case(args, runtime)
    if not case_id:
        raise SystemExit("Denied: --case-id or --create-case with --authorized-purpose is required")

    assistant = OSINTAssistant(
        case_id=case_id,
        runtime=runtime,
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
    if args.export_package:
        package_path = assistant.export_decision_package(args.approved_by, args.approval_reason)
        print(f"DecisionPackage exported: {package_path}")
    if args.json:
        print(model_dump_json(assistant.build_report(args.query, args.results), indent=2))
    else:
        assistant.generate_report()
    if args.save:
        assistant.save_data()


if __name__ == "__main__":
    main()
