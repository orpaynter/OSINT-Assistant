import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

load_dotenv()

DEFAULT_SYSTEM_PROMPT = """
You are a local OSINT (Open Source Intelligence) research assistant.
Gather factual information from reliable public sources, cite sources where
possible, separate facts from inference, and do not invent proof.
"""


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


class OSINTReport(BaseModel):
    collected_data: List[SearchResult]
    analysis_results: Dict[str, Any]
    timestamp: str
    query_info: Dict[str, Any]
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


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    api_key_env: str
    base_url: str
    default_model: str


LOCAL_PROVIDER = ProviderConfig(
    name="local",
    api_key_env="LOCAL_LLM_API_KEY",
    base_url="http://localhost:11434/v1",
    default_model="llama3.1",
)

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
        config = LOCAL_PROVIDER
        selected_model = model or self.model_override or config.default_model
        base_url = self.base_url_override or config.base_url
        api_key = self.api_key_override or os.getenv(config.api_key_env) or "local-dev-key"
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
        api_key: Optional[str] = None,
        providers: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        aia_base_url: Optional[str] = None,
        aia_api_key: Optional[str] = None,
        enable_aia: bool = True,
    ):
        self.console = Console()
        self.api_client = ApiClient(api_key=api_key, providers=providers, model=model, base_url=llm_base_url)
        self.aia_client = AIAClient(aia_base_url, aia_api_key) if enable_aia else None
        self.collected_data: List[Dict[str, Any]] = []
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self.provider_runs: List[ProviderRun] = []
        self.aia_receipt: Optional[AIAReceipt] = None

    def ask_ai(self, query: str, system_prompt: Optional[str] = None, max_tokens: int = 2000) -> Optional[str]:
        messages = [{"role": "system", "content": system_prompt or DEFAULT_SYSTEM_PROMPT}, {"role": "user", "content": query}]
        response = self.api_client.call_api(messages, max_tokens=max_tokens)
        self.provider_runs.extend(self.api_client.provider_runs)
        return response

    def search_web(self, query: str, num_results: int = 10) -> List[SearchResult]:
        self.console.print(f"[bold blue]Searching locally for:[/bold blue] {query}")
        results = self._perform_search(query, num_results)
        self.collected_data = [model_dump(result) for result in results[:num_results]]
        self._send_to_aia(query)
        self.console.print(f"[green]Found {len(self.collected_data)} results[/green]")
        return results

    def _perform_search(self, query: str, num_results: int) -> List[SearchResult]:
        system_prompt = f"""
Return ONLY a valid JSON array with up to {num_results} OSINT search results.
Each object must include: title, url, snippet, source_type, timestamp.
Prefer primary sources. Do not invent URLs. If live web access is unavailable,
return clearly labeled candidate sources or say what must be searched manually.
"""
        content = self.ask_ai(f"Find OSINT sources for: {query}", system_prompt, max_tokens=4000)
        parsed = JsonHelper.extract_json_from_text(content or "", self.console) if content else []
        if not isinstance(parsed, list):
            parsed = []
        results = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            item.setdefault("title", "Untitled result")
            item.setdefault("url", "https://example.invalid/local-model-candidate")
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

    def analyze_content(self, url: str) -> Optional[ContentAnalysis]:
        self.console.print(f"[bold blue]Analyzing locally:[/bold blue] {url}")
        system_prompt = """
Return ONLY JSON with: domain, credibility_score, key_entities, sentiment,
timestamps {published,last_updated}, and connections [{from,to,relationship}].
Use UNKNOWN/N/A where the local model cannot verify source contents.
"""
        content = self.ask_ai(f"Analyze this OSINT source: {url}", system_prompt)
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
            self.aia_receipt = AIAReceipt(
                enabled=True,
                base_url=self.aia_client.base_url,
                verification=verification,
                signals_ingested=inserted,
            )
        except Exception as exc:  # noqa: BLE001
            self.aia_receipt = AIAReceipt(enabled=True, base_url=self.aia_client.base_url, error=str(exc))
            self.console.print(f"[yellow]Local AIA integration failed: {exc}[/yellow]")

    def build_report(self, query: Optional[str] = None, results_requested: Optional[int] = None) -> OSINTReport:
        return OSINTReport(
            collected_data=[SearchResult(**item) for item in self.collected_data],
            analysis_results=self.analysis_results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            query_info={"query": query, "results_requested": results_requested, "results_found": len(self.collected_data), "mode": "local-only"},
            provider_runs=self.provider_runs,
            aia_receipt=self.aia_receipt,
        )

    def generate_report(self) -> None:
        self.console.print("\n[bold yellow]===== LOCAL OSINT ANALYSIS REPORT =====[/bold yellow]")
        table = Table(title="Data Collection Summary")
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Credibility", style="yellow")
        for item in self.collected_data:
            domain = urlparse(item["url"]).netloc
            table.add_row(domain, item["source_type"], f"{self._calculate_credibility(domain):.2f}")
        self.console.print(table)
        self.console.print("\n[bold blue]Local / AIA Status:[/bold blue]")
        for run in self.provider_runs[-12:]:
            detail = f" — {run.error}" if run.error else ""
            self.console.print(f"- {run.provider}:{run.model} — {run.status.upper()}{detail}")
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
            "timestamps": {
                "published": str(timestamps.get("published", "N/A")),
                "last_updated": str(timestamps.get("last_updated", "N/A")),
            },
            "connections": [conn for conn in connections if isinstance(conn, dict)]
            or [{"from": "UNKNOWN", "to": "UNKNOWN", "relationship": "local model could not verify"}],
        }

    def _calculate_credibility(self, domain: str) -> float:
        credibility_db = {"example.com": 0.6, "dataresearch.org": 0.8, "gov.reports.org": 0.9}
        return credibility_db.get(domain, 0.5)

    def _generate_local_analysis(self, url: str, domain: str) -> Dict[str, Any]:
        return {
            "domain": domain or "unknown",
            "credibility_score": self._calculate_credibility(domain),
            "key_entities": ["UNKNOWN"],
            "sentiment": "neutral",
            "timestamps": {"published": "N/A", "last_updated": datetime.now().strftime("%Y-%m-%d")},
            "connections": [{"from": "UNKNOWN", "to": "UNKNOWN", "relationship": "local model could not verify"}],
        }

    def _generate_local_placeholders(self, query: str, count: int) -> List[Dict[str, str]]:
        results = []
        for index in range(count):
            results.append(
                {
                    "title": f"Local OSINT candidate for {query}: {index + 1}",
                    "url": "https://example.invalid/local-only-needs-source-search",
                    "snippet": "Local-only mode did not return a verifiable source. Run with a local model that has retrieval/tool access or manually add sources.",
                    "source_type": "Local-only placeholder",
                    "timestamp": datetime.now().strftime("%Y-%m-%d"),
                }
            )
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only OSINT Assistant with local AIA integration")
    parser.add_argument("--query", "-q", type=str, help="The search query to investigate")
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

    assistant = OSINTAssistant(
        api_key=args.api_key,
        providers=split_csv(args.providers),
        model=args.model,
        llm_base_url=args.llm_base_url,
        aia_base_url=args.aia_base_url,
        aia_api_key=args.aia_api_key,
        enable_aia=not args.skip_aia,
    )
    if not args.query:
        print("Please provide a search query using --query or -q")
        return

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
