import base64
import hashlib

from osint_assistant import AIAClient, OSINTAssistant, ApiClient, SourceClient, SourceFetch, split_csv
from siw_core import AppendOnlyStore, SIWRuntime


def test_split_csv_trims_empty_values():
    assert split_csv("local,, local ") == ["local", "local"]


def test_provider_registry_is_local_only():
    assert ApiClient.available_provider_names() == ["local"]


def test_non_local_provider_requests_are_collapsed_to_local():
    client = ApiClient(providers=["perplexity", "openai"])
    assert client.providers == ["local"]


def test_aia_defaults_to_localhost(monkeypatch):
    monkeypatch.delenv("AIA_BASE_URL", raising=False)
    client = AIAClient()
    assert client.enabled is True
    assert client.base_url == "http://localhost:3001"


def test_onion_uses_tor_proxy():
    client = SourceClient(tor_proxy="socks5h://127.0.0.1:9050")
    assert client.proxies_for("http://abc123.onion/") == {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }


def test_clearnet_uses_direct_connection():
    client = SourceClient()
    assert client.proxies_for("https://example.com") is None


def test_raw_byte_hash_matches_evidence_artifact(tmp_path):
    runtime = SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")
    case = runtime.create_case(
        title="Evidence hash",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    raw_bytes = b"\x00raw-response-bytes\xff"

    class StubSourceClient:
        def fetch_url(self, _url):
            return SourceFetch(
                url="https://example.com/source",
                status="ok",
                http_status=200,
                title="Source",
                text_excerpt="derived excerpt",
                content_hash_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                raw_content_base64=base64.b64encode(raw_bytes).decode("ascii"),
            )

        def search(self, _query, _limit=10):
            return []

    assistant = OSINTAssistant(case_id=case.case_id, runtime=runtime, enable_aia=False, source_client=StubSourceClient())
    result = assistant.fetch_as_result("https://example.com/source")
    assert result.evidence_id is not None
    evidence = runtime.store.load_all("evidence")[-1]
    assert evidence["content_hash_sha256"] == assistant.source_fetches[-1].content_hash_sha256


def test_aia_ingest_without_policy_allow_is_denied_and_logged(tmp_path, monkeypatch):
    runtime = SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")
    case = runtime.create_case(
        title="AIA policy",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    assistant = OSINTAssistant(case_id=case.case_id, runtime=runtime, enable_aia=True)
    assistant.collected_data = [{"url": "https://example.com"}]
    called = {"verify": False, "ingest": False}

    def fake_verify(_statement):
        called["verify"] = True
        return {"ok": True}

    def fake_ingest(_query, _results):
        called["ingest"] = True
        return 1

    monkeypatch.setattr(assistant.aia_client, "verify", fake_verify)
    monkeypatch.setattr(assistant.aia_client, "ingest_results", fake_ingest)

    assistant._send_to_aia("query")

    assert called["verify"] is False
    assert called["ingest"] is False
    assert assistant.aia_receipt is not None
    assert "external share requires explicit per-target policy allow" in (assistant.aia_receipt.error or "")
    decision = runtime.store.load_all("policy_decisions")[-1]
    assert decision["action_type"] == "external_share"
    assert decision["allow"] is False
