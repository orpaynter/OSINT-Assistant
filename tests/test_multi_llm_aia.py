from osint_assistant import AIAClient, ApiClient, OSINTAssistant, split_csv


def test_split_csv_trims_empty_values():
    assert split_csv("perplexity, openai,,anthropic ") == ["perplexity", "openai", "anthropic"]


def test_provider_registry_contains_expected_providers():
    providers = set(ApiClient.available_provider_names())
    assert {"perplexity", "openai", "anthropic", "local"}.issubset(providers)


def test_missing_keys_are_skipped(monkeypatch):
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    client = ApiClient(providers=["perplexity"])
    assert client.call_api([{"role": "user", "content": "hello"}]) is None
    assert client.provider_runs[0].status == "skipped"


def test_aia_disabled_without_base_url(monkeypatch):
    monkeypatch.delenv("AIA_BASE_URL", raising=False)
    assert AIAClient().enabled is False


def test_osint_report_records_aia_disabled(monkeypatch):
    monkeypatch.delenv("AIA_BASE_URL", raising=False)
    assistant = OSINTAssistant(providers=["perplexity"])
    assistant.collected_data = []
    assistant._send_to_aia("test")
    assert assistant.aia_receipt is not None
    assert assistant.aia_receipt.enabled is False
