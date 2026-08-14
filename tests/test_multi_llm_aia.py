from osint_assistant import AIAClient, ApiClient, OSINTAssistant, split_csv


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


def test_osint_report_records_aia_disabled():
    assistant = OSINTAssistant(providers=["local"], enable_aia=False)
    assistant.collected_data = []
    assistant._send_to_aia("test")
    assert assistant.aia_receipt is not None
    assert assistant.aia_receipt.enabled is False
