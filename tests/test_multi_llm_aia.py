from osint_assistant import AIAClient, ApiClient, SourceClient, split_csv


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
