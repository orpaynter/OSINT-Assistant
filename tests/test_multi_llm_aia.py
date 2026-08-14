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
    # allow_onion must be explicitly enabled (default is False for safety).
    client = SourceClient(tor_proxy="socks5h://127.0.0.1:9050", allow_onion=True)
    assert client.proxies_for("http://abc123.onion/") == {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }


def test_clearnet_uses_tor_in_strict_mode():
    # Default (strict) privacy mode routes clearnet through Tor.
    client = SourceClient(privacy_mode="strict", tor_proxy="socks5h://127.0.0.1:9050")
    assert client.proxies_for("https://example.com") == {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }


def test_clearnet_uses_direct_connection_in_direct_mode():
    # Explicit direct mode bypasses Tor.
    client = SourceClient(privacy_mode="direct")
    assert client.proxies_for("https://example.com") is None
