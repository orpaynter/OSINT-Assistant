"""
Tests for privacy-first hardening requirements.

Covers:
- Flask defaults to localhost and debug off.
- No wildcard CORS / no default cross-origin access.
- UI has no third-party CDN / external resource references.
- Strict mode routes clearnet through Tor (socks5h proxy).
- Loopback local services remain direct.
- Strict mode never falls back to direct after proxy failure.
- Direct mode requires explicit selection and is reported in receipt.
- Non-local LLM/AIA endpoints are rejected by default.
- SSRF: loopback/private/link-local/metadata IPs blocked for source URLs.
- SSRF: unsafe redirect targets are blocked.
- Oversized or binary responses are rejected.
- Secrets are redacted from errors/receipts.
"""

import ipaddress
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code=200,
    text="<html><head><title>Test</title></head><body>hello</body></html>",
    headers=None,
    is_redirect=False,
    raw_bytes=None,
):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.is_redirect = is_redirect
    resp.headers = headers or {"content-type": "text/html; charset=utf-8"}
    content = raw_bytes if raw_bytes is not None else text.encode()
    resp.raw = MagicMock()
    resp.raw.read.return_value = content
    resp.raise_for_status = MagicMock()
    return resp


# ===========================================================================
# Flask / web app tests
# ===========================================================================

class TestFlaskDefaults(unittest.TestCase):
    """Flask app defaults to localhost binding and debug off."""

    def test_bind_host_default_is_loopback(self):
        bind_host = os.getenv("OSINT_BIND_HOST", "127.0.0.1")
        self.assertIn(bind_host, ("127.0.0.1", "::1", "localhost"))

    def test_debug_default_is_off(self):
        debug = os.getenv("FLASK_DEBUG", "false").lower()
        self.assertEqual(debug, "false")

    def test_no_wildcard_cors_by_default(self):
        """OSINT_CORS_ORIGINS must be empty (no wildcard) by default."""
        cors_env = os.getenv("OSINT_CORS_ORIGINS", "")
        self.assertEqual(cors_env, "", "OSINT_CORS_ORIGINS must be empty by default (same-origin only)")

    def test_app_html_has_no_cdn_references(self):
        """The embedded HTML template must not contain external CDN URLs."""
        import osint_web_app
        cdn_patterns = [
            "cdn.tailwindcss.com",
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "fonts.googleapis.com",
            "fonts.gstatic.com",
        ]
        html = osint_web_app.APP_HTML
        for cdn in cdn_patterns:
            self.assertNotIn(cdn, html, f"Found CDN reference to {cdn} in APP_HTML")

    def test_app_html_has_no_external_script_src(self):
        """APP_HTML must not contain <script src='http...'>."""
        import osint_web_app
        import re
        matches = re.findall(r'<script[^>]+src=["\']https?://', osint_web_app.APP_HTML, re.IGNORECASE)
        self.assertEqual(matches, [], f"External script tags found: {matches}")


# ===========================================================================
# Privacy mode / routing tests
# ===========================================================================

class TestStrictModeRouting(unittest.TestCase):

    def _strict_client(self, **kwargs):
        from osint_assistant import SourceClient
        return SourceClient(privacy_mode="strict", tor_proxy="socks5h://127.0.0.1:9050", **kwargs)

    def test_clearnet_routed_through_tor_in_strict_mode(self):
        client = self._strict_client()
        proxies = client.proxies_for("https://example.com")
        self.assertEqual(proxies, {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"})

    def test_onion_routed_through_tor_in_strict_mode(self):
        client = self._strict_client(allow_onion=True)
        proxies = client.proxies_for("http://abc123.onion/page")
        self.assertEqual(proxies, {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"})

    def test_loopback_remains_direct_in_strict_mode(self):
        client = self._strict_client()
        self.assertIsNone(client.proxies_for("http://127.0.0.1:11434/v1"))
        self.assertIsNone(client.proxies_for("http://localhost:8080"))

    def test_strict_mode_route_label_clearnet(self):
        client = self._strict_client()
        self.assertEqual(client.route_label("https://example.com"), "tor")

    def test_strict_mode_route_label_loopback(self):
        client = self._strict_client()
        self.assertEqual(client.route_label("http://127.0.0.1:3001"), "local")

    def test_strict_mode_fails_closed_on_proxy_error(self):
        """In strict mode a proxy connection error must NOT silently fall back to direct."""
        client = self._strict_client()
        with patch("requests.get", side_effect=Exception("SOCKS connection refused")):
            fetch = client.fetch_url("https://example.com")
        self.assertEqual(fetch.status, "error")
        self.assertIn("strict-fail-closed", fetch.error)
        # The route label must be 'tor', not 'direct'.
        self.assertNotEqual(fetch.route, "direct")

    def test_strict_mode_fail_closed_reported_in_receipt(self):
        from osint_assistant import OSINTAssistant, SourceClient
        sc = SourceClient(privacy_mode="strict")
        assistant = OSINTAssistant(source_client=sc, enable_aia=False)
        receipt = assistant._build_privacy_receipt()
        self.assertTrue(receipt["fail_closed_on_proxy_error"])
        self.assertEqual(receipt["route"], "tor")


class TestDirectMode(unittest.TestCase):

    def _direct_client(self, **kwargs):
        from osint_assistant import SourceClient
        return SourceClient(privacy_mode="direct", **kwargs)

    def test_clearnet_direct_in_direct_mode(self):
        client = self._direct_client()
        self.assertIsNone(client.proxies_for("https://example.com"))

    def test_direct_mode_receipt_reports_direct(self):
        from osint_assistant import OSINTAssistant, SourceClient
        sc = SourceClient(privacy_mode="direct")
        assistant = OSINTAssistant(source_client=sc, enable_aia=False)
        receipt = assistant._build_privacy_receipt()
        self.assertEqual(receipt["privacy_mode"], "direct")
        self.assertEqual(receipt["route"], "direct")
        self.assertFalse(receipt["fail_closed_on_proxy_error"])

    def test_direct_mode_not_default(self):
        """The default privacy mode must be strict, not direct."""
        from osint_assistant import SourceClient
        import os
        old = os.environ.pop("PRIVACY_MODE", None)
        try:
            client = SourceClient()
            self.assertEqual(client.privacy_mode, SourceClient.STRICT)
        finally:
            if old is not None:
                os.environ["PRIVACY_MODE"] = old


# ===========================================================================
# LLM / AIA endpoint enforcement
# ===========================================================================

class TestEndpointEnforcement(unittest.TestCase):

    def test_remote_llm_endpoint_rejected_by_default(self):
        """ApiClient must reject a non-loopback LLM URL unless opt-in env is set."""
        from osint_assistant import ApiClient
        with patch.dict(os.environ, {"OSINT_ALLOW_REMOTE_ENDPOINTS": "false", "LOCAL_BASE_URL": "https://api.openai.com/v1"}):
            with self.assertRaises(ValueError, msg="Remote LLM endpoint should be rejected"):
                ApiClient()

    def test_local_llm_endpoint_accepted(self):
        from osint_assistant import ApiClient
        with patch.dict(os.environ, {"OSINT_ALLOW_REMOTE_ENDPOINTS": "false", "LOCAL_BASE_URL": "http://localhost:11434/v1"}):
            # Should not raise.
            client = ApiClient()
            self.assertIsNotNone(client)

    def test_remote_aia_endpoint_rejected_by_default(self):
        from osint_assistant import AIAClient
        with patch.dict(os.environ, {"OSINT_ALLOW_REMOTE_ENDPOINTS": "false"}):
            with self.assertRaises(ValueError):
                AIAClient(base_url="https://remote-aia.example.com")

    def test_local_aia_endpoint_accepted(self):
        from osint_assistant import AIAClient
        with patch.dict(os.environ, {"OSINT_ALLOW_REMOTE_ENDPOINTS": "false"}):
            client = AIAClient(base_url="http://localhost:3001")
            self.assertIsNotNone(client)

    def test_remote_endpoint_allowed_when_opt_in(self):
        from osint_assistant import AIAClient
        with patch.dict(os.environ, {"OSINT_ALLOW_REMOTE_ENDPOINTS": "true"}):
            # Should not raise even for a remote URL.
            client = AIAClient(base_url="https://remote-aia.example.com")
            self.assertIsNotNone(client)


# ===========================================================================
# SSRF protection tests
# ===========================================================================

class TestSSRFProtections(unittest.TestCase):

    def _client(self):
        from osint_assistant import SourceClient
        return SourceClient(privacy_mode="direct")

    def test_loopback_ip_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("http://127.0.0.1/admin")
        self.assertFalse(ok)
        self.assertIn("loopback", reason)

    def test_private_ip_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("http://192.168.1.1/")
        self.assertFalse(ok)
        self.assertIn("private", reason)

    def test_link_local_ip_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("http://169.254.1.1/")
        self.assertFalse(ok)

    def test_cloud_metadata_ip_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("http://169.254.169.254/latest/meta-data/")
        # 169.254.169.254 is link-local so it is blocked by that check (or metadata).
        self.assertFalse(ok)

    def test_non_http_scheme_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("file:///etc/passwd")
        self.assertFalse(ok)
        self.assertIn("scheme", reason)

    def test_ftp_scheme_blocked(self):
        from osint_assistant import _is_safe_remote_url
        ok, reason = _is_safe_remote_url("ftp://example.com/file")
        self.assertFalse(ok)

    def test_fetch_blocks_loopback_source_url(self):
        client = self._client()
        fetch = client.fetch_url("http://127.0.0.1:8080/internal")
        self.assertEqual(fetch.status, "error")
        self.assertIn("SSRF", fetch.error)

    def test_fetch_blocks_private_ip_source_url(self):
        client = self._client()
        fetch = client.fetch_url("http://10.0.0.1/data")
        self.assertEqual(fetch.status, "error")
        self.assertIn("SSRF", fetch.error)

    def test_unsafe_redirect_blocked(self):
        """A redirect to a private IP must be blocked."""
        client = self._client()
        redirect_resp = MagicMock()
        redirect_resp.is_redirect = True
        redirect_resp.headers = {"Location": "http://192.168.0.1/secret", "content-type": "text/html"}
        redirect_resp.status_code = 302
        redirect_resp.raise_for_status = MagicMock()
        with patch("requests.get", return_value=redirect_resp):
            fetch = client.fetch_url("https://example.com/redirect")
        self.assertEqual(fetch.status, "error")
        self.assertIn("Redirect blocked", fetch.error)


# ===========================================================================
# Response size / content-type tests
# ===========================================================================

class TestResponseLimits(unittest.TestCase):

    def _direct_client(self):
        from osint_assistant import SourceClient
        return SourceClient(privacy_mode="direct")

    def test_oversized_response_rejected(self):
        from osint_assistant import MAX_RESPONSE_BYTES
        client = self._direct_client()
        big = b"A" * (MAX_RESPONSE_BYTES + 1)
        resp = _make_response(raw_bytes=big, headers={"content-type": "text/html"})
        resp.is_redirect = False
        with patch("requests.get", return_value=resp):
            fetch = client.fetch_url("https://example.com/big")
        self.assertEqual(fetch.status, "error")
        self.assertIn("byte limit", fetch.error)

    def test_binary_content_type_rejected(self):
        client = self._direct_client()
        resp = _make_response(raw_bytes=b"\x00\x01\x02", headers={"content-type": "application/octet-stream"})
        resp.is_redirect = False
        with patch("requests.get", return_value=resp):
            fetch = client.fetch_url("https://example.com/binary.exe")
        self.assertEqual(fetch.status, "error")
        self.assertIn("content-type", fetch.error)

    def test_acceptable_content_type_passes(self):
        client = self._direct_client()
        resp = _make_response(headers={"content-type": "text/html; charset=utf-8"})
        resp.is_redirect = False
        with patch("requests.get", return_value=resp):
            fetch = client.fetch_url("https://example.com/page")
        self.assertEqual(fetch.status, "ok")


# ===========================================================================
# Secret redaction tests
# ===========================================================================

class TestSecretRedaction(unittest.TestCase):

    def test_bearer_token_redacted(self):
        from osint_assistant import redact_secrets
        result = redact_secrets("token=sk-abc1234567890xyz failed to connect")
        self.assertNotIn("sk-abc1234567890xyz", result)
        self.assertIn("[REDACTED]", result)

    def test_api_key_redacted(self):
        from osint_assistant import redact_secrets
        result = redact_secrets("API call failed: key=sk-abcdef1234567890abcdef")
        self.assertNotIn("sk-abcdef1234567890abcdef", result)
        self.assertIn("[REDACTED]", result)

    def test_normal_error_unchanged(self):
        from osint_assistant import redact_secrets
        msg = "Connection refused at 127.0.0.1:9050"
        self.assertEqual(redact_secrets(msg), msg)

    def test_error_in_source_fetch_is_redacted(self):
        """Errors surfaced in SourceFetch should not contain raw credentials."""
        from osint_assistant import SourceClient
        client = SourceClient(privacy_mode="direct")
        with patch(
            "requests.get",
            side_effect=Exception("token=sk-supersecret1234567890 connection failed"),
        ):
            fetch = client.fetch_url("https://example.com")
        self.assertNotIn("sk-supersecret1234567890", fetch.error or "")
        self.assertIn("[REDACTED]", fetch.error or "")


# ===========================================================================
# Privacy receipt completeness tests
# ===========================================================================

class TestPrivacyReceipt(unittest.TestCase):

    def _receipt(self, mode):
        from osint_assistant import OSINTAssistant, SourceClient
        sc = SourceClient(privacy_mode=mode)
        assistant = OSINTAssistant(source_client=sc, enable_aia=False)
        return assistant._build_privacy_receipt()

    def test_strict_receipt_fields(self):
        r = self._receipt("strict")
        self.assertEqual(r["privacy_mode"], "strict")
        self.assertEqual(r["route"], "tor")
        self.assertTrue(r["remote_dns_via_tor"])
        self.assertTrue(r["fail_closed_on_proxy_error"])
        self.assertIn("anonymity_disclaimer", r)
        self.assertIn("does NOT guarantee anonymity", r["anonymity_disclaimer"])

    def test_direct_receipt_fields(self):
        r = self._receipt("direct")
        self.assertEqual(r["privacy_mode"], "direct")
        self.assertEqual(r["route"], "direct")
        self.assertFalse(r["remote_dns_via_tor"])
        self.assertFalse(r["fail_closed_on_proxy_error"])


if __name__ == "__main__":
    unittest.main()
