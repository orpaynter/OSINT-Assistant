import pytest

import osint_web_app
from siw_core import AppendOnlyStore, SIWRuntime


def test_api_search_without_case_is_policy_denied():
    client = osint_web_app.app.test_client()
    response = client.post("/api/search", json={"query": "test"})
    assert response.status_code == 403
    assert "Policy denied" in response.get_json()["error"]


def test_search_route_without_case_is_policy_denied_not_500():
    client = osint_web_app.app.test_client()
    response = client.post("/search", data={"query": "test"})
    assert response.status_code == 403
    assert b"Policy denied" in response.data


def test_api_search_with_case_requires_matching_authorized_purpose(monkeypatch, tmp_path):
    runtime = SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")
    case = runtime.create_case(
        title="Web case",
        authorized_purpose="Authorized purpose",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    monkeypatch.setattr(osint_web_app, "SIWRuntime", lambda requested_by=None: runtime)
    client = osint_web_app.app.test_client()
    response = client.post(
        "/api/search",
        json={"query": "test", "case_id": case.case_id, "authorized_purpose": "Wrong purpose"},
    )
    assert response.status_code == 403
    assert response.get_json()["error"] == "Policy denied"


def test_server_rejects_non_loopback_or_debug():
    with pytest.raises(ValueError):
        osint_web_app.run_server(host="0.0.0.0", debug=True)


def test_skip_aia_string_false_keeps_aia_enabled(monkeypatch, tmp_path):
    runtime = SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")
    case = runtime.create_case(
        title="Web case",
        authorized_purpose="Authorized purpose",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    monkeypatch.setattr(osint_web_app, "SIWRuntime", lambda requested_by=None: runtime)
    monkeypatch.setattr(osint_web_app, "model_dump", lambda value: value)
    observed = {}

    class StubAssistant:
        def __init__(self, **kwargs):
            observed["enable_aia"] = kwargs["enable_aia"]
            self.collected_data = []

        def search_web(self, _query, _num_results):
            self.collected_data = []

        def analyze_content(self, _url):
            return None

        def build_report(self, _query, _num_results):
            return {"collected_data": [], "query_info": {"results_found": 0}}

    monkeypatch.setattr(osint_web_app, "OSINTAssistant", StubAssistant)
    osint_web_app.run_search(
        {
            "query": "acme",
            "case_id": case.case_id,
            "authorized_purpose": "Authorized purpose",
            "skip_aia": "false",
        }
    )
    assert observed["enable_aia"] is True


def test_template_receives_sanitized_links(monkeypatch, tmp_path):
    runtime = SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")
    case = runtime.create_case(
        title="Web case",
        authorized_purpose="Authorized purpose",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    monkeypatch.setattr(osint_web_app, "SIWRuntime", lambda requested_by=None: runtime)
    monkeypatch.setattr(osint_web_app, "model_dump", lambda value: value)

    class StubAssistant:
        def __init__(self, **kwargs):
            self.collected_data = [{"url": "javascript:alert(1)"}]

        def search_web(self, _query, _num_results):
            self.collected_data = [{"url": "javascript:alert(1)"}]

        def analyze_content(self, _url):
            return None

        def build_report(self, _query, _num_results):
            return {
                "collected_data": [{"url": "javascript:alert(1)", "title": "x", "source_type": "stub", "timestamp": "now", "snippet": ""}],
                "query_info": {"results_found": 1},
            }

    monkeypatch.setattr(osint_web_app, "OSINTAssistant", StubAssistant)
    report = osint_web_app.run_search(
        {
            "query": "acme",
            "case_id": case.case_id,
            "authorized_purpose": "Authorized purpose",
        }
    )
    assert report["collected_data"][0]["safe_url"] == ""
