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
