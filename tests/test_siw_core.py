from pathlib import Path

import pytest

from siw_core import AppendOnlyStore, PolicyDecision, SIWRuntime


def make_runtime(tmp_path: Path) -> SIWRuntime:
    return SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")


def make_case(runtime: SIWRuntime, title: str = "Case"):
    return runtime.create_case(
        title=title,
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )


def test_network_action_without_case_id_is_denied(tmp_path):
    runtime = make_runtime(tmp_path)
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(None, "fetch", "https://example.com", "clearnet")


def test_unrecognized_action_is_denied_and_logged(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(case.case_id, "unknown_action", "target", "none")
    decisions = runtime.store.load_all("policy_decisions")
    assert decisions[-1]["allow"] is False
    assert "unrecognized" in decisions[-1]["reason"]


def test_tor_route_requires_tor_authorized_profile(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(case.case_id, "tor_fetch", "http://abc.onion", "tor")


def test_route_type_is_derived_and_mismatch_is_denied(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    with pytest.raises(PermissionError, match="action type does not match target route"):
        runtime.policy_decision_for(case.case_id, "fetch", "http://abc.onion", "tor")
    with pytest.raises(PermissionError, match="route type does not match target route"):
        runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "tor")


def test_scope_constrains_search_and_fetch(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="Scoped case",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
        scope={"target": "acme", "allowed_domains": ["example.com"]},
    )
    with pytest.raises(PermissionError, match="outside case scope target"):
        runtime.policy_decision_for(case.case_id, "search", "globex exposure report", "clearnet")
    with pytest.raises(PermissionError, match="outside case scope allowed_domains"):
        runtime.policy_decision_for(case.case_id, "fetch", "https://other.org/report", "clearnet")
    allowed = runtime.policy_decision_for(case.case_id, "fetch", "https://example.com/report", "clearnet")
    assert allowed.allow is True


def test_successful_fetch_evidence_has_sha256(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    decision = runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "clearnet")
    evidence = runtime.record_evidence(
        case_id=case.case_id,
        source_locator="https://example.com",
        route_type="clearnet",
        content=b"example evidence",
        normalized_text="example evidence",
        policy_decision_id=decision.decision_id,
    )
    assert len(evidence.content_hash_sha256) == 64
    assert evidence.integrity_status == "verified"
    assert evidence.policy_decision_id == decision.decision_id


def test_record_evidence_rejects_unknown_policy_decision(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    with pytest.raises(PermissionError, match="resolve uniquely"):
        runtime.record_evidence(
            case_id=case.case_id,
            source_locator="https://example.com",
            route_type="clearnet",
            content=b"evidence",
            normalized_text="evidence",
            policy_decision_id="pd_missing",
        )
    assert runtime.store.load_all("evidence") == []


def test_record_evidence_rejects_policy_decision_from_another_case(tmp_path):
    runtime = make_runtime(tmp_path)
    case_a = make_case(runtime, "Case A")
    case_b = make_case(runtime, "Case B")
    decision = runtime.policy_decision_for(case_a.case_id, "fetch", "https://example.com", "clearnet")
    with pytest.raises(PermissionError, match="different case"):
        runtime.record_evidence(
            case_id=case_b.case_id,
            source_locator="https://example.com",
            route_type="clearnet",
            content=b"evidence",
            normalized_text="evidence",
            policy_decision_id=decision.decision_id,
        )
    assert runtime.store.load_all("evidence") == []


def test_record_evidence_rejects_denied_policy_decision(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    denied = PolicyDecision(
        case_id=case.case_id,
        action_type="fetch",
        target="https://example.com",
        requested_by="tester",
        allow=False,
        reason="denied fixture",
        route_type="clearnet",
    )
    runtime.store.append("policy_decisions", denied)
    with pytest.raises(PermissionError, match="was not allowed"):
        runtime.record_evidence(
            case_id=case.case_id,
            source_locator="https://example.com",
            route_type="clearnet",
            content=b"evidence",
            normalized_text="evidence",
            policy_decision_id=denied.decision_id,
        )
    assert runtime.store.load_all("evidence") == []


def test_record_evidence_rejects_source_or_route_mismatch(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    decision = runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "clearnet")
    with pytest.raises(PermissionError, match="source does not match"):
        runtime.record_evidence(
            case_id=case.case_id,
            source_locator="https://example.org",
            route_type="clearnet",
            content=b"evidence",
            normalized_text="evidence",
            policy_decision_id=decision.decision_id,
        )
    with pytest.raises(PermissionError, match="action does not authorize this route"):
        runtime.record_evidence(
            case_id=case.case_id,
            source_locator="https://example.com",
            route_type="tor",
            content=b"evidence",
            normalized_text="evidence",
            policy_decision_id=decision.decision_id,
        )
    assert runtime.store.load_all("evidence") == []


def test_claim_cannot_be_accepted_without_evidence(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime, "Claim review")
    claim = runtime.create_claim(
        case_id=case.case_id,
        statement="Unsupported claim",
        evidence_ids=[],
        confidence=0.2,
        created_by="local-model",
    )
    with pytest.raises(ValueError):
        runtime.accept_claim(case.case_id, claim.claim_id, "No evidence should fail")


def test_audit_history_is_append_only(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime)
    runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "clearnet")
    runtime.policy_decision_for(case.case_id, "fetch", "https://example.org", "clearnet")
    assert len(runtime.store.load_all("policy_decisions")) == 2


def test_local_runtime_cannot_mint_governance_receipt(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime, "Package export")
    with pytest.raises(PermissionError, match="cannot mint Governance approval receipts"):
        runtime.record_human_approval_receipt(
            case_id=case.case_id,
            action_type="evidence_export",
            approved_by="tester",
            reason="self-approved",
        )
    assert runtime.store.load_all("human_approvals") == []


def test_export_fails_closed_without_trusted_governance_verifier(tmp_path):
    runtime = make_runtime(tmp_path)
    case = make_case(runtime, "Package export")
    with pytest.raises(PermissionError, match="trusted Governance receipt verification is not wired"):
        runtime.export_decision_package(case.case_id, approval_receipt_id="appr_untrusted")
    assert runtime.store.load_all("exports") == []
