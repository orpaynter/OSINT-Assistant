import json
from pathlib import Path

import pytest

from siw_core import AppendOnlyStore, DecisionPackageVerifier, SIWRuntime


def make_runtime(tmp_path: Path) -> SIWRuntime:
    return SIWRuntime(AppendOnlyStore(tmp_path), requested_by="tester")


def test_network_action_without_case_id_is_denied(tmp_path):
    runtime = make_runtime(tmp_path)
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(None, "fetch", "https://example.com", "clearnet")


def test_unrecognized_action_is_denied_and_logged(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="ExampleCo exposure assessment",
        authorized_purpose="Authorized public exposure assessment demo",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(case.case_id, "unknown_action", "target", "none")
    decisions = runtime.store.load_all("policy_decisions")
    assert decisions[-1]["allow"] is False
    assert "unrecognized" in decisions[-1]["reason"]


def test_tor_route_requires_tor_authorized_profile(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="Clearnet case",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    with pytest.raises(PermissionError):
        runtime.policy_decision_for(case.case_id, "tor_fetch", "http://abc.onion", "tor")


def test_successful_fetch_evidence_has_sha256(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="ExampleCo exposure assessment",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
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


def test_claim_cannot_be_accepted_without_evidence(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="Claim review",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    claim = runtime.create_claim(
        case_id=case.case_id,
        statement="Unsupported claim",
        evidence_ids=[],
        confidence=0.2,
        created_by="local-model",
    )
    with pytest.raises(ValueError):
        runtime.accept_claim(case.case_id, claim.claim_id, "No evidence should fail")


def test_decision_package_verifies_and_fails_after_tamper(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case(
        title="Package export",
        authorized_purpose="Authorized research",
        owner="tester",
        policy_profile="clearnet_authorized",
    )
    decision = runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "clearnet")
    evidence = runtime.record_evidence(
        case_id=case.case_id,
        source_locator="https://example.com",
        route_type="clearnet",
        content=b"example evidence",
        normalized_text="example evidence",
        policy_decision_id=decision.decision_id,
    )
    claim = runtime.create_claim(
        case_id=case.case_id,
        statement="Example evidence exists",
        evidence_ids=[evidence.evidence_id],
        confidence=0.8,
        created_by="tester",
    )
    runtime.accept_claim(case.case_id, claim.claim_id, "Evidence linked")
    receipt = runtime.record_human_approval_receipt(
        case_id=case.case_id,
        action_type="evidence_export",
        approved_by="tester",
        reason="Demo export",
    )
    package_path = runtime.export_decision_package(case.case_id, approval_receipt_id=receipt.approval_id)
    assert DecisionPackageVerifier.verify(package_path).ok is True

    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["case"]["title"] = "Tampered"
    package_path.write_text(json.dumps(package, indent=2), encoding="utf-8")
    result = DecisionPackageVerifier.verify(package_path)
    assert result.ok is False
    assert result.package_hash_ok is False


def test_audit_history_is_append_only(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case("Case", "Authorized", "tester", "clearnet_authorized")
    runtime.policy_decision_for(case.case_id, "fetch", "https://example.com", "clearnet")
    runtime.policy_decision_for(case.case_id, "fetch", "https://example.org", "clearnet")
    assert len(runtime.store.load_all("policy_decisions")) == 2


def test_export_fails_without_verified_governance_receipt(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case("Package export", "Authorized research", "tester", "clearnet_authorized")
    with pytest.raises(PermissionError):
        runtime.export_decision_package(case.case_id, approval_receipt_id="missing")


def test_caller_approved_by_cannot_mint_decision_package(tmp_path):
    runtime = make_runtime(tmp_path)
    case = runtime.create_case("Package export", "Authorized research", "tester", "clearnet_authorized")
    receipt = runtime.record_human_approval_receipt(
        case_id=case.case_id,
        action_type="evidence_export",
        approved_by="governance-user",
        reason="Approved",
    )
    with pytest.raises(PermissionError):
        runtime.export_decision_package(
            case.case_id,
            approval_receipt_id=receipt.approval_id,
            approved_by="attacker",
            reason="self-approve",
        )
