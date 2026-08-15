"""Sovereign Intelligence Workstation core runtime.

This module turns OSINT runs into evidence-governed investigations:
case -> policy decision -> preserved evidence -> evidence-bound claims ->
portable DecisionPackage.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

COLLECTOR_VERSION = "siw-runtime-v0.1"
DEFAULT_DATA_DIR = Path(os.getenv("SIW_DATA_DIR", ".siw_data"))

ActionType = Literal[
    "search",
    "fetch",
    "tor_fetch",
    "model_inference",
    "claim_accept",
    "evidence_export",
    "external_share",
]
PolicyProfile = Literal["local_only", "clearnet_authorized", "tor_authorized", "airgapped_review"]
RouteType = Literal["none", "clearnet", "tor"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()  # type: ignore[attr-defined]
    return model.dict()


class InvestigationCase(BaseModel):
    case_id: str = Field(default_factory=lambda: new_id("case"))
    title: str
    authorized_purpose: str
    owner: str
    scope: dict[str, Any] = Field(default_factory=dict)
    policy_profile: PolicyProfile = "local_only"
    created_at: str = Field(default_factory=utc_now)
    status: Literal["open", "paused", "closed"] = "open"


class PolicyDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: new_id("pd"))
    case_id: str
    action_type: str
    target: str
    requested_by: str
    allow: bool
    reason: str
    timestamp: str = Field(default_factory=utc_now)
    policy_version: str = "siw-policy-v0.1"
    route_type: RouteType = "none"


class EvidenceRecord(BaseModel):
    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    case_id: str
    source_locator: str
    retrieval_timestamp: str = Field(default_factory=utc_now)
    route_type: RouteType
    content_hash_sha256: str
    mime_type: str = "text/plain"
    normalized_text_path: str
    raw_content_path: str
    collector_version: str = COLLECTOR_VERSION
    policy_decision_id: str
    integrity_status: Literal["verified", "missing", "tampered"] = "verified"


class Claim(BaseModel):
    claim_id: str = Field(default_factory=lambda: new_id("claim"))
    case_id: str
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    contradictions: list[str] = Field(default_factory=list)
    created_by: str
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    acceptance_status: Literal["proposed", "accepted", "rejected", "needs_more_evidence"] = "proposed"
    created_at: str = Field(default_factory=utc_now)
    accepted_at: Optional[str] = None
    acceptance_reason: Optional[str] = None


class HumanApproval(BaseModel):
    approval_id: str = Field(default_factory=lambda: new_id("appr"))
    case_id: str
    action_type: str
    approved_by: str
    reason: str
    issued_by: str = "governance"
    verified: bool = False
    timestamp: str = Field(default_factory=utc_now)


class DecisionPackage(BaseModel):
    package_id: str = Field(default_factory=lambda: new_id("dpkg"))
    created_at: str = Field(default_factory=utc_now)
    collector_version: str = COLLECTOR_VERSION
    case: InvestigationCase
    evidence_manifest: list[EvidenceRecord]
    claims: list[Claim]
    policy_decisions: list[PolicyDecision]
    human_approvals: list[HumanApproval]
    verification_instructions: str
    package_hash_sha256: Optional[str] = None


class VerificationResult(BaseModel):
    ok: bool
    package_hash_ok: bool
    evidence_hashes_ok: bool
    errors: list[str] = Field(default_factory=list)


class AppendOnlyStore:
    """Append-only local store for cases, policy decisions, evidence, claims and exports."""

    def __init__(self, root: Path | str = DEFAULT_DATA_DIR):
        self.root = Path(root)
        self.ledger_dir = self.root / "ledger"
        self.raw_dir = self.root / "raw"
        self.text_dir = self.root / "normalized"
        self.exports_dir = self.root / "exports"
        for directory in [self.ledger_dir, self.raw_dir, self.text_dir, self.exports_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def append(self, name: str, item: BaseModel | dict[str, Any]) -> None:
        data = model_to_dict(item) if isinstance(item, BaseModel) else item
        with (self.ledger_dir / f"{name}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(stable_json(data) + "\n")

    def load_all(self, name: str) -> list[dict[str, Any]]:
        path = self.ledger_dir / f"{name}.jsonl"
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def save_content(self, case_id: str, evidence_id: str, content: bytes, text: str) -> tuple[Path, Path]:
        case_raw = self.raw_dir / case_id
        case_text = self.text_dir / case_id
        case_raw.mkdir(parents=True, exist_ok=True)
        case_text.mkdir(parents=True, exist_ok=True)
        raw_path = case_raw / f"{evidence_id}.bin"
        text_path = case_text / f"{evidence_id}.txt"
        raw_path.write_bytes(content)
        text_path.write_text(text, encoding="utf-8")
        return raw_path, text_path

    def export_path(self, package_id: str) -> Path:
        return self.exports_dir / f"{package_id}.decisionpackage.json"


class PolicyGate:
    """Default-deny SIW policy gate."""

    def __init__(self, store: AppendOnlyStore):
        self.store = store

    def decide(
        self,
        case: InvestigationCase,
        action_type: str,
        target: str,
        requested_by: str,
        route_type: RouteType = "none",
    ) -> PolicyDecision:
        allow, reason = self._evaluate(case, action_type, target, route_type)
        decision = PolicyDecision(
            case_id=case.case_id,
            action_type=action_type,
            target=target,
            requested_by=requested_by,
            allow=allow,
            reason=reason,
            route_type=route_type,
        )
        self.store.append("policy_decisions", decision)
        return decision

    def _evaluate(self, case: InvestigationCase, action_type: str, target: str, route_type: RouteType) -> tuple[bool, str]:
        allowed_actions = {
            "search",
            "fetch",
            "tor_fetch",
            "model_inference",
            "claim_accept",
            "evidence_export",
            "external_share",
        }
        if action_type not in allowed_actions:
            return False, "default deny: unrecognized action type"
        if not case.authorized_purpose.strip():
            return False, "default deny: missing authorized purpose"
        if case.status != "open":
            return False, f"default deny: case status is {case.status}"
        if case.policy_profile == "airgapped_review" and action_type in {"search", "fetch", "tor_fetch"}:
            return False, "air-gapped review forbids network collection"
        if case.policy_profile == "local_only" and action_type in {"search", "fetch", "tor_fetch"}:
            return False, "local-only profile forbids network collection"
        if route_type == "tor" and case.policy_profile != "tor_authorized":
            return False, "Tor route requires tor_authorized profile"
        if route_type == "clearnet" and case.policy_profile not in {"clearnet_authorized", "tor_authorized"}:
            return False, "clearnet route requires network-authorized profile"
        if action_type == "external_share":
            allowed_targets = case.scope.get("allow_external_share_targets", [])
            if not isinstance(allowed_targets, list) or target not in allowed_targets:
                return False, "external share requires explicit per-target policy allow"
            return True, "allowed by explicit external share target policy"
        return True, "allowed by SIW policy profile"


class SIWRuntime:
    """Evidence-governed investigation runtime."""

    def __init__(self, store: Optional[AppendOnlyStore] = None, requested_by: str = "local_operator"):
        self.store = store or AppendOnlyStore()
        self.requested_by = requested_by
        self.policy_gate = PolicyGate(self.store)

    def create_case(
        self,
        title: str,
        authorized_purpose: str,
        owner: str,
        policy_profile: PolicyProfile = "local_only",
        scope: Optional[dict[str, Any]] = None,
    ) -> InvestigationCase:
        case = InvestigationCase(
            title=title,
            authorized_purpose=authorized_purpose,
            owner=owner,
            policy_profile=policy_profile,
            scope=scope or {},
        )
        self.store.append("cases", case)
        return case

    def load_case(self, case_id: str) -> InvestigationCase:
        for item in reversed(self.store.load_all("cases")):
            if item.get("case_id") == case_id:
                return InvestigationCase(**item)
        raise ValueError(f"Unknown case ID: {case_id}")

    def require_case(self, case_id: Optional[str]) -> InvestigationCase:
        if not case_id:
            raise PermissionError("Network, model, analysis, and export actions require a case_id")
        return self.load_case(case_id)

    def policy_decision_for(
        self,
        case_id: Optional[str],
        action_type: str,
        target: str,
        route_type: RouteType = "none",
    ) -> PolicyDecision:
        case = self.require_case(case_id)
        decision = self.policy_gate.decide(case, action_type, target, self.requested_by, route_type)
        if not decision.allow:
            raise PermissionError(decision.reason)
        return decision

    def _load_authorizing_evidence_decision(
        self,
        case_id: str,
        policy_decision_id: str,
        source_locator: str,
        route_type: RouteType,
    ) -> PolicyDecision:
        self.require_case(case_id)
        matches = [
            PolicyDecision(**item)
            for item in self.store.load_all("policy_decisions")
            if item.get("decision_id") == policy_decision_id
        ]
        if len(matches) != 1:
            raise PermissionError("Evidence denied: policy decision must resolve uniquely")

        decision = matches[0]
        expected_action = {"clearnet": "fetch", "tor": "tor_fetch"}.get(route_type)
        if expected_action is None:
            raise PermissionError("Evidence denied: preserved network evidence requires clearnet or tor route")
        if decision.case_id != case_id:
            raise PermissionError("Evidence denied: policy decision belongs to a different case")
        if not decision.allow:
            raise PermissionError("Evidence denied: referenced policy decision was not allowed")
        if decision.action_type != expected_action:
            raise PermissionError("Evidence denied: policy decision action does not authorize this route")
        if decision.target != source_locator:
            raise PermissionError("Evidence denied: source does not match the authorized policy target")
        if decision.route_type != route_type:
            raise PermissionError("Evidence denied: route does not match the authorized policy decision")
        return decision

    def record_evidence(
        self,
        case_id: str,
        source_locator: str,
        route_type: RouteType,
        content: bytes,
        normalized_text: str,
        policy_decision_id: str,
        mime_type: str = "text/plain",
    ) -> EvidenceRecord:
        self._load_authorizing_evidence_decision(
            case_id=case_id,
            policy_decision_id=policy_decision_id,
            source_locator=source_locator,
            route_type=route_type,
        )
        evidence_id = new_id("ev")
        raw_path, text_path = self.store.save_content(case_id, evidence_id, content, normalized_text)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            source_locator=source_locator,
            route_type=route_type,
            content_hash_sha256=sha256_bytes(content),
            mime_type=mime_type,
            normalized_text_path=str(text_path),
            raw_content_path=str(raw_path),
            policy_decision_id=policy_decision_id,
        )
        self.store.append("evidence", record)
        return record

    def create_claim(
        self,
        case_id: str,
        statement: str,
        evidence_ids: list[str],
        confidence: float,
        created_by: str,
        contradictions: Optional[list[str]] = None,
        model_metadata: Optional[dict[str, Any]] = None,
    ) -> Claim:
        self.require_case(case_id)
        claim = Claim(
            case_id=case_id,
            statement=statement,
            evidence_ids=evidence_ids,
            confidence=confidence,
            contradictions=contradictions or [],
            created_by=created_by,
            model_metadata=model_metadata or {},
        )
        self.store.append("claims", claim)
        return claim

    def accept_claim(self, case_id: str, claim_id: str, reason: str) -> Claim:
        self.policy_decision_for(case_id, "claim_accept", claim_id, "none")
        claims = self.store.load_all("claims")
        for item in reversed(claims):
            if item.get("claim_id") == claim_id and item.get("case_id") == case_id:
                claim = Claim(**item)
                if not claim.evidence_ids:
                    raise ValueError("Claim cannot be accepted without at least one evidence_id")
                claim.acceptance_status = "accepted"
                claim.accepted_at = utc_now()
                claim.acceptance_reason = reason
                self.store.append("claims", claim)
                return claim
        raise ValueError(f"Unknown claim ID: {claim_id}")

    def record_human_approval_receipt(
        self,
        case_id: str,
        action_type: str,
        approved_by: str,
        reason: str,
    ) -> HumanApproval:
        self.require_case(case_id)
        raise PermissionError(
            "Local SIW cannot mint Governance approval receipts; "
            "a trusted authenticated Governance verifier must issue and verify the receipt"
        )

    def _load_verified_governance_receipt(self, case_id: str, approval_receipt_id: str) -> HumanApproval:
        self.require_case(case_id)
        raise PermissionError(
            "Export denied: trusted Governance receipt verification is not wired; "
            "local ledger fields are not authority"
        )

    def export_decision_package(
        self,
        case_id: str,
        approval_receipt_id: str,
        approved_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Path:
        case = self.require_case(case_id)
        decision = self.policy_gate.decide(case, "evidence_export", case_id, self.requested_by, "none")
        if not decision.allow:
            raise PermissionError(decision.reason)
        approval = self._load_verified_governance_receipt(case_id, approval_receipt_id)
        if approved_by and approved_by != approval.approved_by:
            raise PermissionError("Export denied: caller approved_by does not match verified receipt")
        if reason and reason != approval.reason:
            raise PermissionError("Export denied: caller reason does not match verified receipt")
        unique_approvals: list[HumanApproval] = []
        seen_approval_ids: set[str] = set()
        for item in self.store.load_all("human_approvals"):
            if item.get("case_id") != case_id:
                continue
            candidate = HumanApproval(**item)
            if candidate.approval_id in seen_approval_ids:
                continue
            seen_approval_ids.add(candidate.approval_id)
            unique_approvals.append(candidate)
        package = DecisionPackage(
            case=case,
            evidence_manifest=[EvidenceRecord(**item) for item in self.store.load_all("evidence") if item.get("case_id") == case_id],
            claims=[Claim(**item) for item in self.store.load_all("claims") if item.get("case_id") == case_id],
            policy_decisions=[PolicyDecision(**item) for item in self.store.load_all("policy_decisions") if item.get("case_id") == case_id],
            human_approvals=unique_approvals,
            verification_instructions="Run: python siw_verify.py <package.json>. This checks package and evidence hashes locally without external services.",
        )
        package_dict = model_to_dict(package)
        package_dict["package_hash_sha256"] = sha256_text(stable_json({**package_dict, "package_hash_sha256": None}))
        path = self.store.export_path(package.package_id)
        path.write_text(json.dumps(package_dict, indent=2, sort_keys=True), encoding="utf-8")
        self.store.append("exports", {"case_id": case_id, "package_path": str(path), "package_hash_sha256": package_dict["package_hash_sha256"], "timestamp": utc_now()})
        return path


class DecisionPackageVerifier:
    @staticmethod
    def verify(package_path: Path | str) -> VerificationResult:
        path = Path(package_path)
        errors: list[str] = []
        try:
            package = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(ok=False, package_hash_ok=False, evidence_hashes_ok=False, errors=[str(exc)])

        expected_hash = package.get("package_hash_sha256")
        candidate = dict(package)
        candidate["package_hash_sha256"] = None
        actual_hash = sha256_text(stable_json(candidate))
        package_hash_ok = expected_hash == actual_hash
        if not package_hash_ok:
            errors.append("DecisionPackage hash mismatch")

        evidence_hashes_ok = True
        for record in package.get("evidence_manifest", []):
            raw_path = Path(record.get("raw_content_path", ""))
            if not raw_path.exists():
                evidence_hashes_ok = False
                errors.append(f"Missing evidence content: {record.get('evidence_id')}")
                continue
            actual = sha256_bytes(raw_path.read_bytes())
            if actual != record.get("content_hash_sha256"):
                evidence_hashes_ok = False
                errors.append(f"Evidence hash mismatch: {record.get('evidence_id')}")
        return VerificationResult(ok=package_hash_ok and evidence_hashes_ok, package_hash_ok=package_hash_ok, evidence_hashes_ok=evidence_hashes_ok, errors=errors)