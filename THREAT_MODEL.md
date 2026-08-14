# Sovereign Intelligence Workstation — Threat Model v0.1

## Scope

This threat model covers the local-first SIW slice in OSINT Assistant:

- local OpenAI-compatible LLM inference
- clearnet source fetch/search
- Tor/.onion source fetch through a configured local proxy
- local AIA verification/signal ingest
- append-only local case, policy, evidence, claim, approval, and export ledgers
- portable DecisionPackage export and local verification

## Non-goals

- No cloud model fallback.
- No telemetry or vendor analytics.
- No stealth, evasion, exploitation, credential collection, or unauthorized-access functionality.
- No legal, forensic, evidentiary, or court-admissibility guarantee.
- No anonymity guarantee for Tor or any network route.

## Primary assets

- Investigation scope and purpose
- Source locators and collection metadata
- Raw source captures and normalized text
- Evidence hashes and manifests
- Claims, contradictions, confidence, and model metadata
- Policy decisions and human approvals
- DecisionPackage exports

## Trust boundaries

1. **Operator boundary** — the operator declares authorized purpose, scope, and policy profile.
2. **Policy boundary** — SIW must decide allow/deny before search, fetch, Tor fetch, inference, acceptance, export, or sharing.
3. **Network boundary** — clearnet routes direct; .onion routes through the configured Tor proxy.
4. **Model boundary** — local LLM output is untrusted analysis until linked to evidence and accepted.
5. **Evidence boundary** — raw source content is stored separately from derived claims and hash-bound in the ledger.
6. **Export boundary** — DecisionPackage export requires policy allowance and human approval.

## Key threats and controls

| Threat | Control |
| --- | --- |
| Silent cloud fallback | Provider registry is local-only; tests assert non-local providers collapse to local. |
| Silent network egress | SIW policy decisions are append-logged before network activity. |
| Unauthorized .onion access | Tor route requires `tor_authorized` policy profile and configured Tor proxy. |
| Claim accepted without evidence | Claim acceptance rejects empty `evidence_ids`. |
| Evidence tampering | Raw evidence SHA-256 is recorded and verified during package verification. |
| Mutable audit history | Ledger writes append JSONL records; corrections create superseding records. |
| Overclaiming source reliability | .onion and fetched content are untrusted until independently verified. |
| Export without review | Export creates policy decision + human approval record before DecisionPackage creation. |

## Open risks

- Local filesystem encryption is not implemented in this slice.
- Multi-user roles and SSO are not implemented in this slice.
- Signature keys are not implemented yet; v0.1 package integrity uses SHA-256 package hash and local verifier.
- SearXNG/Tor runtime availability must be tested on the operator machine.
- OPSEC warnings are initial policy controls, not a full detection-risk engine.

## Evidence class

Current slice target: **SOURCE-INSPECTED / TESTED** after CI passes. It is not production-approved and not field-validated.
