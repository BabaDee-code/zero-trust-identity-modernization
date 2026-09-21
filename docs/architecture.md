# Architecture and Control Mapping

## Objective

This repository demonstrates how Zero Trust security principles can be translated into deterministic policy logic that is testable, auditable, and reusable across enterprise identity platforms.

## Core components

1. **Access request context**: user risk, device compliance, MFA strength, location risk, privilege level, and application sensitivity.
2. **Context validation**: enumerated security telemetry is validated before authorization logic executes.
3. **Policy engine**: evaluates validated access context against security control requirements.
4. **Decision output**: returns allow, deny, step-up MFA, or review.
5. **Audit evidence**: each decision includes a reason and mapped controls.

## Supported security context

| Field | Supported values |
|---|---|
| `user_risk` | `low`, `medium`, `high` |
| `location_risk` | `low`, `medium`, `high` |
| `mfa_strength` | `none`, `sms`, `push`, `phishing_resistant` |
| `app_sensitivity` | `standard`, `sensitive`, `restricted` |

Values outside these contracts are treated as untrusted telemetry and produce a deny decision with `CONTEXT_VALIDATION` and `FAIL_CLOSED` control evidence.

## Fail-closed design decision

Authorization systems should not interpret malformed or unsupported security telemetry as low risk. Identity providers, device-management platforms, and policy gateways can evolve independently, so an unexpected enum value may represent schema drift, an integration defect, or incomplete telemetry. Allowing such a value to fall through normal comparisons creates a policy-bypass condition.

The engine therefore validates security context before evaluating access rules. Unsupported values are denied rather than silently coerced or defaulted. This makes integration failures visible in audit evidence and preserves the Zero Trust principle that access is granted only after explicit verification.

## Control mapping

| Control Area | Implementation Example |
|---|---|
| Identity verification | Request must include user and MFA context |
| Context integrity | Unsupported security telemetry fails closed before authorization |
| MFA | Privileged and risky access requires phishing-resistant MFA |
| Device compliance | Non-compliant endpoints are denied |
| Least privilege | Restricted apps require privilege or owner review |
| Risk-based access | Medium/high user risk triggers step-up authentication |
| Auditability | Decisions include reason and control list |

## Trust boundaries

This lab is intentionally vendor-neutral. The same policy model can be adapted to Microsoft Entra ID Conditional Access, Okta sign-on policy, ZTNA gateways, CASB controls, or custom authorization middleware. Inputs arriving from those systems cross a trust boundary: their values must conform to the policy engine's supported schema before they are trusted for an authorization decision.
