# Architecture and Control Mapping

## Objective

This repository demonstrates how Zero Trust security principles can be translated into deterministic policy logic that is testable, auditable, and reusable across enterprise identity platforms.

## Core components

1. **Access request context**: user risk, device compliance, MFA strength, location risk, privilege level, and application sensitivity.
2. **Policy engine**: evaluates access context against security control requirements.
3. **Decision output**: returns allow, deny, step-up MFA, or review.
4. **Audit evidence**: each decision includes a reason and mapped controls.

## Control mapping

| Control Area | Implementation Example |
|---|---|
| Identity verification | Request must include user and MFA context |
| MFA | Privileged and risky access requires phishing-resistant MFA |
| Device compliance | Non-compliant endpoints are denied |
| Least privilege | Restricted apps require privilege or owner review |
| Risk-based access | Medium/high user risk triggers step-up authentication |
| Auditability | Decisions include reason and control list |

## Trust boundaries

This lab is intentionally vendor-neutral. The same policy model can be adapted to Microsoft Entra ID Conditional Access, Okta sign-on policy, ZTNA gateways, CASB controls, or custom authorization middleware.
