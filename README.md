# Zero Trust Identity Modernization

![CI](https://github.com/BabaDee-code/zero-trust-identity-modernization/actions/workflows/ci.yml/badge.svg)

A portfolio-grade Zero Trust lab that demonstrates identity-centered access control, device posture validation, risk-based conditional access, privileged access review, and audit-ready policy decisions.

## What this project shows

- Zero Trust decision logic using identity, device, network, application, and risk context
- Policy-as-code design for conditional access decisions
- Least-privilege access modeling for workforce and privileged users
- Audit-ready JSON decision output for governance and incident review
- Unit tests and CI validation so employers can trust the implementation

## Architecture

```text
User / Device / Location / App Context
              |
              v
      Zero Trust Policy Engine
              |
    +---------+---------+
    |                   |
Allow / Step-up MFA / Deny / Review
              |
              v
      Audit Decision Record
```

## Repository structure

```text
src/zt_policy_engine/       Core policy engine
data/                       Sample access requests
policies/                   Policy-as-code controls
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/architecture.md        Architecture and control mapping
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest -q
python -m zt_policy_engine.evaluate data/sample_requests.json
```

## Example output

```json
{
  "request_id": "REQ-1001",
  "decision": "step_up_mfa",
  "reason": "medium user risk requires phishing-resistant MFA",
  "controls": ["MFA", "DEVICE_COMPLIANCE", "RISK_BASED_ACCESS"]
}
```

## Security controls represented

- Identity verification and MFA
- Device compliance and posture checks
- Privileged access review
- Location and network risk checks
- Audit logging and decision evidence
- Least-privilege authorization

## Portfolio talking points

This project demonstrates how I would modernize enterprise identity controls by turning Zero Trust principles into testable security engineering logic. It also shows how security architecture can be translated into policy-as-code, measurable control outcomes, and evidence that can support SOC 2, ISO 27001, HIPAA, or internal audit requirements.
