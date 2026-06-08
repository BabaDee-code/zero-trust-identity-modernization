from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Decision:
    request_id: str
    decision: str
    reason: str
    controls: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "decision": self.decision,
            "reason": self.reason,
            "controls": self.controls,
        }


def evaluate_request(request: dict[str, Any]) -> Decision:
    """Evaluate an access request using Zero Trust policy principles.

    This is intentionally deterministic and auditable. It is not tied to any
    vendor product, so the logic can be mapped to Entra ID Conditional Access,
    Okta, Zscaler, Netskope, or custom authorization layers.
    """
    request_id = str(request.get("request_id", "unknown"))
    user_risk = request.get("user_risk", "low")
    device_compliant = bool(request.get("device_compliant", False))
    mfa_strength = request.get("mfa_strength", "none")
    privileged = bool(request.get("privileged", False))
    location_risk = request.get("location_risk", "low")
    app_sensitivity = request.get("app_sensitivity", "standard")

    controls = ["IDENTITY_VERIFICATION", "AUDIT_LOGGING"]

    if not device_compliant:
        return Decision(
            request_id,
            "deny",
            "device is not compliant with endpoint security baseline",
            controls + ["DEVICE_COMPLIANCE"],
        )

    if location_risk == "high":
        return Decision(
            request_id,
            "deny",
            "high-risk location requires access block pending review",
            controls + ["LOCATION_RISK"],
        )

    if privileged and mfa_strength != "phishing_resistant":
        return Decision(
            request_id,
            "step_up_mfa",
            "privileged access requires phishing-resistant MFA",
            controls + ["PRIVILEGED_ACCESS", "MFA"],
        )

    if user_risk in {"medium", "high"} and mfa_strength != "phishing_resistant":
        return Decision(
            request_id,
            "step_up_mfa",
            "medium or high user risk requires phishing-resistant MFA",
            controls + ["RISK_BASED_ACCESS", "MFA"],
        )

    if app_sensitivity == "restricted" and not privileged:
        return Decision(
            request_id,
            "review",
            "restricted application access requires owner approval",
            controls + ["LEAST_PRIVILEGE", "ACCESS_REVIEW"],
        )

    return Decision(
        request_id,
        "allow",
        "request satisfies Zero Trust access requirements",
        controls + ["DEVICE_COMPLIANCE", "MFA", "LEAST_PRIVILEGE"],
    )
