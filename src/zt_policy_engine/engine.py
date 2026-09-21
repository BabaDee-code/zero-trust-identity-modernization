from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_CONTEXT_VALUES = {
    "user_risk": {"low", "medium", "high"},
    "location_risk": {"low", "medium", "high"},
    "mfa_strength": {"none", "sms", "push", "phishing_resistant"},
    "app_sensitivity": {"standard", "sensitive", "restricted"},
}


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

    Security context is validated before policy evaluation. Unsupported values
    fail closed so malformed identity or device telemetry cannot silently weaken
    an authorization decision.
    """
    request_id = str(request.get("request_id", "unknown"))
    user_risk = request.get("user_risk", "low")
    device_compliant = bool(request.get("device_compliant", False))
    mfa_strength = request.get("mfa_strength", "none")
    privileged = bool(request.get("privileged", False))
    location_risk = request.get("location_risk", "low")
    app_sensitivity = request.get("app_sensitivity", "standard")

    controls = ["IDENTITY_VERIFICATION", "AUDIT_LOGGING"]
    context = {
        "user_risk": user_risk,
        "location_risk": location_risk,
        "mfa_strength": mfa_strength,
        "app_sensitivity": app_sensitivity,
    }

    invalid_fields = [
        field
        for field, value in context.items()
        if value not in VALID_CONTEXT_VALUES[field]
    ]
    if invalid_fields:
        return Decision(
            request_id,
            "deny",
            f"invalid security context: unsupported value for {', '.join(invalid_fields)}",
            controls + ["CONTEXT_VALIDATION", "FAIL_CLOSED"],
        )

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
