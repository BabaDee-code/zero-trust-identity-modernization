from zt_policy_engine.engine import evaluate_request


def test_non_compliant_device_is_denied():
    decision = evaluate_request({"request_id": "T1", "device_compliant": False})
    assert decision.decision == "deny"
    assert "DEVICE_COMPLIANCE" in decision.controls


def test_privileged_user_requires_phishing_resistant_mfa():
    decision = evaluate_request(
        {
            "request_id": "T2",
            "device_compliant": True,
            "privileged": True,
            "mfa_strength": "push",
            "location_risk": "low",
        }
    )
    assert decision.decision == "step_up_mfa"
    assert "PRIVILEGED_ACCESS" in decision.controls


def test_valid_request_is_allowed():
    decision = evaluate_request(
        {
            "request_id": "T3",
            "device_compliant": True,
            "privileged": False,
            "mfa_strength": "phishing_resistant",
            "location_risk": "low",
            "user_risk": "low",
            "app_sensitivity": "standard",
        }
    )
    assert decision.decision == "allow"


def test_invalid_user_risk_fails_closed():
    decision = evaluate_request(
        {
            "request_id": "T4",
            "device_compliant": True,
            "mfa_strength": "phishing_resistant",
            "user_risk": "unknown",
        }
    )
    assert decision.decision == "deny"
    assert "CONTEXT_VALIDATION" in decision.controls
    assert "FAIL_CLOSED" in decision.controls


def test_invalid_mfa_strength_fails_closed():
    decision = evaluate_request(
        {
            "request_id": "T5",
            "device_compliant": True,
            "mfa_strength": "magic_link",
        }
    )
    assert decision.decision == "deny"
    assert "mfa_strength" in decision.reason


def test_invalid_app_sensitivity_fails_closed():
    decision = evaluate_request(
        {
            "request_id": "T6",
            "device_compliant": True,
            "mfa_strength": "phishing_resistant",
            "app_sensitivity": "top_secret",
        }
    )
    assert decision.decision == "deny"
    assert "app_sensitivity" in decision.reason


def test_multiple_invalid_context_fields_are_reported():
    decision = evaluate_request(
        {
            "request_id": "T7",
            "device_compliant": True,
            "mfa_strength": "invalid",
            "location_risk": "unknown",
        }
    )
    assert decision.decision == "deny"
    assert "location_risk" in decision.reason
    assert "mfa_strength" in decision.reason
