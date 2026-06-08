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
