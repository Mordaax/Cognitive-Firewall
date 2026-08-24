from cognitive_firewall.detectors.pii import detect_pii


def test_email_before_sentence_period_is_detected():
    findings = detect_pii("Contact alice@example.com.")
    assert any(item.category == "email" for item in findings)
from cognitive_firewall.detectors.secrets import detect_secrets


def test_detects_supported_pii_in_text_and_nested_json():
    payload = {"case": {"email": "alice@example.com", "phone": "+1 415 555 0182", "ip": "192.0.2.8", "customer_id": "CUS-12345", "username": "alice_7"}}
    findings = detect_pii(payload)
    categories = {f.category for f in findings}
    assert {"email", "phone", "ip", "customer_id", "username"} <= categories
    assert any(f.json_path == "$.case.email" for f in findings)
    assert any(f.category == "email" for f in detect_pii("Contact alice@example.com"))


def test_secrets_win_over_overlapping_pii_and_are_not_recorded_as_values():
    secret = "sk-" + "a" * 32
    findings = detect_secrets({"email": "alice@example.com", "api_key": secret})
    assert any(f.category == "secret" and f.json_path == "$.api_key" for f in findings)
    assert all(secret not in f.model_dump_json() for f in findings)
