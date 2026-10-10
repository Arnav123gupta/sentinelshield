from app.core.request_protection import RequestProtection
from app.models.request import HTTPRequest


def test_detected_request_is_logged(monkeypatch):
    logged_events = []

    def fake_log_detection(request, result):
        logged_events.append((request, result))

    monkeypatch.setattr(
        "app.core.request_protection.log_detection",
        fake_log_detection,
    )

    protection = RequestProtection()

    request = HTTPRequest(
        method="GET",
        path="/login",
        query_params={"id": "1 OR 1=1"},
    )

    decision = protection.check(request)

    assert decision == "BLOCK"
    assert len(logged_events) == 1
    assert logged_events[0][1].action == "BLOCK"


def test_safe_request_does_not_log_detection(monkeypatch):
    logged_events = []

    def fake_log_detection(request, result):
        logged_events.append((request, result))

    monkeypatch.setattr(
        "app.core.request_protection.log_detection",
        fake_log_detection,
    )

    protection = RequestProtection()

    request = HTTPRequest(
        method="GET",
        path="/home",
    )

    decision = protection.check(request)

    assert decision == "ALLOW"
    assert logged_events == []
