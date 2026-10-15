from app.core.traffic_tracker import TrafficTracker
from app.core.rate_limiter import RateLimiter
from app.core.repeat_detector import RepeatDetector
from app.core.ip_blocker import IPBlocker
from app.core.protection_manager import ProtectionManager
from app.core.request_protection import RequestProtection
from app.models.request import HTTPRequest


def test_traffic_tracker_counts_requests():
    tracker = TrafficTracker()
    assert tracker.record_request("192.0.2.1") == 1
    assert tracker.record_request("192.0.2.1") == 2


def test_traffic_tracker_keeps_clients_separate():
    tracker = TrafficTracker()
    tracker.record_request("192.0.2.1")
    tracker.record_request("192.0.2.2")
    assert tracker.get_request_count("192.0.2.1") == 1
    assert tracker.get_request_count("192.0.2.2") == 1


def test_traffic_tracker_expires_old_requests(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("app.core.traffic_tracker.time", lambda: clock[0])
    tracker = TrafficTracker(window_seconds=10)

    tracker.record_request("192.0.2.1")
    clock[0] = 105.0
    tracker.record_request("192.0.2.1")
    assert tracker.get_request_count("192.0.2.1") == 2

    clock[0] = 111.0
    assert tracker.get_request_count("192.0.2.1") == 1


def test_rate_limiter_allows_requests_under_limit():
    limiter = RateLimiter(max_requests=2)
    assert limiter.check_request("192.0.2.1") is True
    assert limiter.check_request("192.0.2.1") is True


def test_rate_limiter_blocks_request_over_limit():
    limiter = RateLimiter(max_requests=2)
    assert limiter.check_request("192.0.2.1") is True
    assert limiter.check_request("192.0.2.1") is True
    assert limiter.check_request("192.0.2.1") is False


def test_rate_limiter_tracks_clients_separately():
    limiter = RateLimiter(max_requests=1)
    assert limiter.check_request("192.0.2.1") is True
    assert limiter.check_request("192.0.2.2") is True
    assert limiter.check_request("192.0.2.1") is False


def test_repeat_detector_allows_up_to_configured_repeats():
    detector = RepeatDetector(max_repeats=2)
    assert detector.check("192.0.2.1", "GET:/login") is False
    assert detector.check("192.0.2.1", "GET:/login") is False


def test_repeat_detector_flags_excess_repeats():
    detector = RepeatDetector(max_repeats=2)
    for _ in range(2):
        assert detector.check("192.0.2.1", "GET:/login") is False
    assert detector.check("192.0.2.1", "GET:/login") is True


def test_repeat_detector_separates_clients_and_paths():
    detector = RepeatDetector(max_repeats=1)
    assert detector.check("192.0.2.1", "GET:/login") is False
    assert detector.check("192.0.2.2", "GET:/login") is False
    assert detector.check("192.0.2.1", "GET:/home") is False


def test_repeat_detector_expires_old_repeats(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("app.core.repeat_detector.time", lambda: clock[0])
    detector = RepeatDetector(max_repeats=1, window_seconds=10)

    assert detector.check("192.0.2.1", "GET:/login") is False
    clock[0] = 111.0
    assert detector.check("192.0.2.1", "GET:/login") is False


def test_ip_blocker_allows_unblocked_ip():
    blocker = IPBlocker()
    assert blocker.is_blocked("192.0.2.1") is False


def test_ip_blocker_blocks_and_expires_ip(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("app.core.ip_blocker.time", lambda: clock[0])
    blocker = IPBlocker(block_seconds=5)

    blocker.block("192.0.2.1")
    assert blocker.is_blocked("192.0.2.1") is True

    clock[0] = 105.0
    assert blocker.is_blocked("192.0.2.1") is False
    assert "192.0.2.1" not in blocker.blocked_ips


def test_protection_manager_blocks_after_rate_limit():
    manager = ProtectionManager(
        max_requests=2,
        max_repeats=100,
        block_seconds=30,
    )
    assert manager.check_request("192.0.2.1", "GET:/one") == "ALLOW"
    assert manager.check_request("192.0.2.1", "GET:/two") == "ALLOW"
    assert manager.check_request("192.0.2.1", "GET:/three") == "BLOCK"
    assert manager.check_request("192.0.2.1", "GET:/four") == "BLOCK"


def test_protection_manager_blocks_excess_repeated_requests():
    manager = ProtectionManager(
        max_requests=100,
        max_repeats=2,
        block_seconds=30,
    )
    assert manager.check_request("192.0.2.1", "GET:/login") == "ALLOW"
    assert manager.check_request("192.0.2.1", "GET:/login") == "ALLOW"
    assert manager.check_request("192.0.2.1", "GET:/login") == "BLOCK"


def test_protection_manager_does_not_block_another_client():
    manager = ProtectionManager(
        max_requests=1,
        max_repeats=100,
    )
    assert manager.check_request("192.0.2.1", "GET:/one") == "ALLOW"
    assert manager.check_request("192.0.2.1", "GET:/two") == "BLOCK"
    assert manager.check_request("192.0.2.2", "GET:/one") == "ALLOW"


def test_protection_block_is_logged_as_block(monkeypatch):
    logged_events = []

    class BlockingManager:
        def check_request(self, client_ip, request_key):
            return "BLOCK"

    monkeypatch.setattr(
        "app.core.request_protection.log_detection",
        lambda request, result: logged_events.append(result),
    )

    protection = RequestProtection(manager=BlockingManager())
    request = HTTPRequest(method="GET", path="/home")

    assert protection.check(request) == "BLOCK"
    assert len(logged_events) == 1

    result = logged_events[0]
    assert result.detected is True
    assert result.action == "BLOCK"
    assert result.category == "PROTECTION"
    assert result.rule == "RATE_LIMIT_OR_REPEAT_REQUEST"
    assert result.severity == "high"
    assert "rate limiting" in result.reason.lower()
