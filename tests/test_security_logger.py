import json

from app.logging import security_logger
from app.logging.security_logger import log_detection
from app.detectors.rule_detector import inspect_request
from app.models.request import HTTPRequest


def test_log_detection_saves_finding_location(tmp_path, monkeypatch):
    log_file = tmp_path / "security_events.log"
    monkeypatch.setattr(security_logger, "LOG_FILE", log_file)

    request = HTTPRequest(
        method="GET",
        path="/login",
        query_params={"id": "1 OR 1=1"},
    )

    result = inspect_request(request)

    log_detection(request, result)

    event = json.loads(log_file.read_text(encoding="utf-8"))

    assert event["detected"] is True
    assert event["action"] == "BLOCK"
    assert event["findings"]
    assert event["findings"][0]["location"] == "query"


def test_log_detection_saves_empty_findings_for_safe_request(
    tmp_path, monkeypatch
):
    log_file = tmp_path / "security_events.log"
    monkeypatch.setattr(security_logger, "LOG_FILE", log_file)

    request = HTTPRequest(
        method="GET",
        path="/home",
    )

    result = inspect_request(request)

    log_detection(request, result)

    event = json.loads(log_file.read_text(encoding="utf-8"))

    assert event["detected"] is False
    assert event["findings"] == []
