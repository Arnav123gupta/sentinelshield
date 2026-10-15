import json
from datetime import datetime
from pathlib import Path

from app.models.detection import DetectionResult
from app.logging import alert_logger, alert_manager, log_viewer
from app.core import dashboard_stats


def test_alert_manager_ignores_low_severity():
    result = DetectionResult(
        detected=True,
        category="XSS",
        severity="low",
        action="BLOCK",
    )
    assert alert_manager.should_alert(result) is False
    assert alert_manager.create_alert(result) is None


def test_alert_manager_creates_high_severity_alert():
    result = DetectionResult(
        detected=True,
        category="SQL_INJECTION",
        severity="high",
        action="BLOCK",
        reason="Matched a test rule",
    )
    alert = alert_manager.create_alert(result)
    assert alert is not None
    assert alert["alert"] is True
    assert alert["category"] == "SQL_INJECTION"
    assert alert["severity"] == "high"
    assert alert["action"] == "BLOCK"


def test_alert_manager_creates_critical_alert():
    result = DetectionResult(
        detected=True,
        category="COMMAND_INJECTION",
        severity="critical",
        action="BLOCK",
    )
    assert alert_manager.should_alert(result) is True


def test_alert_manager_ignores_undetected_critical_result():
    result = DetectionResult(
        detected=False,
        severity="critical",
        action="ALLOW",
    )
    assert alert_manager.should_alert(result) is False


def test_alert_logger_writes_json_line(tmp_path, monkeypatch):
    log_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(alert_logger, "ALERT_LOG_FILE", log_file)

    alert_logger.log_alert({"category": "XSS", "severity": "high"})

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "XSS"
    assert event["severity"] == "high"
    assert "timestamp" in event


def test_alert_logger_timestamp_cannot_be_overridden(tmp_path, monkeypatch):
    log_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(alert_logger, "ALERT_LOG_FILE", log_file)

    alert_logger.log_alert({
        "category": "XSS",
        "timestamp": "caller-supplied-invalid-timestamp",
    })

    event = json.loads(log_file.read_text(encoding="utf-8"))
    assert event["timestamp"] != "caller-supplied-invalid-timestamp"
    datetime.fromisoformat(event["timestamp"])


def test_read_log_returns_empty_for_missing_file(tmp_path):
    assert log_viewer.read_log(tmp_path / "missing.jsonl") == []


def test_read_log_skips_blank_and_invalid_lines(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        '{"action":"BLOCK"}\n\nnot-json\n{"action":"ALLOW"}\n',
        encoding="utf-8",
    )

    events = log_viewer.read_log(log_file)
    assert events == [{"action": "BLOCK"}, {"action": "ALLOW"}]


def test_read_log_preserves_unicode(tmp_path):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        json.dumps({"reason": "prueba de seguridad"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    assert log_viewer.read_log(log_file)[0]["reason"] == "prueba de seguridad"


def test_dashboard_stats_counts_actions_and_alerts(tmp_path, monkeypatch):
    security_file = tmp_path / "events.jsonl"
    alert_file = tmp_path / "alerts.jsonl"

    security_file.write_text(
        "\n".join([
            json.dumps({"action": "BLOCK", "category": "XSS", "severity": "high", "detected": True}),
            json.dumps({"action": "ALLOW", "category": None, "severity": "low", "detected": False}),
            json.dumps({"action": "BLOCK", "category": "XSS", "severity": "critical", "detected": True}),
        ]) + "\n",
        encoding="utf-8",
    )
    alert_file.write_text('{"category":"XSS"}\n', encoding="utf-8")

    monkeypatch.setattr(dashboard_stats, "SECURITY_LOG", security_file)
    monkeypatch.setattr(dashboard_stats, "ALERT_LOG", alert_file)

    stats = dashboard_stats.get_dashboard_stats()
    assert stats["total_requests"] == 3
    assert stats["blocked_requests"] == 2
    assert stats["allowed_requests"] == 1
    assert stats["attack_categories"] == {"XSS": 2}
    assert stats["severity_counts"] == {"high": 1, "critical": 1}
    assert stats["total_alerts"] == 1


def test_recent_events_respects_limit(tmp_path, monkeypatch):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        "".join(json.dumps({"number": i}) + "\n" for i in range(4)),
        encoding="utf-8",
    )
    monkeypatch.setattr(dashboard_stats, "SECURITY_LOG", log_file)

    assert dashboard_stats.get_recent_events(2) == [{"number": 2}, {"number": 3}]


def test_recent_events_zero_limit_returns_empty(tmp_path, monkeypatch):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text('{"number":1}\n', encoding="utf-8")
    monkeypatch.setattr(dashboard_stats, "SECURITY_LOG", log_file)

    assert dashboard_stats.get_recent_events(0) == []


def test_recent_events_negative_limit_returns_empty(tmp_path, monkeypatch):
    log_file = tmp_path / "events.jsonl"
    log_file.write_text('{"number":1}\n', encoding="utf-8")
    monkeypatch.setattr(dashboard_stats, "SECURITY_LOG", log_file)

    assert dashboard_stats.get_recent_events(-1) == []


def test_recent_alerts_zero_limit_returns_empty(tmp_path, monkeypatch):
    log_file = tmp_path / "alerts.jsonl"
    log_file.write_text('{"category":"XSS"}\n', encoding="utf-8")
    monkeypatch.setattr(dashboard_stats, "ALERT_LOG", log_file)

    assert dashboard_stats.get_recent_alerts(0) == []
