from collections import Counter
from app.logging.log_viewer import read_log, SECURITY_LOG, ALERT_LOG


def get_dashboard_stats() -> dict:
    events = read_log(SECURITY_LOG)
    alerts = read_log(ALERT_LOG)

    total_requests = len(events)
    blocked_requests = sum(
        1 for event in events if event.get("action") == "BLOCK"
    )
    allowed_requests = sum(
        1 for event in events if event.get("action") == "ALLOW"
    )

    attack_categories = Counter(
        event.get("category")
        for event in events
        if event.get("category")
    )

    severity_counts = Counter(
        event.get("severity")
        for event in events
        if event.get("detected")
    )

    return {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed_requests,
        "attack_categories": dict(attack_categories),
        "severity_counts": dict(severity_counts),
        "total_alerts": len(alerts),
    }


def get_recent_events(limit: int = 5) -> list[dict]:
    events = read_log(SECURITY_LOG)
    return events[-limit:]


def get_recent_alerts(limit: int = 5) -> list[dict]:
    alerts = read_log(ALERT_LOG)
    return alerts[-limit:]
