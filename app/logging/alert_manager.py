from app.models.detection import DetectionResult


ALERT_SEVERITIES = {"high", "critical"}


def should_alert(result: DetectionResult) -> bool:
    return result.detected and result.severity.lower() in ALERT_SEVERITIES


def create_alert(result: DetectionResult) -> dict | None:
    if not should_alert(result):
        return None

    return {
        "alert": True,
        "category": result.category,
        "severity": result.severity,
        "action": result.action,
        "reason": result.reason,
    }
