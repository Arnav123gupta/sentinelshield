import json
from datetime import datetime, timezone
from pathlib import Path

from app.models.request import HTTPRequest
from app.models.detection import DetectionResult


LOG_FILE = Path("logs/security_events.log")


def log_detection(
    request: HTTPRequest,
    result: DetectionResult,
) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": request.client_ip,
        "method": request.method,
        "path": request.path,
        "detected": result.detected,
        "action": result.action,
        "category": result.category,
        "severity": result.severity,
        "rule": result.rule,
        "reason": result.reason,
        "findings": [
            {
                "category": finding.category,
                "rule": finding.rule,
                "severity": finding.severity,
                "location": finding.location,
            }
            for finding in result.findings
        ],
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
