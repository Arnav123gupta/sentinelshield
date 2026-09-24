import json
from datetime import datetime, timezone
from pathlib import Path


ALERT_LOG_FILE = Path("logs/security_alerts.log")


def log_alert(alert: dict) -> None:
    ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **alert,
    }

    with ALERT_LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
