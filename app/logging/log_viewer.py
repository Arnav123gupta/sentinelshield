import json
from pathlib import Path


SECURITY_LOG = Path("logs/security_events.log")
ALERT_LOG = Path("logs/security_alerts.log")


def read_log(log_file: Path) -> list[dict]:
    if not log_file.exists():
        return []

    events = []

    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def show_security_events() -> None:
    events = read_log(SECURITY_LOG)

    print("=== SECURITY EVENTS ===")

    for event in events:
        print(
            f"{event.get('timestamp')} | "
            f"{event.get('client_ip')} | "
            f"{event.get('category') or 'NORMAL'} | "
            f"{event.get('severity')} | "
            f"{event.get('action', 'UNKNOWN')}"
        )


def show_alerts() -> None:
    alerts = read_log(ALERT_LOG)

    print("=== SECURITY ALERTS ===")

    for alert in alerts:
        print(
            f"{alert.get('timestamp')} | "
            f"{alert.get('category')} | "
            f"{alert.get('severity')} | "
            f"{alert.get('action')}"
        )
