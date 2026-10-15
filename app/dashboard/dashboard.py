
from html import escape

from app.core.dashboard_stats import (
    get_dashboard_stats,
    get_recent_events,
    get_recent_alerts,
)


def safe(value) -> str:
    return escape(str(value if value is not None else "-"))


def generate_dashboard() -> str:
    stats = get_dashboard_stats()
    events = get_recent_events(5)
    alerts = get_recent_alerts(5)

    category_rows = "".join(
        f"<tr><td>{safe(category)}</td><td>{count}</td></tr>"
        for category, count in stats["attack_categories"].items()
    )

    severity_rows = "".join(
        f"<tr><td>{safe(severity.upper())}</td><td>{count}</td></tr>"
        for severity, count in stats["severity_counts"].items()
    )

    event_rows = ""

    for event in events:
        findings = event.get("findings", [])
        finding_summary = ", ".join(
            f"{finding.get('category', 'UNKNOWN')} "
            f"({finding.get('location', 'unknown')})"
            for finding in findings
        ) or "-"

        event_rows += f"""
        <tr>
            <td>{safe(event.get('timestamp', '-'))}</td>
            <td>{safe(event.get('client_ip', '-'))}</td>
            <td>{safe(event.get('path', '-'))}</td>
            <td>{safe(event.get('category') or 'NORMAL')}</td>
            <td>{safe(event.get('severity', '-'))}</td>
            <td>{safe(event.get('action', 'UNKNOWN'))}</td>
            <td>{safe(finding_summary)}</td>
        </tr>
        """

    alert_rows = "".join(
        f"""
        <tr>
            <td>{safe(alert.get('timestamp', '-'))}</td>
            <td>{safe(alert.get('category', '-'))}</td>
            <td>{safe(alert.get('severity', '-'))}</td>
            <td>{safe(alert.get('action', '-'))}</td>
        </tr>
        """
        for alert in alerts
    )

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelShield Dashboard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 24px;
            background: #f4f6f8;
            color: #202833;
        }}
        h1 {{ margin-bottom: 24px; }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .number {{
            font-size: 28px;
            font-weight: bold;
            margin-top: 8px;
        }}
        section {{
            margin-top: 24px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        th {{ background: #f0f2f4; }}
        @media (max-width: 760px) {{
            body {{ padding: 12px; }}
            .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
        }}
    </style>
</head>
<body>
    <h1>🛡 SentinelShield Security Dashboard</h1>

    <div class="cards">
        <div class="card">
            <div>Total Requests</div>
            <div class="number">{stats["total_requests"]}</div>
        </div>
        <div class="card">
            <div>Blocked Requests</div>
            <div class="number">{stats["blocked_requests"]}</div>
        </div>
        <div class="card">
            <div>Allowed Requests</div>
            <div class="number">{stats["allowed_requests"]}</div>
        </div>
        <div class="card">
            <div>Security Alerts</div>
            <div class="number">{stats["total_alerts"]}</div>
        </div>
    </div>

    <section>
        <h2>Attack Categories</h2>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
            {category_rows}
        </table>
    </section>

    <section>
        <h2>Severity Breakdown</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {severity_rows}
        </table>
    </section>

    <section>
        <h2>Recent Security Events</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>IP</th>
                <th>Path</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Action</th>
                <th>Findings / Location</th>
            </tr>
            {event_rows}
        </table>
    </section>

    <section>
        <h2>Recent Alerts</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Action</th>
            </tr>
            {alert_rows}
        </table>
    </section>
</body>
</html>
"""


def save_dashboard(output_file: str = "dashboard.html") -> None:
    html = generate_dashboard()

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)
