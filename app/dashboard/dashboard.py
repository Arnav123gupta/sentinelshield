from app.core.dashboard_stats import (
    get_dashboard_stats,
    get_recent_events,
    get_recent_alerts,
)


def generate_dashboard() -> str:
    stats = get_dashboard_stats()
    events = get_recent_events(5)
    alerts = get_recent_alerts(5)

    category_rows = "".join(
        f"<tr><td>{category}</td><td>{count}</td></tr>"
        for category, count in stats["attack_categories"].items()
    )

    severity_rows = "".join(
        f"<tr><td>{severity.upper()}</td><td>{count}</td></tr>"
        for severity, count in stats["severity_counts"].items()
    )

    event_rows = "".join(
        f"""
        <tr>
            <td>{event.get('timestamp', '-')}</td>
            <td>{event.get('client_ip', '-')}</td>
            <td>{event.get('path', '-')}</td>
            <td>{event.get('category') or 'NORMAL'}</td>
            <td>{event.get('severity', '-')}</td>
            <td>{event.get('action', 'UNKNOWN')}</td>
        </tr>
        """
        for event in events
    )

    alert_rows = "".join(
        f"""
        <tr>
            <td>{alert.get('timestamp', '-')}</td>
            <td>{alert.get('category', '-')}</td>
            <td>{alert.get('severity', '-')}</td>
            <td>{alert.get('action', '-')}</td>
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
        }}

        h1 {{
            margin-bottom: 24px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
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
        }}

        section {{
            margin-top: 24px;
            background: white;
            padding: 20px;
            border-radius: 10px;
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

        th {{
            background: #f0f2f4;
        }}
    </style>
</head>

<body>
    <h1>🛡️ SentinelShield Security Dashboard</h1>

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
            <tr>
                <th>Category</th>
                <th>Count</th>
            </tr>
            {category_rows}
        </table>
    </section>

    <section>
        <h2>Severity Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
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
