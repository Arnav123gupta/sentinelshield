from html import escape
import json

from app.core.dashboard_stats import (
    get_dashboard_stats,
    get_recent_events,
    get_recent_alerts,
)


def safe(value) -> str:
    return escape(str(value if value is not None else "-"))


def generate_dashboard() -> str:
    stats = get_dashboard_stats()
    events = get_recent_events(100)
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
    filter_events = []

    for event in events:
        findings = event.get("findings", [])
        finding_summary = ", ".join(
            f"{finding.get('category', 'UNKNOWN')} "
            f"({finding.get('location', 'unknown')})"
            for finding in findings
        ) or "-"

        category = str(event.get("category") or "NORMAL")
        severity = str(event.get("severity") or "unknown")
        action = str(event.get("action") or "UNKNOWN")

        filter_events.append({
            "timestamp": str(event.get("timestamp", "-")),
            "client_ip": str(event.get("client_ip", "-")),
            "path": str(event.get("path", "-")),
            "category": category,
            "severity": severity,
            "action": action,
            "findings": finding_summary,
        })

        event_rows += f"""
        <tr>
            <td>{safe(event.get('timestamp', '-'))}</td>
            <td>{safe(event.get('client_ip', '-'))}</td>
            <td>{safe(event.get('path', '-'))}</td>
            <td>{safe(category)}</td>
            <td>{safe(severity)}</td>
            <td>{safe(action)}</td>
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

    events_json = json.dumps(filter_events).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelShield Security Dashboard</title>
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
        .filters {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 16px;
        }}
        .filters label {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            font-size: 14px;
            font-weight: bold;
        }}
        select, input, button {{
            padding: 9px;
            border: 1px solid #cbd2d9;
            border-radius: 6px;
            background: white;
            color: #202833;
        }}
        button {{
            cursor: pointer;
            align-self: end;
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
        .empty {{
            text-align: center;
            padding: 20px;
            color: #657080;
        }}
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
        <div class="filters">
            <label>Action
                <select id="actionFilter">
                    <option value="">All actions</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="ALLOW">ALLOW</option>
                </select>
            </label>
            <label>Category
                <select id="categoryFilter">
                    <option value="">All categories</option>
                </select>
            </label>
            <label>Severity
                <select id="severityFilter">
                    <option value="">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="unknown">Unknown</option>
                </select>
            </label>
            <label>Search path or IP
                <input id="searchFilter" type="search" placeholder="/login or IP">
            </label>
            <button id="resetFilters" type="button">Reset filters</button>
        </div>
        <p id="filterCount" aria-live="polite"></p>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP</th>
                    <th>Path</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Action</th>
                    <th>Findings / Location</th>
                </tr>
            </thead>
            <tbody id="eventTableBody">
                {event_rows}
            </tbody>
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

    <script id="eventData" type="application/json">{events_json}</script>
    <script>
    (() => {{
        const data = JSON.parse(document.getElementById("eventData").textContent);
        const actionFilter = document.getElementById("actionFilter");
        const categoryFilter = document.getElementById("categoryFilter");
        const severityFilter = document.getElementById("severityFilter");
        const searchFilter = document.getElementById("searchFilter");
        const tableBody = document.getElementById("eventTableBody");
        const countLabel = document.getElementById("filterCount");

        const categories = [...new Set(data.map(e => e.category))].sort();
        categories.forEach(category => {{
            const option = document.createElement("option");
            option.value = category;
            option.textContent = category;
            categoryFilter.appendChild(option);
        }});

        function cell(value) {{
            const td = document.createElement("td");
            td.textContent = value ?? "-";
            return td;
        }}

        function render() {{
            const action = actionFilter.value.toUpperCase();
            const category = categoryFilter.value.toUpperCase();
            const severity = severityFilter.value.toLowerCase();
            const search = searchFilter.value.trim().toLowerCase();

            const filtered = data.filter(event =>
                (!action || event.action.toUpperCase() === action) &&
                (!category || event.category.toUpperCase() === category) &&
                (!severity || event.severity.toLowerCase() === severity) &&
                (!search ||
                    event.path.toLowerCase().includes(search) ||
                    event.client_ip.toLowerCase().includes(search))
            );

            tableBody.replaceChildren();

            if (filtered.length === 0) {{
                const row = document.createElement("tr");
                const td = cell("No matching security events.");
                td.colSpan = 7;
                td.className = "empty";
                row.appendChild(td);
                tableBody.appendChild(row);
            }} else {{
                filtered.forEach(event => {{
                    const row = document.createElement("tr");
                    [
                        event.timestamp,
                        event.client_ip,
                        event.path,
                        event.category,
                        event.severity,
                        event.action,
                        event.findings
                    ].forEach(value => row.appendChild(cell(value)));
                    tableBody.appendChild(row);
                }});
            }}

            countLabel.textContent = `Showing ${{filtered.length}} of ${{data.length}} events`;
        }}

        [actionFilter, categoryFilter, severityFilter].forEach(
            element => element.addEventListener("change", render)
        );
        searchFilter.addEventListener("input", render);

        document.getElementById("resetFilters").addEventListener("click", () => {{
            actionFilter.value = "";
            categoryFilter.value = "";
            severityFilter.value = "";
            searchFilter.value = "";
            render();
        }});

        render();
    }})();
    </script>
</body>
</html>
"""


def save_dashboard(output_file: str = "dashboard.html") -> None:
    html = generate_dashboard()

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)
