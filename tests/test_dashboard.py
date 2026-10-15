
from app.dashboard.dashboard import generate_dashboard


def test_dashboard_contains_findings_location_column():
    html = generate_dashboard()

    assert "Recent Security Events" in html
    assert "Findings / Location" in html


def test_dashboard_contains_existing_sections():
    html = generate_dashboard()

    assert "Attack Categories" in html
    assert "Severity Breakdown" in html
    assert "Recent Alerts" in html


def test_dashboard_escapes_html_in_dynamic_values(monkeypatch):
    from app.dashboard import dashboard

    monkeypatch.setattr(
        dashboard,
        "get_dashboard_stats",
        lambda: {
            "total_requests": 1,
            "blocked_requests": 1,
            "allowed_requests": 0,
            "total_alerts": 1,
            "attack_categories": {"<script>alert(1)</script>": 1},
            "severity_counts": {"high": 1},
        },
    )
    monkeypatch.setattr(dashboard, "get_recent_events", lambda limit: [])
    monkeypatch.setattr(dashboard, "get_recent_alerts", lambda limit: [])

    html = dashboard.generate_dashboard()

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_dashboard_renders_finding_location(monkeypatch):
    from app.dashboard import dashboard

    monkeypatch.setattr(
        dashboard,
        "get_dashboard_stats",
        lambda: {
            "total_requests": 1,
            "blocked_requests": 1,
            "allowed_requests": 0,
            "total_alerts": 0,
            "attack_categories": {"SQL_INJECTION": 1},
            "severity_counts": {"high": 1},
        },
    )

    monkeypatch.setattr(
        dashboard,
        "get_recent_events",
        lambda limit: [
            {
                "timestamp": "2026-10-15T10:00:00",
                "client_ip": "127.0.0.1",
                "path": "/login",
                "category": "SQL_INJECTION",
                "severity": "high",
                "action": "BLOCK",
                "findings": [
                    {
                        "category": "SQL_INJECTION",
                        "location": "query",
                    }
                ],
            }
        ],
    )
    monkeypatch.setattr(dashboard, "get_recent_alerts", lambda limit: [])

    html = dashboard.generate_dashboard()

    assert "SQL_INJECTION (query)" in html

