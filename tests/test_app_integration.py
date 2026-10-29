from app.main import app


def test_home_request_returns_dashboard_html():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"SentinelShield Security Dashboard" in response.data
    assert b"Recent Security Events" in response.data


def test_safe_path_returns_allowed_response():
    client = app.test_client()

    response = client.get("/integration-safe-page")

    assert response.status_code == 200
    assert response.get_json()["status"] == "allowed"
    assert response.get_json()["path"] == "/integration-safe-page"


def test_sql_injection_query_returns_403():
    client = app.test_client()

    response = client.get("/integration-login?id=1%20OR%201%3D1")

    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "blocked"
    assert "blocked" in data["message"].lower()


def test_safe_post_request_returns_allowed():
    client = app.test_client()

    response = client.post(
        "/integration-submit",
        data={"comment": "hello"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "allowed"


def test_response_is_json_for_blocked_request():
    client = app.test_client()

    response = client.get("/integration-search?q=%3Cscript%3Ealert(1)%3C/script%3E")

    assert response.status_code == 403
    assert response.is_json


def test_route_passes_request_path_to_response():
    client = app.test_client()

    response = client.get("/integration/nested/resource")

    assert response.status_code == 200
    assert response.get_json()["path"] == "/integration/nested/resource"
