from app.detectors.rule_detector import inspect_request
from app.models.request import HTTPRequest


def test_normal_request_is_allowed():
    request = HTTPRequest(
        method="GET",
        path="/home",
    )

    result = inspect_request(request)

    assert result.action == "ALLOW"
    assert result.detected is False


def test_sql_injection_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/login",
        query_params={"id": "or 1=1"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "SQL_INJECTION"
    assert result.severity == "high"


def test_xss_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/search",
        query_params={"q": "<script>alert(1)</script>"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "XSS"


def test_path_traversal_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/files/../../etc/passwd",
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "PATH_TRAVERSAL"


def test_lfi_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/page",
        query_params={"file": "/etc/passwd"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "LFI"
    assert result.severity == "critical"


def test_command_injection_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/run",
        query_params={"cmd": "test; id"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "COMMAND_INJECTION"
    assert result.severity == "critical"


def test_sql_injection_union_select_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/users",
        query_params={"id": "1 UNION SELECT username FROM users"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "SQL_INJECTION"


def test_xss_javascript_protocol_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/redirect",
        query_params={"next": "javascript:alert(1)"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "XSS"


def test_command_injection_pipe_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/run",
        query_params={"cmd": "test | whoami"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "COMMAND_INJECTION"


def test_attack_in_request_header_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/profile",
        headers={"User-Agent": "<script>alert(1)</script>"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "XSS"


def test_sql_injection_is_case_insensitive():
    request = HTTPRequest(
        method="GET",
        path="/login",
        query_params={"id": "OR 1=1"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "SQL_INJECTION"


def test_sql_injection_with_extra_whitespace_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/login",
        query_params={"id": "1 OR    1 = 1"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "SQL_INJECTION"


def test_command_substitution_is_blocked():
    request = HTTPRequest(
        method="GET",
        path="/run",
        query_params={"cmd": "$(whoami)"},
    )

    result = inspect_request(request)

    assert result.action == "BLOCK"
    assert result.category == "COMMAND_INJECTION"


def test_safe_search_query_is_allowed():
    request = HTTPRequest(
        method="GET",
        path="/search",
        query_params={"q": "security testing basics"},
    )

    result = inspect_request(request)

    assert result.action == "ALLOW"
    assert result.detected is False
