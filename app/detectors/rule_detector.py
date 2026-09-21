import re

from app.models.request import HTTPRequest
from app.models.detection import DetectionResult


RULES = {
    "SQL_INJECTION": [
        r"\bunion\s+select\b",
        r"\bor\s+1\s*=\s*1\b",
        r"\band\s+1\s*=\s*1\b",
    ],
    "XSS": [
        r"<\s*script\b",
        r"javascript\s*:",
        r"onerror\s*=",
    ],
    "PATH_TRAVERSAL": [
        r"\.\./",
        r"\.\.\\",
    ],
}


def inspect_request(request: HTTPRequest) -> DetectionResult:
    header_values = [
        f"{key}: {value}"
        for key, value in request.headers.items()
    ]

    parts = [
        request.path,
        *request.query_params.values(),
        *header_values,
        request.body or "",
    ]

    target = " ".join(parts)

    for category, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, target, re.IGNORECASE):
                return DetectionResult(
                    detected=True,
                    category=category,
                    rule=pattern,
                    severity="high",
                    reason=f"Matched {category} detection rule",
                )

    return DetectionResult(
        detected=False,
        severity="low",
        reason="No configured detection rule matched",
    )
