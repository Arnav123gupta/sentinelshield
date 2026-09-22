import re

from app.models.request import HTTPRequest
from app.models.detection import DetectionResult


RULES = {
    "SQL_INJECTION": [
        (r"\bunion\s+select\b", "high"),
        (r"\bor\s+1\s*=\s*1\b", "high"),
        (r"\band\s+1\s*=\s*1\b", "high"),
    ],
    "XSS": [
        (r"<\s*script\b", "high"),
        (r"javascript\s*:", "high"),
        (r"onerror\s*=", "high"),
    ],
    "PATH_TRAVERSAL": [
        (r"\.\./", "high"),
        (r"\.\.\\", "high"),
    ],
    "LFI": [
        (r"/etc/passwd", "critical"),
        (r"\.\./.*etc/passwd", "critical"),
    ],
    "COMMAND_INJECTION": [
        (r";\s*(?:id|whoami|uname|cat)\b", "critical"),
        (r"\|\s*(?:id|whoami|uname|cat)\b", "critical"),
        (r"\$\(\s*(?:id|whoami|uname|cat)\s*\)", "critical"),
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

    for category, rules in RULES.items():
        for pattern, severity in rules:
            if re.search(pattern, target, re.IGNORECASE):
                return DetectionResult(
                    detected=True,
                    category=category,
                    rule=pattern,
                    severity=severity,
                    action="BLOCK",
                    reason=f"Matched {category} detection rule",
                )

    return DetectionResult(
        detected=False,
        severity="low",
        action="ALLOW",
        reason="No configured detection rule matched",
    )
