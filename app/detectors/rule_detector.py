import re
from urllib.parse import unquote_plus

from app.models.request import HTTPRequest
from app.models.detection import DetectionFinding, DetectionResult


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


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def normalize_detection_input(value: str) -> str:
    return unquote_plus(value)


def get_detection_sources(request: HTTPRequest) -> list[tuple[str, str]]:
    sources = [
        ("path", normalize_detection_input(request.path))
    ]

    sources.extend(
        ("query", normalize_detection_input(value))
        for value in request.query_params.values()
    )

    sources.extend(
        ("header", normalize_detection_input(f"{key}: {value}"))
        for key, value in request.headers.items()
    )

    if request.body:
        sources.append(
            ("body", normalize_detection_input(request.body))
        )

    return sources


def build_detection_target(request: HTTPRequest) -> str:
    return " ".join(
        value for _, value in get_detection_sources(request)
    )


def inspect_request(request: HTTPRequest) -> DetectionResult:
    findings = []

    for location, target in get_detection_sources(request):
        for category, rules in RULES.items():
            for pattern, severity in rules:
                if re.search(pattern, target, re.IGNORECASE):
                    findings.append(
                        DetectionFinding(
                            category=category,
                            rule=pattern,
                            severity=severity,
                            location=location,
                        )
                    )

    if not findings:
        return DetectionResult(
            detected=False,
            severity="low",
            action="ALLOW",
            reason="No configured detection rule matched",
        )

    primary = findings[0]
    highest_severity = max(
        findings,
        key=lambda finding: SEVERITY_RANK[finding.severity],
    ).severity

    return DetectionResult(
        detected=True,
        category=primary.category,
        rule=primary.rule,
        severity=highest_severity,
        action="BLOCK",
        reason=f"Matched {len(findings)} detection rule(s)",
        findings=findings,
    )
