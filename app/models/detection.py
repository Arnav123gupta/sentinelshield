
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionFinding:
    category: str
    rule: str
    severity: str
    location: str = "unknown"


@dataclass
class DetectionResult:
    detected: bool
    category: Optional[str] = None
    rule: Optional[str] = None
    severity: str = "low"
    action: str = "ALLOW"
    reason: Optional[str] = None
    findings: list[DetectionFinding] = field(default_factory=list)
