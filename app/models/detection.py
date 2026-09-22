from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    detected: bool
    category: Optional[str] = None
    rule: Optional[str] = None
    severity: str = "low"
    action: str = "ALLOW"
    reason: Optional[str] = None
