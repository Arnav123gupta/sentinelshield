from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    client_ip: str = "127.0.0.1"
