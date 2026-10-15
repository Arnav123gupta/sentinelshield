from app.models.request import HTTPRequest
from app.models.detection import DetectionResult
from app.core.protection_manager import ProtectionManager
from app.detectors.rule_detector import inspect_request
from app.logging.security_logger import log_detection


class RequestProtection:
    def __init__(self, manager: ProtectionManager | None = None):
        self.manager = manager or ProtectionManager()

    def check(self, request: HTTPRequest) -> str:
        detection_result = inspect_request(request)

        if detection_result.action == "BLOCK":
            log_detection(request, detection_result)
            return "BLOCK"

        request_key = f"{request.method}:{request.path}"

        decision = self.manager.check_request(
            client_ip=request.client_ip,
            request_key=request_key,
        )

        if decision == "BLOCK":
            protection_result = DetectionResult(
                detected=True,
                category="PROTECTION",
                rule="RATE_LIMIT_OR_REPEAT_REQUEST",
                severity="high",
                action="BLOCK",
                reason="Blocked by rate limiting or repeated-request protection",
            )
            log_detection(request, protection_result)

        return decision
