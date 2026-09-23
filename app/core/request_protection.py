from app.models.request import HTTPRequest
from app.core.protection_manager import ProtectionManager


class RequestProtection:
    def __init__(self, manager: ProtectionManager | None = None):
        self.manager = manager or ProtectionManager()

    def check(self, request: HTTPRequest) -> str:
        request_key = f"{request.method}:{request.path}"

        return self.manager.check_request(
            client_ip=request.client_ip,
            request_key=request_key,
        )
