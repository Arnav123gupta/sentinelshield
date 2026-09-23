from app.core.rate_limiter import RateLimiter
from app.core.ip_blocker import IPBlocker
from app.core.repeat_detector import RepeatDetector


class ProtectionManager:
    def __init__(
        self,
        max_requests: int = 5,
        rate_window: int = 60,
        max_repeats: int = 3,
        repeat_window: int = 60,
        block_seconds: int = 60,
    ):
        self.rate_limiter = RateLimiter(
            max_requests=max_requests,
            window_seconds=rate_window,
        )

        self.repeat_detector = RepeatDetector(
            max_repeats=max_repeats,
            window_seconds=repeat_window,
        )

        self.ip_blocker = IPBlocker(
            block_seconds=block_seconds,
        )

    def check_request(self, client_ip: str, request_key: str) -> str:
        if self.ip_blocker.is_blocked(client_ip):
            return "BLOCK"

        if not self.rate_limiter.check_request(client_ip):
            self.ip_blocker.block(client_ip)
            return "BLOCK"

        if self.repeat_detector.check(client_ip, request_key):
            self.ip_blocker.block(client_ip)
            return "BLOCK"

        return "ALLOW"
