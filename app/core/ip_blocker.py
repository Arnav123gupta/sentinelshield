from time import time


class IPBlocker:
    def __init__(self, block_seconds: int = 60):
        self.block_seconds = block_seconds
        self.blocked_ips = {}

    def block(self, client_ip: str) -> None:
        self.blocked_ips[client_ip] = time() + self.block_seconds

    def is_blocked(self, client_ip: str) -> bool:
        expires_at = self.blocked_ips.get(client_ip)

        if expires_at is None:
            return False

        if time() >= expires_at:
            del self.blocked_ips[client_ip]
            return False

        return True
