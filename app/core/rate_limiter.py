from app.core.traffic_tracker import TrafficTracker


class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.tracker = TrafficTracker(window_seconds=window_seconds)

    def check_request(self, client_ip: str) -> bool:
        request_count = self.tracker.record_request(client_ip)
        return request_count <= self.max_requests
