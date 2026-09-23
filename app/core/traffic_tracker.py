from collections import defaultdict, deque
from time import time


class TrafficTracker:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)

    def record_request(self, client_ip: str) -> int:
        now = time()
        timestamps = self.requests[client_ip]

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        timestamps.append(now)

        return len(timestamps)

    def get_request_count(self, client_ip: str) -> int:
        now = time()
        timestamps = self.requests[client_ip]

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        return len(timestamps)
