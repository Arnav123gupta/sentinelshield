from collections import defaultdict, deque
from time import time


class RepeatDetector:
    def __init__(self, max_repeats: int = 3, window_seconds: int = 60):
        self.max_repeats = max_repeats
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)

    def check(self, client_ip: str, request_key: str) -> bool:
        now = time()
        key = (client_ip, request_key)
        timestamps = self.requests[key]

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        timestamps.append(now)

        return len(timestamps) > self.max_repeats
