import time
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def same_origin(base: str, target: str) -> bool:
    b = urlparse(base)
    t = urlparse(target)
    return b.netloc == t.netloc


class RateLimiter:
    def __init__(self, delay: float = 0.5):
        self._delay = delay
        self._last = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last = time.monotonic()
