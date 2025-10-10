from concurrent.futures import ThreadPoolExecutor

from borgmatic_api_app.rate_limit import RateLimiter


class DummyRequest:
    def __init__(self, token: str) -> None:
        self.headers = {"Authorization": f"Bearer {token}"}
        self.remote_addr = "127.0.0.1"


def test_rate_limiter_is_thread_safe():
    limiter = RateLimiter()
    request = DummyRequest("shared")

    def call_allow():
        return limiter.allow(request, max_calls=5, per_seconds=60)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda _: call_allow(), range(10)))

    assert results.count(True) == 5
    assert results.count(False) == 5
