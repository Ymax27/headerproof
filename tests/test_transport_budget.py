from __future__ import annotations

from headerproof.transport import HostRateLimiter, UrlBudget


def test_non_positive_rate_limit_does_not_sleep(monkeypatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("headerproof.transport.time.sleep", slept.append)

    for rate in (0, -3):
        limiter = HostRateLimiter(rate)
        limiter.wait("https://example.test/a")
        limiter.wait("https://example.test/b")

    assert slept == []


def test_same_host_is_paced_independently_of_other_hosts(monkeypatch) -> None:
    clock = {"now": 100.0}
    slept: list[float] = []

    def monotonic() -> float:
        return clock["now"]

    def sleep(delay: float) -> None:
        slept.append(delay)
        clock["now"] += delay

    monkeypatch.setattr("headerproof.transport.time.monotonic", monotonic)
    monkeypatch.setattr("headerproof.transport.time.sleep", sleep)
    limiter = HostRateLimiter(2)

    limiter.wait("https://Example.COM/a")
    limiter.wait("https://example.com/b")
    limiter.wait("https://other.test/c")
    limiter.wait("https://EXAMPLE.com/d")

    assert slept == [0.5, 0.5]


def test_url_budget_remaining_and_request_timeout_stay_non_negative(monkeypatch) -> None:
    clock = {"now": 50.0}
    monkeypatch.setattr("headerproof.transport.time.monotonic", lambda: clock["now"])
    budget = UrlBudget(1.0)

    assert budget.remaining() == 1.0
    assert budget.expired() is False
    assert budget.request_timeout(2.0) == 1.0
    assert budget.request_timeout(0.2) == 0.2

    clock["now"] = 50.96875
    assert budget.remaining() == 0.03125
    assert budget.request_timeout(1.0) == 0.05

    clock["now"] = 80.0
    assert budget.remaining() == 0.0
    assert budget.expired() is True
    assert budget.request_timeout(1.0) == 0.0
