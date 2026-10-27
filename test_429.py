#!/usr/bin/env python3
"""Offline tests for 429 handling in tor_fetch.py.

Run with:  python test_429.py
No Tor or network access is needed.
"""

from __future__ import annotations

import email.utils
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tor_fetch import (
    fetch,
    is_rate_limited,
    retry_after_seconds,
    rotate_via_daemon,
    verify_tor,
)


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        headers: dict | None = None,
        text: str = "",
        json_data: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Returns canned responses and records calls."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def get(self, url: str, timeout: float | None = None, **kwargs) -> FakeResponse:
        self.calls += 1
        return self._responses.pop(0)


class DetectionTests(unittest.TestCase):
    def test_429_is_rate_limited(self) -> None:
        self.assertTrue(is_rate_limited(FakeResponse(429)))

    def test_403_with_zero_remaining_is_rate_limited(self) -> None:
        response = FakeResponse(403, {"X-RateLimit-Remaining": "0"})
        self.assertTrue(is_rate_limited(response))

    def test_403_with_retry_after_is_rate_limited(self) -> None:
        self.assertTrue(is_rate_limited(FakeResponse(403, {"Retry-After": "30"})))

    def test_plain_403_is_not_rate_limited(self) -> None:
        self.assertFalse(is_rate_limited(FakeResponse(403)))

    def test_200_is_not_rate_limited(self) -> None:
        self.assertFalse(is_rate_limited(FakeResponse(200)))


class RetryAfterTests(unittest.TestCase):
    def test_seconds(self) -> None:
        self.assertEqual(retry_after_seconds(FakeResponse(429, {"Retry-After": "7"})), 7.0)

    def test_http_date(self) -> None:
        when = datetime.now(timezone.utc) + timedelta(seconds=30)
        header = email.utils.format_datetime(when, usegmt=True)
        value = retry_after_seconds(FakeResponse(429, {"Retry-After": header}))
        self.assertIsNotNone(value)
        self.assertGreaterEqual(value, 25.0)
        self.assertLessEqual(value, 31.0)

    def test_missing(self) -> None:
        self.assertIsNone(retry_after_seconds(FakeResponse(429)))

    def test_garbage(self) -> None:
        self.assertIsNone(retry_after_seconds(FakeResponse(429, {"Retry-After": "soon"})))


class FetchTests(unittest.TestCase):
    def test_rotates_until_success(self) -> None:
        session = FakeSession([FakeResponse(429), FakeResponse(429), FakeResponse(200)])
        rotations: list[int] = []
        response = fetch(
            "https://example.test",
            session=session,
            rotate=lambda: rotations.append(1),
            sleep=lambda _: None,
            verbose=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(rotations), 2)
        self.assertEqual(session.calls, 3)

    def test_gives_up_after_max_attempts(self) -> None:
        session = FakeSession([FakeResponse(429) for _ in range(3)])
        rotations: list[int] = []
        response = fetch(
            "https://example.test",
            session=session,
            rotate=lambda: rotations.append(1),
            max_attempts=3,
            sleep=lambda _: None,
            verbose=False,
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(len(rotations), 2)  # no rotation after the last attempt
        self.assertEqual(session.calls, 3)

    def test_honours_retry_after(self) -> None:
        session = FakeSession([FakeResponse(429, {"Retry-After": "5"}), FakeResponse(200)])
        sleeps: list[float] = []
        fetch(
            "https://example.test",
            session=session,
            rotate=lambda: None,
            sleep=sleeps.append,
            verbose=False,
        )
        self.assertEqual(sleeps, [5.0])

    def test_caps_retry_after(self) -> None:
        session = FakeSession([FakeResponse(429, {"Retry-After": "9999"}), FakeResponse(200)])
        sleeps: list[float] = []
        fetch(
            "https://example.test",
            session=session,
            rotate=lambda: None,
            sleep=sleeps.append,
            max_retry_after=60.0,
            verbose=False,
        )
        self.assertEqual(sleeps, [60.0])

    def test_no_rotation_on_200(self) -> None:
        session = FakeSession([FakeResponse(200)])
        rotations: list[int] = []
        fetch(
            "https://example.test",
            session=session,
            rotate=lambda: rotations.append(1),
            verbose=False,
        )
        self.assertEqual(rotations, [])
        self.assertEqual(session.calls, 1)


class DaemonRotationTests(unittest.TestCase):
    def test_returns_true_when_done_file_appears(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trigger = Path(tmp) / "rotate.now"
            done = Path(tmp) / "rotate.done"
            calls = {"n": 0}

            def fake_sleep(_: float) -> None:
                calls["n"] += 1
                if calls["n"] == 2:
                    done.write_text("ok", encoding="utf-8")

            self.assertTrue(
                rotate_via_daemon(
                    trigger, done_file=done, wait=5.0, poll=0.0, sleep=fake_sleep
                )
            )
            self.assertTrue(trigger.exists())

    def test_returns_false_on_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trigger = Path(tmp) / "rotate.now"
            done = Path(tmp) / "rotate.done"

            self.assertFalse(
                rotate_via_daemon(
                    trigger,
                    done_file=done,
                    wait=0.05,
                    poll=0.0,
                    sleep=lambda _: time.sleep(0.01),
                )
            )


class VerifyTests(unittest.TestCase):
    def test_accepts_tor_exit(self) -> None:
        session = FakeSession(
            [FakeResponse(200, json_data={"IsTor": True, "IP": "1.2.3.4"})]
        )
        self.assertEqual(verify_tor(session), "1.2.3.4")

    def test_rejects_non_tor(self) -> None:
        session = FakeSession(
            [FakeResponse(200, json_data={"IsTor": False, "IP": "5.6.7.8"})]
        )
        with self.assertRaises(RuntimeError):
            verify_tor(session)

    def test_fetch_can_require_tor(self) -> None:
        session = FakeSession(
            [
                FakeResponse(200, json_data={"IsTor": True, "IP": "1.2.3.4"}),
                FakeResponse(200, text="ok"),
            ]
        )
        response = fetch(
            "https://example.test",
            session=session,
            require_tor=True,
            verbose=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session.calls, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
