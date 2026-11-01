"""ntfy HTTP publish with retries and backend failover. Tokens read at send time, never
logged; logs carry counts and backend labels only."""
from __future__ import annotations

import logging
import time as _time
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import quote

from .config import Backend
from .message import Message

log = logging.getLogger("cvc.notify")

# post(url, body, headers, timeout) -> HTTP status code; raise on transport error
HttpPost = Callable[[str, bytes, dict, float], int]


def urllib_post(url: str, body: bytes, headers: dict, timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


class NtfySender:
    def __init__(self, backends: list[Backend], post: HttpPost = urllib_post,
                 attempts: int = 2, backoff_s: float = 1.0,
                 sleep: Callable[[float], None] = _time.sleep, timeout: float = 10.0):
        self.backends, self.post, self.attempts = backends, post, max(1, attempts)
        self.backoff_s, self.sleep, self.timeout = backoff_s, sleep, timeout
        self.sent = self.failed = 0

    def send(self, topic: str, msg: Message) -> bool:
        """Try each backend in order (failover), `attempts` tries each. Never raises."""
        headers = {"Title": msg.title, "Priority": str(msg.priority),
                   "Content-Type": "text/plain; charset=utf-8"}
        if msg.click:
            headers["Click"] = msg.click
        if msg.tags:
            headers["Tags"] = msg.tags
        body = msg.body.encode("utf-8")
        for b in self.backends:
            url = f"{b.url.rstrip('/')}/{quote(topic, safe='')}"
            for attempt in range(self.attempts):
                h = dict(headers)
                tok = b.token()
                if tok:
                    h["Authorization"] = f"Bearer {tok}"
                try:
                    status = self.post(url, body, h, self.timeout)
                except Exception:                      # noqa: BLE001 - never propagate
                    status = 0
                finally:
                    tok = h = None                     # drop token refs promptly
                if 200 <= status < 300:
                    self.sent += 1
                    return True
                if status in (400, 401, 403, 404, 413):
                    break                              # not retryable on this backend
                if attempt + 1 < self.attempts:
                    self.sleep(self.backoff_s * (attempt + 1))
            log.warning("notify: backend %s unavailable, failing over", b.name)
        self.failed += 1
        return False
