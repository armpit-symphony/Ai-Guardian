from __future__ import annotations

import json
from typing import Callable
from urllib import request


def send_webhook(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url=url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=5):
        return


class AlertDispatcher:
    def __init__(self, webhook_urls: tuple[str, ...], sender: Callable[[str, dict], None] = send_webhook):
        self.webhook_urls = webhook_urls
        self.sender = sender

    def dispatch(self, payload: dict) -> int:
        sent = 0
        for webhook_url in self.webhook_urls:
            self.sender(webhook_url, payload)
            sent += 1
        return sent
