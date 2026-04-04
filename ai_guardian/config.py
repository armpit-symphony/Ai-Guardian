from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    service_name: str
    bootstrap_api_keys: tuple[str, ...]
    database_path: str
    blocked_domains: tuple[str, ...]
    default_allowed_domains: tuple[str, ...]
    suspicious_phrases: tuple[str, ...]
    webhook_urls: tuple[str, ...]
    rate_limit_per_minute: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    bootstrap_api_keys = tuple(_split_csv(os.getenv("AI_GUARDIAN_BOOTSTRAP_KEYS", "dev-guardian-key")))
    blocked_domains = tuple(
        _split_csv(
            os.getenv(
                "AI_GUARDIAN_BLOCKED_DOMAINS",
                "pastebin.com,mega.nz,transfer.sh,temp.sh,file.io",
            )
        )
    )
    allowed_domains = tuple(
        _split_csv(
            os.getenv(
                "AI_GUARDIAN_DEFAULT_ALLOWED_DOMAINS",
                "github.com,api.openai.com,yourdomain.com",
            )
        )
    )
    suspicious_phrases = tuple(
        _split_csv(
            os.getenv(
                "AI_GUARDIAN_SUSPICIOUS_PHRASES",
                "ignore previous instructions,bypass policy,disable guard,export secrets,"
                "send credentials,exfiltrate,download and execute,rm -rf,drop table",
            )
        )
    )
    webhook_urls = tuple(_split_csv(os.getenv("AI_GUARDIAN_WEBHOOK_URLS", "")))
    return Settings(
        service_name=os.getenv("AI_GUARDIAN_SERVICE_NAME", "AI Guardian"),
        bootstrap_api_keys=bootstrap_api_keys,
        database_path=os.getenv("AI_GUARDIAN_DB_PATH", "ai_guardian.db"),
        blocked_domains=blocked_domains,
        default_allowed_domains=allowed_domains,
        suspicious_phrases=suspicious_phrases,
        webhook_urls=webhook_urls,
        rate_limit_per_minute=int(os.getenv("AI_GUARDIAN_RATE_LIMIT_PER_MINUTE", "120")),
    )
