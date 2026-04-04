from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from urllib.parse import urlparse


SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("openai_api_key", r"sk-[A-Za-z0-9]{20,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("generic_bearer", r"bearer\s+[A-Za-z0-9._-]{20,}"),
)


def canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(data: object) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return f"aig_live_{secrets.token_urlsafe(24)}"


def constant_time_contains(needle: str, haystack: tuple[str, ...]) -> bool:
    return any(hmac.compare_digest(needle, item) for item in haystack)


def extract_domain(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.lower().split("@")[-1]
    return domain.split(":")[0] if domain else None


def find_secret_exposures(text: str) -> list[str]:
    findings: list[str] = []
    for code, pattern in SECRET_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(code)
    return findings
