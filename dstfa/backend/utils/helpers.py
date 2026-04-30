"""Miscellaneous utilities for DSTFA backend."""

from __future__ import annotations

import hashlib
import re
from typing import Any


def sha256_hex(text: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def truncate(s: str, max_len: int = 120, suffix: str = "…") -> str:
    """Truncate a string to at most max_len characters."""
    if not s or len(s) <= max_len:
        return s
    return s[: max_len - len(suffix)] + suffix


def extract_ipv4_addresses(text: str) -> list[str]:
    """Return all unique IPv4 addresses found in text, preserving order."""
    pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    seen: set[str] = set()
    out: list[str] = []
    for m in pattern.finditer(text):
        ip = m.group(0)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def safe_get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts: safe_get(d, 'a', 'b', 'c')."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is default:
            return default
    return cur


def flatten_list(value: Any) -> list[str]:
    """Coerce a list-or-single-string field to a flat list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(x) for x in value if x is not None]
    return [str(value)]
