"""SPF evaluation for DSTFA Phase 3.

Sync-only API: safe to invoke from ``asyncio.to_thread`` or an executor for
non-blocking FastAPI handlers.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from email.utils import getaddresses
from typing import Any, Iterator

import dns.exception
import dns.resolver
import spf

from config import settings

# Oldest hop is the last Received block in header document order (top = newest).
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


@contextmanager
def _pyspf_dns_resolver_from_settings(timeout: int) -> Iterator[None]:
    """Point pyspf (dnspython) at ``DNS_RESOLVER`` when it is an IPv4 literal."""
    ns = (settings.DNS_RESOLVER or "").strip()
    if not ns or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ns):
        yield
        return
    res = dns.resolver.Resolver(configure=True)
    res.nameservers = [ns]
    res.lifetime = timeout
    prev = dns.resolver.default_resolver
    dns.resolver.default_resolver = res
    try:
        yield
    finally:
        dns.resolver.default_resolver = prev


def _split_headers_body(raw: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep) :]
    return raw, b""


def _received_blocks_header_order(header_bytes: bytes) -> list[str]:
    """Received values in on-the-wire order (first item = newest / top of headers)."""
    text = header_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    blocks: list[str] = []
    current: list[str] | None = None
    for line in lines:
        if not line.strip():
            break
        if line[0] in (" ", "\t") and current is not None:
            current.append(line.strip())
        elif ":" in line:
            if current is not None:
                blocks.append(" ".join(current))
            name, _, value = line.partition(":")
            n = name.strip().lower()
            if n == "received":
                current = [value.strip()]
            else:
                current = None
        else:
            continue
    if current is not None:
        blocks.append(" ".join(current))
    return blocks


def _extract_ipv4_from_oldest_hop(raw_email: bytes) -> str:
    blocks = _received_blocks_header_order(_split_headers_body(raw_email)[0])
    if not blocks:
        return ""
    oldest = blocks[-1]
    m = _RE_IPV4.search(oldest.replace("\n", " "))
    return m.group(0) if m else ""


def _helo_from_oldest_hop(raw_email: bytes) -> str:
    blocks = _received_blocks_header_order(_split_headers_body(raw_email)[0])
    if not blocks:
        return "unknown"
    oldest = blocks[-1].replace("\n", " ")
    m = re.search(r"\bfrom\s+(\S+)", oldest, re.IGNORECASE)
    if not m:
        return "unknown"
    token = m.group(1).strip()
    if token.startswith("[") and token.endswith("]"):
        return "unknown"
    return token.lower()


def _mail_from_sender(parsed_summary: dict[str, Any]) -> str:
    """MAIL FROM for SPF: Return-Path address if present, else RFC5322 From address."""
    headers = (parsed_summary.get("headers") or {}).get("parsed") or []
    summary = parsed_summary.get("input_summary") or {}
    from_hdr = str(summary.get("from", "") or "")
    _, from_mail = (getaddresses([from_hdr])[0] if from_hdr else ("", ""))
    from_mail = from_mail.lower().strip() if from_mail else ""
    for h in headers:
        if str(h.get("name", "")).lower() != "return-path":
            continue
        val = str(h.get("value", "") or "")
        for _, addr in getaddresses([val]):
            if addr and "@" in addr:
                return addr.lower().strip()
        inner = val.strip()
        if inner.startswith("<") and inner.endswith(">"):
            inner = inner[1:-1].strip()
        if "@" in inner:
            return inner.lower().strip()
    return from_mail


def check_spf(raw_email: bytes, parsed_summary: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate SPF for the connecting IP vs MAIL FROM (Return-Path, else From) and HELO.

    Uses ``pyspf`` + dnspython. DNS timeouts map to ``temperror``.
    Returns a dict compatible with ``SPFResult`` (result, domain, ip, explanation).
    """
    ip = _extract_ipv4_from_oldest_hop(raw_email)
    sender = _mail_from_sender(parsed_summary)
    domain = sender.split("@", 1)[1] if "@" in sender else ""
    helo = _helo_from_oldest_hop(raw_email)

    if not ip:
        return {
            "result": "none",
            "domain": domain,
            "ip": "",
            "explanation": "No IPv4 address found in the oldest Received hop; SPF check skipped.",
        }

    if not sender or "@" not in sender:
        return {
            "result": "none",
            "domain": "",
            "ip": ip,
            "explanation": "No MAIL FROM / Return-Path / From address available; SPF check skipped.",
        }

    timeout = max(1, min(20, int(settings.SANDBOX_TIMEOUT_SECONDS)))
    try:
        with _pyspf_dns_resolver_from_settings(timeout):
            res, expl = spf.check2(
                ip,
                sender,
                helo,
                timeout=timeout,
                querytime=timeout,
            )
    except spf.TempError as e:
        return {
            "result": "temperror",
            "domain": domain,
            "ip": ip,
            "explanation": f"SPF temporary error (often DNS): {e}",
        }
    except spf.PermError as e:
        return {
            "result": "permerror",
            "domain": domain,
            "ip": ip,
            "explanation": f"SPF permanent error: {e}",
        }
    except dns.exception.Timeout as e:
        return {
            "result": "temperror",
            "domain": domain,
            "ip": ip,
            "explanation": f"SPF DNS timeout: {e}",
        }
    except Exception as e:  # DNS failures, etc.
        return {
            "result": "temperror",
            "domain": domain,
            "ip": ip,
            "explanation": f"SPF lookup failed (treated as temperror): {e}",
        }

    r = str(res).lower()
    if r not in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
        r = "none"
    base = expl or f"SPF result: {r}"
    if r == "pass":
        explanation = f"The IP {ip} is authorized to send mail for domain {domain} according to its SPF record."
    elif r == "fail":
        explanation = f"The IP {ip} is not authorized to send mail for domain {domain} according to its SPF record."
    elif r == "softfail":
        explanation = f"The IP {ip} is not clearly authorized for {domain} (SPF softfail)."
    else:
        explanation = base
    return {
        "result": r,
        "domain": domain,
        "ip": ip,
        "explanation": explanation,
    }
