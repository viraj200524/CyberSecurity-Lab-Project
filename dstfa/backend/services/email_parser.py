"""Parse .eml / .msg into header structures for DSTFA (Phase 1)."""

from __future__ import annotations

import email.policy
import logging
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

try:
    from msg_parser import MsOxMessage
except ImportError:  # pragma: no cover
    MsOxMessage = None  # type: ignore[misc, assignment]


RECEIVED_RE = re.compile(
    r"from\s+(?P<frm>\S+)\s+by\s+(?P<by>\S+).*?;\s*(?P<ts>.+?)(?:\s*$)",
    re.IGNORECASE | re.DOTALL,
)


class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def get_text(self) -> str:
        return "".join(self._chunks).strip()


def _strip_html(html: str) -> str:
    p = _HTMLStripper()
    p.feed(html)
    p.close()
    return p.get_text() or ""


def _looks_like_eml(raw: bytes) -> bool:
    """Detect RFC822 / mbox; minimal fixtures may omit Content-Type if they have common headers."""
    if raw.lstrip().startswith(b"From "):
        return True
    head = raw[:8192].lower()
    if b"content-type:" in head or b"message-id:" in head or b"received:" in head:
        return True
    try:
        preview = raw[:4096].decode("utf-8", errors="replace")
    except Exception:
        return False
    lines = [ln.strip().lower() for ln in preview.splitlines()[:16] if ln.strip()]
    if len(lines) < 2:
        return False
    headerish = (
        "from:",
        "to:",
        "subject:",
        "date:",
        "reply-to:",
        "cc:",
        "bcc:",
        "mime-version:",
    )
    hits = sum(1 for ln in lines[:10] if any(ln.startswith(p) for p in headerish))
    return hits >= 2


def _split_headers_body(raw: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep) :]
    return raw, b""


def _parse_raw_header_pairs(header_bytes: bytes) -> list[tuple[str, str]]:
    """RFC 5322-style header lines with folding; preserves duplicate header names."""
    text = header_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    pairs: list[tuple[str, str]] = []
    current_name: str | None = None
    current_parts: list[str] = []

    def flush() -> None:
        nonlocal current_name, current_parts
        if current_name is not None and current_parts:
            pairs.append((current_name, " ".join(current_parts).strip()))
        current_name = None
        current_parts = []

    for line in lines:
        if not line.strip():
            break
        if line[0] in (" ", "\t") and current_name is not None:
            current_parts.append(line.strip())
        elif ":" in line:
            flush()
            name, _, value = line.partition(":")
            current_name = name.strip()
            current_parts = [value.strip()]
        else:
            continue
    flush()
    return pairs


def _domain_from_addr(addr: str) -> str:
    parts = getaddresses([addr])
    if not parts:
        return ""
    _, email_addr = parts[0]
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip()
    return ""


def _parse_received_hops(msg: Message) -> list[dict[str, Any]]:
    received_values = msg.get_all("Received", []) or []
    hops: list[dict[str, str | int]] = []
    for block in received_values:
        if not isinstance(block, str):
            continue
        m = RECEIVED_RE.search(block.replace("\n", " ").replace("\r", " "))
        if not m:
            hops.append({"from": "", "by": "", "timestamp": block.strip(), "delay_seconds": 0})
            continue
        hops.append(
            {
                "from": m.group("frm").strip(),
                "by": m.group("by").strip(),
                "timestamp": m.group("ts").strip(),
                "delay_seconds": 0,
            }
        )
    # Document order: first Received = newest hop → oldest-first = reverse
    hops.reverse()
    for i in range(1, len(hops)):
        t_prev = _safe_parse_dt(str(hops[i - 1]["timestamp"]))
        t_cur = _safe_parse_dt(str(hops[i]["timestamp"]))
        if t_prev and t_cur:
            hops[i]["delay_seconds"] = int(max(0, (t_cur - t_prev).total_seconds()))
    return hops


def _safe_parse_dt(s: str) -> datetime | None:
    try:
        dt = parsedate_to_datetime(s.strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError, OverflowError):
        return None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _header_suspicious(name: str, value: str, msg: Message) -> tuple[bool, str]:
    n = name.lower()
    explanation = ""

    if n == "reply-to":
        from_hdr = msg.get("From", "") or ""
        rt_domains: set[str] = set()
        for _, addr in getaddresses([value]):
            d = _domain_from_addr(addr)
            if d:
                rt_domains.add(d)
        from_domains: set[str] = set()
        for _, addr in getaddresses([from_hdr]):
            d = _domain_from_addr(addr)
            if d:
                from_domains.add(d)
        if rt_domains and from_domains and rt_domains.isdisjoint(from_domains):
            return True, "Reply-To domain differs from From domain (possible spoofing)."

    if n == "date":
        dt = _safe_parse_dt(value)
        if dt:
            now = _now_utc()
            if dt > now + timedelta(minutes=5):
                return True, "Date is in the future relative to server time."
            if dt < now - timedelta(days=7):
                return True, "Date is more than 7 days in the past."

    if n in ("x-mailer", "user-agent"):
        from_hdr = (msg.get("From", "") or "").lower()
        v = value.lower()
        claimed_outlook = "microsoft" in from_hdr or "outlook" in from_hdr
        claimed_thunderbird = "thunderbird" in from_hdr or "mozilla" in from_hdr
        if claimed_outlook and ("thunderbird" in v or "gecko" in v):
            return True, "X-Mailer/User-Agent does not match typical Outlook client."
        if claimed_thunderbird and ("microsoft" in v or "outlook" in v):
            return True, "X-Mailer/User-Agent does not match typical Thunderbird client."

    return False, explanation


def _extract_body(msg: Message) -> tuple[str, str]:
    plain = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not plain:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif ctype == "text/html" and not html:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if ctype == "text/html":
                html = text
            else:
                plain = text
    body = plain or (_strip_html(html) if html else "")
    return body, html


def _extract_attachments(msg: Message) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not msg.is_multipart():
        return out
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = str(part.get("Content-Disposition", "") or "").lower()
        if "attachment" not in disp and part.get_filename() is None:
            continue
        fn = part.get_filename() or "unnamed"
        raw = part.get_payload(decode=True)
        if not isinstance(raw, bytes):
            raw = b""
        out.append(
            {
                "filename": fn,
                "content_type": part.get_content_type(),
                "size_bytes": len(raw),
                "raw_bytes": raw,
            }
        )
    return out


def _parse_eml(raw: bytes) -> dict[str, Any]:
    mp_plain = ""
    mp_extra_atts: list[dict[str, Any]] = []
    try:
        import mailparser

        # mailparser warns on application/pgp-signature parts; we still parse via stdlib ``email``.
        _mplog = logging.getLogger("mailparser.mailparser")
        _prev_level = _mplog.level
        _mplog.setLevel(logging.ERROR)
        try:
            mp = mailparser.parse_from_bytes(raw)
        finally:
            _mplog.setLevel(_prev_level)
        if mp.text_plain:
            mp_plain = str(mp.text_plain).strip()
        for a in mp.attachments or []:
            if not isinstance(a, dict):
                continue
            raw_b = a.get("binary")
            if not isinstance(raw_b, bytes):
                raw_b = b""
            mp_extra_atts.append(
                {
                    "filename": str(a.get("filename") or "unnamed"),
                    "content_type": str(a.get("mail_content_type") or "application/octet-stream"),
                    "size_bytes": len(raw_b),
                    "raw_bytes": raw_b,
                }
            )
    except Exception:
        pass

    msg = message_from_bytes(raw, policy=email.policy.default)
    header_bytes, _ = _split_headers_body(raw)
    pairs = _parse_raw_header_pairs(header_bytes)

    parsed: list[dict[str, Any]] = []
    for name, value in pairs:
        susp, expl = _header_suspicious(name, value, msg)
        parsed.append({"name": name, "value": value, "suspicious": susp, "explanation": expl})

    received_chain = _parse_received_hops(msg)

    to_addrs = [addr for _, addr in getaddresses([msg.get("To", "")])]
    summary = {
        "subject": msg.get("Subject", "") or "",
        "from": msg.get("From", "") or "",
        "to": to_addrs if to_addrs else [],
        "date": msg.get("Date", "") or "",
        "message_id": msg.get("Message-ID", "") or "",
        "mime_parts": len(list(msg.walk())) if msg.is_multipart() else 1,
    }

    body, _html = _extract_body(msg)
    if not body and mp_plain:
        body = mp_plain
    attachments = _extract_attachments(msg)
    if not attachments and mp_extra_atts:
        attachments = list(mp_extra_atts)

    raw_header_text = header_bytes.decode("utf-8", errors="replace")

    return {
        "detected_type": "eml",
        "headers": {
            "raw": raw_header_text,
            "parsed": parsed,
            "received_chain": received_chain,
        },
        "input_summary": summary,
        "body_preview": body[:2000],
        "attachments_meta": [
            {"filename": a["filename"], "content_type": a["content_type"], "size_bytes": a["size_bytes"]}
            for a in attachments
        ],
        "_attachments_raw": attachments,
    }


def _parse_msg(raw: bytes) -> dict[str, Any]:
    if MsOxMessage is None:
        raise RuntimeError("msg-parser is not installed")

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as f:
            f.write(raw)
            tmp_path = f.name
        m = MsOxMessage(tmp_path)
        data = m.get_data()  # type: ignore[union-attr]
    except Exception as e:  # pragma: no cover - OLE errors vary
        raise ValueError(f"Could not parse Outlook .msg file: {e}") from e
    finally:
        if tmp_path and os.path.isfile(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if not isinstance(data, dict):
        raise ValueError("Unexpected .msg parser output")

    headers_lines: list[str] = []
    for key in ("from", "to", "cc", "subject", "date", "message-id", "reply-to"):
        val = data.get(key) or data.get(key.replace("-", "_"))
        if val:
            hname = key if "-" in key else key.replace("_", "-")
            if isinstance(val, list):
                val = ", ".join(str(x) for x in val)
            headers_lines.append(f"{hname.title() if hname != 'message-id' else 'Message-ID'}: {val}")
    raw_header_text = "\r\n".join(headers_lines) + "\r\n\r\n"

    pairs = _parse_raw_header_pairs(raw_header_text.encode())
    msg_stub = message_from_bytes(
        (raw_header_text + "(body omitted)").encode(),
        policy=email.policy.default,
    )
    parsed: list[dict[str, Any]] = []
    for name, value in pairs:
        susp, expl = _header_suspicious(name, value, msg_stub)
        parsed.append({"name": name, "value": value, "suspicious": susp, "explanation": expl})

    to_field = data.get("to") or ""
    if isinstance(to_field, list):
        to_list = [str(x) for x in to_field]
    else:
        to_list = [str(to_field)] if to_field else []

    summary = {
        "subject": str(data.get("subject") or ""),
        "from": str(data.get("sender") or data.get("from") or ""),
        "to": to_list,
        "date": str(data.get("date") or ""),
        "message_id": str(data.get("message_id") or data.get("message-id") or ""),
        "mime_parts": 1,
    }

    body = str(data.get("body") or "")
    atts: list[dict[str, Any]] = []
    for att in data.get("attachments") or []:
        if not isinstance(att, dict):
            continue
        fn = str(att.get("filename") or att.get("name") or "unnamed")
        b = att.get("data") or att.get("binary") or b""
        if not isinstance(b, bytes):
            b = str(b).encode("utf-8", errors="replace")
        atts.append(
            {
                "filename": fn,
                "content_type": str(att.get("content_type") or "application/octet-stream"),
                "size_bytes": len(b),
                "raw_bytes": b,
            }
        )

    return {
        "detected_type": "msg",
        "headers": {"raw": raw_header_text.strip(), "parsed": parsed, "received_chain": []},
        "input_summary": summary,
        "body_preview": body[:2000],
        "attachments_meta": [
            {"filename": a["filename"], "content_type": a["content_type"], "size_bytes": a["size_bytes"]}
            for a in atts
        ],
        "_attachments_raw": atts,
    }


def parse_email(raw_bytes: bytes) -> dict[str, Any]:
    """
    Parse raw email bytes (.eml or .msg).

    Returns a dict with keys: detected_type, headers (raw, parsed, received_chain),
    input_summary, body_preview, attachments_meta, _attachments_raw (internal).
    """
    if not raw_bytes:
        return {
            "detected_type": "unknown",
            "headers": {"raw": "", "parsed": [], "received_chain": []},
            "input_summary": {
                "subject": "",
                "from": "",
                "to": [],
                "date": "",
                "message_id": "",
                "mime_parts": 0,
            },
            "body_preview": "",
            "attachments_meta": [],
            "_attachments_raw": [],
        }

    if _looks_like_eml(raw_bytes):
        return _parse_eml(raw_bytes)

    if MsOxMessage is None:
        raise ValueError("Binary does not look like .eml and msg-parser is unavailable.")

    return _parse_msg(raw_bytes)


def build_minimal_eml_from_headers(raw_headers: str) -> bytes:
    """Wrap pasted headers in a minimal RFC822 message for parsing."""
    text = raw_headers.strip()
    if not text.endswith("\n"):
        text += "\n"
    return (text + "\nMinimal body for DSTFA paste upload.\n").encode("utf-8")
