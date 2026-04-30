"""DKIM verification and ARC chain inspection (Phase 3)."""

from __future__ import annotations

import binascii
import re
from typing import Callable

import dns.exception
import dns.resolver
import dkim
from dkim.crypto import UnparsableKeyError, parse_public_key
from dkim.util import InvalidTagValueList, parse_tag_value

from config import settings


def make_dkim_dnsfunc(timeout: float = 5.0) -> Callable[[str], list[str]]:
    """
    TXT lookup compatible with dkimpy (fqdn str -> list of TXT record strings).
    Uses ``DNS_RESOLVER`` from settings when it looks like an IPv4 address.
    """

    def dnsfunc(name: str) -> list[str]:
        res = dns.resolver.Resolver(configure=True)
        ns = (settings.DNS_RESOLVER or "").strip()
        if ns and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ns):
            res.nameservers = [ns]
        res.lifetime = timeout
        try:
            ans = res.resolve(name, "TXT", lifetime=timeout)
        except dns.exception.Timeout:
            raise dkim.DnsTimeoutError(f"timeout resolving {name!r}") from None
        out: list[str] = []
        for rr in ans:
            for s in rr.strings:
                if isinstance(s, (bytes, bytearray)):
                    out.append(bytes(s).decode("utf-8", errors="replace"))
                else:
                    out.append(str(s))
        return out

    return dnsfunc


def _split_headers_body(raw: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep) :]
    return raw, b""


def _parse_first_dkim_signature_fields(raw_email: bytes) -> dict[str, str]:
    header_bytes = _split_headers_body(raw_email)[0]
    text = header_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    value_parts: list[str] = []
    collecting = False
    for line in lines:
        if line.lower().startswith("dkim-signature:"):
            collecting = True
            value_parts.append(line.split(":", 1)[1].strip())
            continue
        if collecting:
            if not line.strip():
                break
            if line[0] in (" ", "\t"):
                value_parts.append(line.strip())
            else:
                break
    if not value_parts:
        return {}
    blob = " ".join(value_parts).encode("utf-8", errors="replace")
    try:
        tags = parse_tag_value(blob)
    except (InvalidTagValueList, TypeError, ValueError):
        return {}
    out: dict[str, str] = {}
    for k in (b"d", b"s", b"a", b"bh", b"b", b"c", b"h"):
        if k in tags:
            out[k.decode()] = tags[k].decode("utf-8", errors="replace")
    return out


def _rsa_key_bits_from_txt_chunks(txt_chunks: list[str]) -> int:
    joined = "".join(txt_chunks).replace(" ", "").replace("\t", "")
    if not joined:
        return 0
    try:
        tags = parse_tag_value(joined.encode("ascii", errors="ignore"))
    except (InvalidTagValueList, TypeError, ValueError):
        return 0
    p = tags.get(b"p")
    if not p:
        return 0
    try:
        der = binascii.a2b_base64(p.replace(b"\n", b"").replace(b" ", b""))
    except binascii.Error:
        return 0
    if not der:
        return 0
    try:
        pk = parse_public_key(der)
        mod = pk.get("modulus")
        if isinstance(mod, int):
            return mod.bit_length()
    except (UnparsableKeyError, KeyError, TypeError, ValueError):
        return 0
    return 0


def verify_dkim(raw_email: bytes) -> dict[str, object]:
    """
    Verify the first (topmost) DKIM signature using dkimpy.

    Returns a dict compatible with ``DKIMResult``.
    """
    fields = _parse_first_dkim_signature_fields(raw_email)
    if not fields:
        return {
            "result": "none",
            "domain": "",
            "selector": "",
            "algorithm": "",
            "body_hash": "",
            "signature_valid": False,
            "key_size_bits": 0,
            "explanation": "No DKIM-Signature header found.",
        }

    domain = fields.get("d", "")
    selector = fields.get("s", "")
    algorithm = fields.get("a", "")
    body_hash = fields.get("bh", "")
    canon = fields.get("c", "")
    signed_headers = fields.get("h", "")
    dnsfunc = make_dkim_dnsfunc(timeout=5.0)
    fqdn = f"{selector}._domainkey.{domain}".strip(".")

    key_bits = 0
    try:
        txts = dnsfunc(fqdn)
        key_bits = _rsa_key_bits_from_txt_chunks(txts)
    except Exception:
        pass

    try:
        ok = bool(dkim.verify(raw_email, dnsfunc=dnsfunc, minkey=512, timeout=5))
    except dkim.DnsTimeoutError as e:
        return {
            "result": "temperror",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "body_hash": body_hash,
            "signature_valid": False,
            "key_size_bits": key_bits,
            "explanation": f"DKIM DNS timeout: {e}",
        }
    except Exception as e:
        return {
            "result": "permerror",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "body_hash": body_hash,
            "signature_valid": False,
            "key_size_bits": key_bits,
            "explanation": f"DKIM verification error: {e}",
        }

    res = "pass" if ok else "fail"
    hdr_note = ""
    if canon or signed_headers:
        hdr_note = f" c={canon or '?'}" + (f", h={signed_headers}" if signed_headers else "")
    b_tag = fields.get("b", "")
    b_note = ""
    if b_tag:
        b_clean = b_tag.replace("\n", "").replace(" ", "")
        b_note = f" b=({len(b_clean)} base64 chars)"
    expl = (
        "Signature verified successfully."
        if ok
        else "Signature did not verify (body, DNS key, or crypto mismatch)."
    )
    expl = f"DKIM-Signature: d={domain}, s={selector}, a={algorithm or '?'}, bh={body_hash or '?'}{b_note}. " + expl
    if hdr_note:
        expl += f" ({hdr_note.strip()})"
    algo_l = (algorithm or "").lower()
    warns: list[str] = []
    if "rsa-sha1" in algo_l or algo_l == "rsa-sha1":
        warns.append("Algorithm rsa-sha1 is deprecated; prefer rsa-sha256.")
    if key_bits and key_bits < 1024:
        warns.append(f"DKIM key is short ({key_bits} bits); use at least 1024–2048 bits.")
    elif key_bits and 1024 <= key_bits < 2048:
        warns.append(f"Key size {key_bits} bits is acceptable but 2048+ is recommended.")
    if warns:
        expl = expl + " " + " ".join(warns)
    return {
        "result": res,
        "domain": domain,
        "selector": selector,
        "algorithm": algorithm,
        "body_hash": body_hash,
        "signature_valid": ok,
        "key_size_bits": key_bits,
        "explanation": expl,
    }


def verify_arc(raw_email: bytes) -> dict[str, object]:
    """
    ARC chain using dkimpy ``arc_verify`` when possible, with header heuristics.

    Returns a dict compatible with ``ARCResult``.
    """
    header_bytes = _split_headers_body(raw_email)[0]
    htext = header_bytes.decode("utf-8", errors="replace")
    if "ARC-Seal:" not in htext and "arc-seal:" not in htext.lower():
        return {
            "present": False,
            "chain_valid": False,
            "instance_count": 0,
            "explanation": "No ARC-Seal headers present.",
        }

    dnsfunc = make_dkim_dnsfunc(timeout=5.0)
    try:
        cv, result_data, reason = dkim.arc_verify(raw_email, dnsfunc=dnsfunc, minkey=512, timeout=5)
    except Exception as e:
        return _arc_fallback_from_headers(htext, f"ARC verify raised: {e}")

    inst = 0
    if isinstance(result_data, list) and result_data:
        for row in result_data:
            if not isinstance(row, dict):
                continue
            for key in ("instance", "i", "Instance"):
                if key in row:
                    try:
                        inst = max(inst, int(row[key]))
                    except (TypeError, ValueError):
                        pass
                    break

    seals_in_headers = len(re.findall(r"(?im)^arc-seal:\s*", htext))
    present = seals_in_headers > 0 or inst > 0 or bool(result_data)

    cv_b = cv if isinstance(cv, (bytes, bytearray)) else str(cv).encode("utf-8", errors="replace")
    if cv_b == dkim.CV_Pass:
        chain_valid = True
    elif cv_b == dkim.CV_Fail:
        chain_valid = False
    elif cv_b == dkim.CV_None:
        chain_valid = False
    else:
        chain_valid = cv_b.lower() == b"pass"

    if not present:
        return _arc_fallback_from_headers(htext, str(reason or "No ARC instances parsed."))

    if inst == 0 and seals_in_headers:
        fb = _arc_fallback_from_headers(htext, str(reason or ""))
        inst = int(fb["instance_count"]) or seals_in_headers

    expl = str(reason or "").strip()
    if not expl:
        expl = "ARC chain valid (cryptographic verification passed)." if chain_valid else "ARC chain invalid or incomplete."
    return {
        "present": True,
        "chain_valid": chain_valid,
        "instance_count": inst or len(result_data) or seals_in_headers,
        "explanation": expl,
    }


def _arc_fallback_from_headers(htext: str, prefix: str) -> dict[str, object]:
    seals = re.findall(r"(?im)^arc-seal:\s*(.+)$", htext)
    i_vals: list[int] = []
    for block in seals:
        m = re.search(r"\bi=(\d+)", block, re.IGNORECASE)
        if m:
            i_vals.append(int(m.group(1)))
    inst = max(i_vals) if i_vals else len(seals)
    present = bool(seals)
    cvs = re.findall(r"\bcv=(pass|fail|none)\b", htext, re.IGNORECASE)
    chain_guess = bool(seals) and seals and all(v.lower() == "pass" for v in cvs) if cvs else False
    return {
        "present": present,
        "chain_valid": chain_guess,
        "instance_count": inst,
        "explanation": f"{prefix} Header-level ARC estimate: {len(seals)} seal(s).",
    }
