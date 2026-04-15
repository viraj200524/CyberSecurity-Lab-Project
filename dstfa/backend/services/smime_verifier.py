"""S/MIME and PKCS#7 signed-data detection (Phase 4)."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import EmailPolicy
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
    load_pem_pkcs7_certificates,
)

_PKCS7_CT = re.compile(
    rb"application/(?:pkcs7|x-pkcs7)-(?:mime|signature)",
    re.IGNORECASE,
)


def _smime_result(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "present": False,
        "valid": False,
        "subject_cn": "",
        "issuer_cn": "",
        "valid_from": "",
        "valid_to": "",
        "serial_number": "",
        "algorithm": "",
        "chain": [],
        "explanation": "",
    }
    base.update(overrides)
    return base


def _cn(name: x509.Name | None) -> str:
    if name is None:
        return ""
    try:
        attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return ""


def _cert_type(i: int, n: int) -> str:
    if n <= 1:
        return "end-entity"
    if i == n - 1:
        return "root"
    if i == 0:
        return "end-entity"
    return "intermediate"


def _ordered_chain_valid(candidate: list[x509.Certificate]) -> bool:
    """True if each cert is directly issued by the next (EE → … → root)."""
    if not candidate:
        return False
    for i in range(len(candidate) - 1):
        try:
            candidate[i].verify_directly_issued_by(candidate[i + 1])
        except Exception:
            return False
    root = candidate[-1]
    if root.issuer == root.subject:
        try:
            root.verify_directly_issued_by(root)
        except Exception:
            return False
    return True


def _order_cert_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    if len(certs) <= 1:
        return certs
    for candidate in (certs, list(reversed(certs))):
        if _ordered_chain_valid(candidate):
            return candidate
    return certs


def _now_valid(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc)
    try:
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_before <= now.replace(tzinfo=None) <= cert.not_valid_after


def _der_from_payload(raw: bytes | None) -> bytes | None:
    """Return best-effort DER from PEM or base64-wrapped PKCS#7."""
    if not raw:
        return None
    s = raw.strip()
    if s.startswith(b"-----BEGIN"):
        lines = [ln for ln in s.splitlines() if ln and not ln.startswith(b"-----")]
        try:
            return base64.b64decode(b"".join(lines), validate=False)
        except binascii.Error:
            return None
    try:
        return base64.b64decode(s, validate=False)
    except binascii.Error:
        return s


def _extract_pkcs7_candidates(msg: Any, raw_email: bytes) -> list[bytes]:
    found: list[bytes] = []
    if msg is None:
        return found
    if msg.get_content_type() == "multipart/signed":
        proto = (msg.get_param("protocol") or "").lower()
        if "pkcs7" in proto or "x-pkcs7" in proto:
            pl = msg.get_payload()
            if isinstance(pl, list) and len(pl) >= 2:
                for p in pl[1:]:
                    ct = (p.get_content_type() or "").lower()
                    if "pkcs7" in ct or "octet-stream" in ct:
                        raw = p.get_payload(decode=True)
                        if isinstance(raw, str):
                            raw = raw.encode("utf-8", "replace")
                        if raw:
                            der = _der_from_payload(raw)
                            if der:
                                found.append(der)
    for part in msg.walk():
        ct = (part.get_content_type() or "").lower()
        if "pkcs7" in ct:
            raw = part.get_payload(decode=True)
            if isinstance(raw, str):
                raw = raw.encode("utf-8", "replace")
            if raw:
                der = _der_from_payload(raw)
                if der:
                    found.append(der)
    if _PKCS7_CT.search(raw_email):
        # raw scan for base64 blocks near pkcs7 headers (fallback)
        pass
    return found


def verify_smime(raw_email: bytes) -> dict[str, Any]:
    """
    Detect PKCS#7 / S/MIME structures and extract certificate chains when possible.

    Returns a dict compatible with :class:`models.response_models.SMIMEResult`.
    Message-level CMS digest verification is not always available; chain integrity
    uses ``verify_directly_issued_by`` when multiple certificates are embedded.
    """
    out = _smime_result()
    if not raw_email:
        out["explanation"] = "Empty input; no S/MIME material."
        return out

    try:
        msg = BytesParser(policy=EmailPolicy()).parsebytes(raw_email)
    except Exception:
        msg = None

    if msg is not None:
        root_ct = msg.get_content_type() or ""
        if "pkcs7" in root_ct.lower():
            out["present"] = True
        if root_ct == "multipart/signed":
            proto = (msg.get_param("protocol") or "").lower()
            if "pkcs7" in proto or "x-pkcs7" in proto:
                out["present"] = True

    if not out["present"] and _PKCS7_CT.search(raw_email):
        out["present"] = True

    if not out["present"]:
        out["explanation"] = "No S/MIME / PKCS#7 signed structures detected."
        return out

    candidates = _extract_pkcs7_candidates(msg, raw_email)
    if not candidates and msg is not None:
        # try first walk for any base64-looking attachment when multipart/signed pkcs7
        pl = msg.get_payload() if msg.is_multipart() else None
        if isinstance(pl, list) and len(pl) >= 2:
            for p in pl[1:]:
                raw = p.get_payload(decode=True)
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", "replace")
                if raw and len(raw) > 16:
                    d = _der_from_payload(raw)
                    candidates.append(d if d is not None else raw)

    def _load_pkcs7_certs(blob: bytes) -> list[x509.Certificate]:
        errs: list[str] = []
        for loader, label in (
            (load_der_pkcs7_certificates, "DER"),
            (load_pem_pkcs7_certificates, "PEM"),
        ):
            try:
                got = list(loader(blob))
                if got:
                    return got
            except Exception as e:  # noqa: BLE001 — try both encodings
                errs.append(f"{label}:{e!s}")
        raise ValueError("; ".join(errs) if errs else "empty PKCS#7")

    last_err = ""
    for der in candidates:
        if not der:
            continue
        try:
            certs = _load_pkcs7_certs(der)
        except Exception as e:
            last_err = str(e)
            continue
        if not certs:
            continue
        ordered = _order_cert_chain(certs)
        struct_ok = _ordered_chain_valid(ordered)
        chain_dicts: list[dict[str, Any]] = []
        for i, cert in enumerate(ordered):
            link_ok = True
            if i < len(ordered) - 1:
                try:
                    cert.verify_directly_issued_by(ordered[i + 1])
                except Exception:
                    link_ok = False
            elif len(ordered) == 1 and cert.issuer == cert.subject:
                try:
                    cert.verify_directly_issued_by(cert)
                except Exception:
                    link_ok = False
            entry = {
                "level": i,
                "type": _cert_type(i, len(ordered)),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "valid": link_ok and _now_valid(cert),
            }
            chain_dicts.append(entry)

        ee = ordered[0]
        out["chain"] = chain_dicts
        out["subject_cn"] = _cn(ee.subject)
        out["issuer_cn"] = _cn(ee.issuer)
        try:
            out["valid_from"] = ee.not_valid_before_utc.isoformat()
            out["valid_to"] = ee.not_valid_after_utc.isoformat()
        except AttributeError:
            out["valid_from"] = ee.not_valid_before.isoformat()
            out["valid_to"] = ee.not_valid_after.isoformat()
        out["serial_number"] = str(ee.serial_number)
        try:
            pub = ee.public_key()
            out["algorithm"] = pub.__class__.__name__.replace("PublicKey", "")
        except Exception:
            out["algorithm"] = ""

        out["valid"] = bool(struct_ok and _now_valid(ee))
        out["explanation"] = (
            "Parsed embedded X.509 certificates from PKCS#7. "
            "Issuer-to-subject links were checked where possible; CMS signedAttributes "
            "over the MIME body are not fully verified in this pass."
        )
        return out

    out["valid"] = False
    out["chain"] = []
    out["explanation"] = (
        "S/MIME or PKCS#7 framing was detected, but no certificate set could be loaded "
        f"from the signature blob{f' ({last_err})' if last_err else ''}. "
        "Synthetic lab samples often ship non-DER placeholders."
    )
    return out
