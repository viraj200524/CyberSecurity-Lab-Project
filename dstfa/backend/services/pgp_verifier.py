"""OpenPGP signature detection and verification (Phase 4)."""

from __future__ import annotations

import re
import warnings
from email.generator import BytesGenerator
from email.parser import BytesParser
from email.policy import EmailPolicy
from io import BytesIO
from typing import Any

from pgpy import PGPKey, PGPMessage, PGPSignature
from pgpy.errors import PGPError

_PGP_ARMOR = re.compile(
    rb"-----BEGIN PGP [A-Z0-9 ]+-----[\s\S]*?-----END PGP [A-Z0-9 ]+-----",
    re.MULTILINE,
)


def _pgp_result(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "present": False,
        "valid": False,
        "key_id": "",
        "fingerprint": "",
        "algorithm": "",
        "key_size": 0,
        "signer_uid": "",
        "signature_date": "",
        "trust_level": "none",
        "explanation": "",
    }
    base.update(overrides)
    return base


def _unwrap_from_blob(obj: Any) -> Any:
    if isinstance(obj, tuple):
        return obj[0]
    return obj


def _flatten_mime_part(part: Any, policy: EmailPolicy) -> bytes:
    buf = BytesIO()
    BytesGenerator(buf, policy=policy, mangle_from_=False).flatten(part)
    return buf.getvalue()


def _collect_public_keys(raw: bytes) -> list[PGPKey]:
    keys: list[PGPKey] = []
    for block in _PGP_ARMOR.finditer(raw):
        blob = block.group(0)
        if b"PUBLIC KEY BLOCK" not in blob and b"PRIVATE KEY BLOCK" not in blob:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = PGPKey.from_blob(blob)
            k = _unwrap_from_blob(res)
            if isinstance(k, PGPKey):
                keys.append(k)
        except (PGPError, ValueError, TypeError):
            continue
    return keys


def _mpi_hex(val: Any) -> str:
    """Best-effort hex for pgpy MPI / int-like signature material."""
    if val is None:
        return ""
    try:
        if hasattr(val, "to_mpibytes"):
            b = val.to_mpibytes()
            return b.hex() if b else ""
    except Exception:
        pass
    try:
        i = int(val)
        h = format(i, "x")
        if len(h) % 2:
            h = "0" + h
        return h
    except Exception:
        return ""


def _normalize_algo_name(raw: str) -> str:
    u = (raw or "").upper()
    if "RSA" in u:
        return "RSA"
    if "DSA" in u or u == "DSA":
        return "DSA"
    if "ED25519" in u or "EDDSA" in u:
        return "Ed25519"
    if "ECDSA" in u or "ELLIPTIC" in u or "EC" == u:
        return "ECDSA"
    return raw or ""


def _append_dsa_teaching_block(out: dict[str, Any], r_hex: str, s_hex: str) -> None:
    if not r_hex and not s_hex:
        return
    block = (
        "\n__DSA_HEX__\n"
        f"r={r_hex}\n"
        f"s={s_hex}\n"
        "__END_DSA__\n"
    )
    out["explanation"] = (out.get("explanation", "") + block).strip()


def _sig_meta(sig: PGPSignature, out: dict[str, Any]) -> None:
    try:
        kid = getattr(sig, "signer", None)
        if kid is not None:
            out["key_id"] = str(kid)
    except Exception:
        pass
    try:
        fp = getattr(sig, "signer_fingerprint", None)
        if fp is not None:
            out["fingerprint"] = str(fp)
    except Exception:
        pass
    try:
        ka = getattr(sig, "key_algorithm", None)
        if ka is not None:
            raw_alg = str(ka.name) if hasattr(ka, "name") else str(ka)
            out["algorithm"] = _normalize_algo_name(raw_alg)
    except Exception:
        pass
    try:
        ct = getattr(sig, "created", None)
        if ct is not None:
            if hasattr(ct, "isoformat"):
                out["signature_date"] = ct.isoformat()
            else:
                out["signature_date"] = str(ct)
    except Exception:
        pass
    # DSA (r,s) — Unit 6 teaching block (parsed by SignatureTab)
    try:
        pkt = getattr(sig, "__sig__", None)
        inner = getattr(pkt, "signature", None) if pkt is not None else None
        if inner is not None and inner.__class__.__name__ == "DSASignature":
            r, s = getattr(inner, "r", None), getattr(inner, "s", None)
            r_hex, s_hex = _mpi_hex(r), _mpi_hex(s)
            if r_hex or s_hex:
                out["algorithm"] = "DSA"
                _append_dsa_teaching_block(out, r_hex, s_hex)
                note = (
                    "DSA signature: (r, s) MPIs extracted (RFC 4880); verification uses "
                    "domain parameters and public key y with hash of canonical message."
                )
                out["explanation"] = f"{note}\n{out.get('explanation', '')}".strip()
    except Exception:
        pass


def _try_verify_with_keys(
    signed_material: bytes | PGPMessage,
    sig: PGPSignature,
    keys: list[PGPKey],
    out: dict[str, Any],
) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for key in keys:
            try:
                sv = key.verify(signed_material, sig)
                if bool(sv):
                    out["valid"] = True
                    out["fingerprint"] = str(key.fingerprint)
                    if key.userids:
                        out["signer_uid"] = str(key.userids[0])
                    try:
                        out["key_size"] = int(key.key_size) if key.key_size else 0
                    except Exception:
                        out["key_size"] = 0
                    try:
                        ka = key.key_algorithm
                        raw_alg = str(ka.name) if hasattr(ka, "name") else str(ka)
                        out["algorithm"] = _normalize_algo_name(raw_alg)
                    except Exception:
                        pass
                    out["trust_level"] = "unknown"
                    out["explanation"] = "OpenPGP signature verified with an embedded or supplied public key."
                    return True
            except (PGPError, NotImplementedError, TypeError, ValueError):
                continue
    return False


def verify_pgp(raw_email: bytes) -> dict[str, Any]:
    """
    Detect PGP clearsigned or PGP/MIME multipart/signed and verify when possible.

    Returns a dict compatible with :class:`models.response_models.PGPResult`.
    """
    out = _pgp_result()
    if not raw_email:
        out["explanation"] = "Empty input; no PGP material."
        return out

    keys = _collect_public_keys(raw_email)

    try:
        msg = BytesParser(policy=EmailPolicy()).parsebytes(raw_email)
    except Exception:
        msg = None

    signed_bytes: bytes | None = None
    detached_sig_armor: bytes | None = None
    clearsigned_blob: bytes | None = None

    if msg is not None and msg.get_content_type() == "multipart/signed":
        proto = (msg.get_param("protocol") or "").lower()
        if "pgp-signature" in proto or "application/pgp-signature" in proto:
            out["present"] = True
            pl = msg.get_payload()
            if isinstance(pl, list) and len(pl) >= 2:
                p0, p1 = pl[0], pl[1]
                try:
                    signed_bytes = _flatten_mime_part(p0, msg.policy)
                except Exception:
                    signed_bytes = None
                try:
                    if p1.get_content_type() in (
                        "application/pgp-signature",
                        "application/pgp-keys",
                    ) or "BEGIN PGP SIGNATURE" in (p1.as_string() or ""):
                        detached_sig_armor = p1.get_payload(decode=True)
                        if detached_sig_armor is None and isinstance(p1.get_payload(), str):
                            detached_sig_armor = p1.get_payload().encode("utf-8", "replace")
                except Exception:
                    detached_sig_armor = None

    if b"BEGIN PGP SIGNED MESSAGE" in raw_email:
        out["present"] = True
        m = _PGP_ARMOR.search(raw_email)
        if m and b"SIGNED MESSAGE" in m.group(0):
            clearsigned_blob = m.group(0)

    if not out["present"]:
        if b"BEGIN PGP SIGNATURE" in raw_email or b"BEGIN PGP MESSAGE" in raw_email:
            out["present"] = True

    if not out["present"]:
        out["explanation"] = "No OpenPGP signed message or detached signature detected."
        return out

    # --- clearsigned path ---
    if clearsigned_blob:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = PGPMessage.from_blob(clearsigned_blob)
            pmsg = _unwrap_from_blob(res)
            if isinstance(pmsg, PGPMessage) and pmsg.signatures:
                sig = next(iter(pmsg.signatures))
                _sig_meta(sig, out)
                if _try_verify_with_keys(pmsg, sig, keys, out):
                    return out
                out["valid"] = False
                out["trust_level"] = "unknown"
                out["explanation"] = (
                    "Clearsigned OpenPGP material found, but no usable public key was available "
                    "to complete verification (or the signature does not verify)."
                )
                return out
        except (PGPError, ValueError, TypeError) as e:
            out["valid"] = False
            out["trust_level"] = "none"
            out["explanation"] = (
                f"Clearsigned PGP block could not be parsed ({type(e).__name__}). "
                "Common with lab placeholder armors."
            )
            return out

    # --- detached PGP/MIME path ---
    if detached_sig_armor:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                res = PGPSignature.from_blob(detached_sig_armor)
            sig = _unwrap_from_blob(res)
            if not isinstance(sig, PGPSignature):
                raise ValueError("not a signature packet")
            _sig_meta(sig, out)
            if signed_bytes is None:
                out["valid"] = False
                out["explanation"] = "Detached PGP signature present but signed MIME part could not be flattened."
                return out
            if _try_verify_with_keys(signed_bytes, sig, keys, out):
                return out
            out["valid"] = False
            out["trust_level"] = "unknown"
            out["explanation"] = (
                "Detached PGP signature detected. It is not valid for the signed MIME part with the "
                "available keys, or the armor is a synthetic placeholder."
            )
            return out
        except (PGPError, ValueError, TypeError) as e:
            out["valid"] = False
            out["trust_level"] = "none"
            out["explanation"] = (
                f"PGP signature armor could not be parsed ({type(e).__name__}). "
                "Lab samples may use non-cryptographic placeholders."
            )
            return out

    out["valid"] = False
    out["explanation"] = (
        "PGP-like material was hinted in the message, but no verifiable clearsigned or detached "
        "signature structure was completed."
    )
    return out
