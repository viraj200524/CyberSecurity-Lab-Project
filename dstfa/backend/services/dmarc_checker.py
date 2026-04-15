"""DMARC policy lookup and alignment heuristics (Phase 3).

``check_dmarc`` evaluates header From domain against published DMARC (``_dmarc`` TXT)
and SPF/DKIM dicts from :func:`spf_checker.check_spf` and :func:`dkim_verifier.verify_dkim`.

``run_auth_checks`` is the single orchestrator returning an ``AuthResult``-shaped dict
(``spf``, ``dkim``, ``dmarc``, ``arc``) for API integration.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from email.utils import getaddresses
from typing import Any, Iterator

import dns.exception
import dns.resolver

from config import settings

from .dkim_verifier import verify_arc, verify_dkim
from .spf_checker import check_spf

__all__ = ["check_dmarc", "run_auth_checks"]


def _resolver_for_dmarc(timeout: float) -> dns.resolver.Resolver:
    res = dns.resolver.Resolver(configure=True)
    ns = (settings.DNS_RESOLVER or "").strip()
    if ns and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ns):
        res.nameservers = [ns]
    res.lifetime = timeout
    return res


@contextmanager
def _default_resolver_override(res: dns.resolver.Resolver) -> Iterator[None]:
    prev = dns.resolver.default_resolver
    dns.resolver.default_resolver = res
    try:
        yield
    finally:
        dns.resolver.default_resolver = prev


def _from_header_domain(parsed: dict[str, Any]) -> str:
    summary = parsed.get("input_summary") or {}
    from_hdr = str(summary.get("from", "") or "")
    _, mail = (getaddresses([from_hdr])[0] if from_hdr else ("", ""))
    if "@" in mail:
        return mail.split("@", 1)[1].lower().strip()
    return ""


def _domains_align(mode: str, left: str, right: str) -> bool:
    """Strict (s) or relaxed (r) alignment between two hostnames."""
    a = (left or "").lower().strip().rstrip(".")
    b = (right or "").lower().strip().rstrip(".")
    if not a or not b:
        return False
    if (mode or "r").lower() == "s":
        return a == b
    if a == b:
        return True
    if a.endswith("." + b) or b.endswith("." + a):
        return True
    return False


def _parse_dmarc_record(txt_joined: str) -> dict[str, str]:
    out: dict[str, str] = {}
    blob = txt_joined.replace("\n", "").strip()
    for part in blob.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        key = k.strip().lower()
        val = v.strip()
        if key:
            out[key] = val
    return out


def check_dmarc(from_domain: str, spf: dict[str, Any], dkim: dict[str, Any]) -> dict[str, Any]:
    """
    Fetch DMARC for the Header From domain and evaluate alignment vs SPF/DKIM dicts.

    Returns a dict compatible with ``DMARCResult``.
    """
    fd = (from_domain or "").lower().strip().rstrip(".")
    if not fd:
        return {
            "result": "none",
            "policy": "none",
            "alignment_spf": "none",
            "alignment_dkim": "none",
            "explanation": "No From header domain; DMARC not evaluated.",
        }

    timeout = 5.0
    name = f"_dmarc.{fd}"
    resolv = _resolver_for_dmarc(timeout)
    txt_blob = ""
    try:
        with _default_resolver_override(resolv):
            ans = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        chunks: list[str] = []
        for rr in ans:
            for s in rr.strings:
                if isinstance(s, (bytes, bytearray)):
                    chunks.append(bytes(s).decode("utf-8", errors="replace"))
                else:
                    chunks.append(str(s))
        txt_blob = "".join(chunks)
    except dns.resolver.NXDOMAIN:
        return {
            "result": "none",
            "policy": "none",
            "alignment_spf": "none",
            "alignment_dkim": "none",
            "explanation": f"No DMARC record at {name} (NXDOMAIN).",
        }
    except dns.exception.Timeout:
        return {
            "result": "none",
            "policy": "none",
            "alignment_spf": "none",
            "alignment_dkim": "none",
            "explanation": "DMARC DNS lookup timed out; treated as no usable policy.",
        }
    except Exception as e:
        return {
            "result": "none",
            "policy": "none",
            "alignment_spf": "none",
            "alignment_dkim": "none",
            "explanation": f"DMARC DNS lookup failed: {e}",
        }

    if "v=DMARC1" not in txt_blob and "v=dmarc1" not in txt_blob.lower():
        return {
            "result": "none",
            "policy": "none",
            "alignment_spf": "none",
            "alignment_dkim": "none",
            "explanation": f"TXT at {name} present but not a valid DMARC1 record.",
        }

    tags = _parse_dmarc_record(txt_blob)
    policy = (tags.get("p") or "none").lower()
    subdomain_policy = (tags.get("sp") or policy).lower()
    aspf = (tags.get("aspf") or "r").lower()
    adkim = (tags.get("adkim") or "r").lower()

    spf_domain = str(spf.get("domain") or "").lower().strip().rstrip(".")
    spf_result = str(spf.get("result") or "none").lower()
    dkim_domain = str(dkim.get("domain") or "").lower().strip().rstrip(".")
    dkim_result = str(dkim.get("result") or "none").lower()
    dkim_sig_ok = bool(dkim.get("signature_valid"))

    spf_aligned = spf_result == "pass" and _domains_align(aspf, spf_domain, fd)
    dkim_aligned = dkim_result == "pass" and dkim_sig_ok and _domains_align(adkim, dkim_domain, fd)

    alignment_spf = "aligned" if spf_aligned else ("not_aligned" if spf_domain else "none")
    alignment_dkim = "aligned" if dkim_aligned else ("not_aligned" if dkim_domain else "none")

    dmarc_pass = spf_aligned or dkim_aligned
    dmarc_result = "pass" if dmarc_pass else "fail"

    pol_label = policy if policy in ("reject", "quarantine", "none") else "none"
    explain = (
        f"DMARC policy p={pol_label}"
        + (f", sp={subdomain_policy}" if tags.get("sp") else "")
        + f". SPF alignment: {alignment_spf}; DKIM alignment: {alignment_dkim}. "
        f"Aggregate result: {dmarc_result} (at least one aligned pass required)."
    )
    if pol_label == "reject":
        explain += " This domain publishes a strict reject policy for failing mail."
    elif pol_label == "quarantine":
        explain += " Failing mail may be quarantined or junk-foldered."

    return {
        "result": dmarc_result,
        "policy": pol_label,
        "alignment_spf": alignment_spf,
        "alignment_dkim": alignment_dkim,
        "explanation": explain,
    }


def run_auth_checks(raw_email: bytes, parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Run SPF, DKIM, DMARC, and ARC checks. Returns a dict ``AuthResult`` can validate.
    """
    spf_res = check_spf(raw_email, parsed)
    dkim_res = verify_dkim(raw_email)
    arc_res = verify_arc(raw_email)
    from_domain = _from_header_domain(parsed)
    dmarc_res = check_dmarc(from_domain, spf_res, dkim_res)
    return {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res,
        "arc": arc_res,
    }
