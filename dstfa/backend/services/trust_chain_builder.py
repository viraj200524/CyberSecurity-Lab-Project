"""Aggregate PGP, S/MIME, and authentication results into a trust-chain view (Phase 4)."""

from __future__ import annotations

from typing import Any

from services.pgp_verifier import verify_pgp
from services.smime_verifier import verify_smime


def _esc(s: str) -> str:
    return (
        (s or "")
        .replace("&", " and ")
        .replace('"', "'")
        .replace("\n", " ")
        .replace("\r", "")
    )[:120]


def _boolish(v: Any) -> bool:
    return bool(v)


def _cn_from_subject(subject: str) -> str:
    for part in (subject or "").split(","):
        p = part.strip()
        if p.upper().startswith("CN="):
            return _esc(p[3:])
    return _esc(subject[:96])


def _smime_chain_labels(chain: list[dict[str, Any]]) -> list[tuple[str, str, bool]]:
    """Return (emoji_title, short_label, link_ok) from root → EE order (reversed level index)."""
    if not chain:
        return []
    by_level = sorted(chain, key=lambda x: int(x.get("level", 0)))
    n = len(by_level)
    out: list[tuple[str, str, bool]] = []
    for i, entry in enumerate(by_level):
        subj = str(entry.get("subject") or "")
        cn = _cn_from_subject(subj) or "cert"
        ctype = str(entry.get("type") or "")
        ok = _boolish(entry.get("valid"))
        if n == 1:
            emoji = "🔒 Root CA" if ctype == "root" else "📧 End-entity"
        elif ctype == "root" or i == n - 1:
            emoji = "🔒 Root CA"
        elif ctype == "end-entity" or i == 0:
            emoji = "📧 End-entity"
        else:
            emoji = "🔑 Intermediate"
        out.append((emoji, cn, ok))
    # PRD flow: Root → … → EE → Email — list is EE-first from verifier
    return list(reversed(out))


def build_trust_chain(
    pgp: dict[str, Any],
    smime: dict[str, Any],
    dkim: dict[str, Any],
    spf: dict[str, Any],
    dmarc: dict[str, Any],
) -> dict[str, Any]:
    """
    Build Mermaid diagram and summary compatible with :class:`models.response_models.TrustChainResult`.
    """
    weak_points: list[str] = []

    pgp_present = _boolish(pgp.get("present"))
    pgp_valid = _boolish(pgp.get("valid"))
    sm_present = _boolish(smime.get("present"))
    sm_valid = _boolish(smime.get("valid"))
    sm_chain = smime.get("chain") if isinstance(smime.get("chain"), list) else []

    dkim_result = str(dkim.get("result") or "none").lower()
    dkim_sig_ok = _boolish(dkim.get("signature_valid"))
    spf_result = str(spf.get("result") or "none").lower()
    dmarc_result = str(dmarc.get("result") or "none").lower()

    if pgp_present and not pgp_valid:
        weak_points.append("OpenPGP signature present but not verified (invalid, missing key, or placeholder).")
    if sm_present and not sm_valid:
        weak_points.append("S/MIME or PKCS#7 present but certificate chain or structure is not fully valid.")
    if isinstance(sm_chain, list) and sm_chain:
        for link in sm_chain:
            if not _boolish(link.get("valid")):
                weak_points.append(
                    f"Certificate link flagged not valid: {_esc(str(link.get('subject', '')))}."
                )
    if dkim_result == "fail" or (dkim_result == "pass" and not dkim_sig_ok):
        weak_points.append("DKIM failed or claims pass without a verified signature.")
    elif dkim_result in ("permerror", "temperror"):
        weak_points.append(f"DKIM returned {dkim_result}; DNS or parsing issues may affect trust.")
    if spf_result in ("fail", "softfail", "permerror"):
        weak_points.append(f"SPF result is adverse ({spf_result}).")
    if dmarc_result == "fail":
        weak_points.append("DMARC alignment/policy evaluation failed.")

    chain_valid = not any(
        [
            pgp_present and not pgp_valid,
            sm_present and not sm_valid,
            dkim_result == "fail",
            spf_result in ("fail", "softfail"),
            dmarc_result == "fail",
        ]
    )

    # --- Mermaid (graph TD + PRD colour palette) ---
    fill_ok = "#00ff88"
    fill_bad = "#ff3860"
    fill_warn = "#ffb800"
    fill_absent = "#6b7a99"
    fill_email = "#1a2340"

    def node_style(ok: bool, absent: bool, warn: bool = False) -> str:
        if absent:
            return f"fill:{fill_absent},color:#fff"
        if warn:
            return f"fill:{fill_warn},color:#000"
        return f"fill:{fill_ok},color:#000" if ok else f"fill:{fill_bad},color:#fff"

    pgp_abs = not pgp_present
    sm_abs = not sm_present
    dkim_abs = dkim_result in ("none", "")
    spf_abs = spf_result in ("none", "")
    dmarc_abs = dmarc_result in ("none", "")

    pgp_lbl = "🔐 PGP<br/>absent" if pgp_abs else ("🔐 PGP<br/>valid" if pgp_valid else "🔐 PGP<br/>invalid")
    sm_lbl = "📧 S/MIME<br/>absent" if sm_abs else ("📧 S/MIME<br/>valid" if sm_valid else "📧 S/MIME<br/>invalid")
    dkim_lbl = f"🛡️ DKIM<br/>{_esc(dkim_result or 'none')}"
    spf_lbl = f"✅ SPF<br/>{_esc(spf_result or 'none')}"
    dmarc_lbl = f"📋 DMARC<br/>{_esc(dmarc_result or 'none')}"
    email_lbl = "✉️ Email<br/>message"

    lines: list[str] = ["graph TD"]

    sm_labels = _smime_chain_labels(sm_chain) if sm_present and isinstance(sm_chain, list) else []

    # PKI stack: Root → … → EE → Email (only when we parsed a chain)
    if sm_labels:
        for idx, (emoji_title, short_lbl, _ok) in enumerate(sm_labels):
            lines.append(f'  SM{idx}["{emoji_title}<br/>{short_lbl}"]')
        for idx in range(len(sm_labels) - 1):
            lines.append(f"  SM{idx} --> SM{idx + 1}")
        last_sm = len(sm_labels) - 1
    else:
        last_sm = -1

    lines.append(f'  Email["{email_lbl}"]')
    lines.append(f'  PGPn["{pgp_lbl}"]')
    if not sm_labels:
        lines.append(f'  SMIME["{sm_lbl}"]')
    lines.append(f'  DKIMn["{dkim_lbl}"]')
    lines.append(f'  SPFn["{spf_lbl}"]')
    lines.append(f'  DMARCn["{dmarc_lbl}"]')

    if sm_labels:
        lines.append(f"  SM{last_sm} --> Email")
    else:
        lines.append("  SMIME --> Email")
    lines.append("  PGPn --> Email")
    lines.append("  DKIMn --> Email")
    lines.append("  SPFn --> Email")
    lines.append("  DMARCn --> Email")

    lines.append(f"  style Email fill:{fill_email},color:#e8eaf0,stroke:#00d4ff,stroke-width:2px")
    lines.append(
        f"  style PGPn {node_style(pgp_valid, pgp_abs, warn=pgp_present and not pgp_valid and not pgp_abs)}"
    )
    if sm_labels:
        for idx, (_t, _s, ok) in enumerate(sm_labels):
            lines.append(f"  style SM{idx} {node_style(ok, False, warn=not ok)}")
    else:
        lines.append(
            f"  style SMIME {node_style(sm_valid, sm_abs, warn=sm_present and not sm_valid and not sm_abs)}"
        )
    dkim_ok = dkim_result == "pass" and dkim_sig_ok
    lines.append(f"  style DKIMn {node_style(dkim_ok, dkim_abs, warn=dkim_result not in ('pass', 'none', '') and not dkim_ok)}")
    lines.append(f"  style SPFn {node_style(spf_result == 'pass', spf_abs, warn=spf_result in ('softfail', 'permerror'))}")
    lines.append(
        f"  style DMARCn {node_style(dmarc_result == 'pass', dmarc_abs, warn=dmarc_result in ('none', '') and not dmarc_abs)}"
    )

    mermaid = "\n".join(lines)

    d_dom = _esc(str(dkim.get("domain") or ""))
    s_dom = _esc(str(spf.get("domain") or ""))
    summary = (
        f"Trust overview: PGP is {'verified' if pgp_valid else ('absent' if pgp_abs else 'not verified')}; "
        f"S/MIME is {'verified' if sm_valid else ('absent' if sm_abs else 'not verified')}. "
        f"Email authentication: DKIM {dkim_result or 'none'}"
        + (f" (d={d_dom})" if d_dom else "")
        + f", SPF {spf_result or 'none'}"
        + (f" for {s_dom}" if s_dom else "")
        + f", DMARC {dmarc_result or 'none'}."
    )

    return {
        "mermaid_diagram": mermaid,
        "chain_valid": chain_valid,
        "weak_points": weak_points,
        "summary": summary,
    }


def run_signature_and_trust(raw_email: bytes, auth: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Run PGP + S/MIME verification and compose the trust chain.

    Parameters
    ----------
    raw_email:
        Raw RFC822 bytes.
    auth:
        Authentication subtree (e.g. ``AnalysisResult.authentication.model_dump()``),
        containing ``spf``, ``dkim``, and ``dmarc`` dicts.

    Returns
    -------
    tuple
        ``(signatures_result_dict, trust_chain_dict)`` compatible with
        :class:`models.response_models.SignaturesResult` and
        :class:`models.response_models.TrustChainResult`.
    """
    pgp = verify_pgp(raw_email)
    smime = verify_smime(raw_email)
    auth = auth or {}
    dkim = auth.get("dkim") if isinstance(auth.get("dkim"), dict) else {}
    spf = auth.get("spf") if isinstance(auth.get("spf"), dict) else {}
    dmarc = auth.get("dmarc") if isinstance(auth.get("dmarc"), dict) else {}
    trust = build_trust_chain(pgp, smime, dkim, spf, dmarc)
    return {"pgp": pgp, "smime": smime}, trust
