"""Analysis pipeline: Phase 1 headers + Phases 2–4 crypto, auth, signatures, trust chain."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, status

from config import settings
from models.request_models import AnalyzeRequest
from models.response_models import (
    AnalysisResult,
    AuthResult,
    HashResult,
    HeadersResult,
    InputSummary,
    LLMInsights,
    ParsedHeader,
    ReceivedHop,
    SignaturesResult,
    TrustChainResult,
)
from services.dmarc_checker import run_auth_checks
from services.email_parser import parse_email
from services.hash_engine import build_hash_result, get_body_bytes
from services.llm_agent import generate_forensic_explanation
from services.trust_chain_builder import run_signature_and_trust
from storage import analysis_store, store_analysis, upload_store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analyze"])


def _default_hashes() -> dict[str, Any]:
    return HashResult().model_dump(mode="json")


def _default_auth() -> dict[str, Any]:
    return AuthResult().model_dump(mode="json")


def _safe_build_hashes(body_bytes: bytes, attachments: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        return build_hash_result(body_bytes, attachments)
    except Exception:
        logger.exception("hash pipeline failed")
        return _default_hashes()


def _safe_run_auth(raw: bytes, parsed: dict[str, Any]) -> dict[str, Any]:
    try:
        return run_auth_checks(raw, parsed)
    except Exception:
        logger.exception("authentication pipeline failed")
        return _default_auth()


def _safe_signatures_trust(raw: bytes, auth_dict: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        return run_signature_and_trust(raw, auth_dict)
    except Exception:
        logger.exception("signature/trust pipeline failed")
        return (
            SignaturesResult().model_dump(mode="json"),
            TrustChainResult().model_dump(mode="json"),
        )


async def _build_analysis_result(
    raw: bytes,
    *,
    run_llm: bool = False,
) -> AnalysisResult:
    parsed = await asyncio.to_thread(parse_email, raw)
    s = parsed.get("input_summary") or {}

    input_summary = InputSummary.model_validate(
        {
            "subject": s.get("subject", ""),
            "from": s.get("from", ""),
            "to": s.get("to", []) if isinstance(s.get("to"), list) else [],
            "date": s.get("date", ""),
            "message_id": s.get("message_id", ""),
            "mime_parts": int(s.get("mime_parts") or 0),
        }
    )

    parsed_headers = [ParsedHeader.model_validate(h) for h in (parsed.get("headers") or {}).get("parsed", [])]
    received = [ReceivedHop.model_validate(h) for h in (parsed.get("headers") or {}).get("received_chain", [])]
    headers = HeadersResult(
        raw=(parsed.get("headers") or {}).get("raw", ""),
        parsed=parsed_headers,
        received_chain=received,
    )

    body_bytes = await asyncio.to_thread(get_body_bytes, raw)
    attachments = list(parsed.get("_attachments_raw") or [])

    h_task = asyncio.to_thread(_safe_build_hashes, body_bytes, attachments)
    a_task = asyncio.to_thread(_safe_run_auth, raw, parsed)
    hdict, adict = await asyncio.gather(h_task, a_task)

    hashes = HashResult.model_validate(hdict)
    authentication = AuthResult.model_validate(adict)

    sig_dict, trust_dict = await asyncio.to_thread(_safe_signatures_trust, raw, adict)
    digital_signatures = SignaturesResult.model_validate(sig_dict)
    trust_chain = TrustChainResult.model_validate(trust_dict)

    vulnerability_available = bool(hashes.vulnerability_flags.md5_detected)

    result = AnalysisResult(
        analysis_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_summary=input_summary,
        headers=headers,
        hashes=hashes,
        authentication=authentication,
        digital_signatures=digital_signatures,
        trust_chain=trust_chain,
        llm_insights=None,
        llm_error=None,
        vulnerability_available=vulnerability_available,
    )

    if not run_llm:
        return result

    if not (settings.GROQ_API_KEY or "").strip():
        return result.model_copy(
            update={
                "llm_insights": None,
                "llm_error": "GROQ_API_KEY is not set. Add it to backend/.env to enable AI insights.",
            }
        )

    try:
        partial = result.model_dump(mode="json", by_alias=True)
        partial.pop("llm_insights", None)
        partial.pop("llm_error", None)
        insights: LLMInsights = await asyncio.to_thread(generate_forensic_explanation, partial)
        return result.model_copy(update={"llm_insights": insights, "llm_error": None})
    except Exception as e:
        logger.exception("Groq forensic generation failed")
        return result.model_copy(
            update={
                "llm_insights": None,
                "llm_error": str(e) or "LLM analysis failed",
            }
        )


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_email(body: AnalyzeRequest) -> AnalysisResult:
    raw = upload_store.get(body.upload_id)
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown upload_id")

    result = await _build_analysis_result(raw, run_llm=body.options.run_llm)
    store_analysis(result.analysis_id, result.model_dump(mode="json", by_alias=True))
    return result
