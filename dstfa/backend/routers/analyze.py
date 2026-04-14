"""Analysis pipeline (Phase 1: headers + input summary only)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from models.request_models import AnalyzeRequest
from models.response_models import (
    AnalysisResult,
    HeadersResult,
    InputSummary,
    ParsedHeader,
    ReceivedHop,
)
from services.email_parser import parse_email
from storage import analysis_store, upload_store

router = APIRouter(tags=["analyze"])


def _build_analysis_result(raw: bytes) -> AnalysisResult:
    parsed = parse_email(raw)
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

    return AnalysisResult(
        analysis_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_summary=input_summary,
        headers=headers,
        vulnerability_available=False,
    )


@router.post("/analyze", response_model=AnalysisResult)
def analyze_email(body: AnalyzeRequest) -> AnalysisResult:
    raw = upload_store.get(body.upload_id)
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown upload_id")

    result = _build_analysis_result(raw)
    analysis_store[result.analysis_id] = result.model_dump(mode="json", by_alias=True)
    return result
