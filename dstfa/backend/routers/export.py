"""Export analysis as PDF or JSON (Phase 7.2)."""

from __future__ import annotations

import logging
from io import BytesIO

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from models.request_models import ExportRequest
from services.report_generator import generate_json_export, generate_pdf
from storage import analysis_store

logger = logging.getLogger(__name__)

router = APIRouter(tags=["export"])


@router.post("/export/pdf")
def export_pdf(body: ExportRequest) -> StreamingResponse:
    raw = analysis_store.get(body.analysis_id)
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown analysis_id")
    try:
        pdf_bytes = generate_pdf(raw)
    except Exception as e:
        logger.exception("PDF generation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation failed",
        ) from e

    short = body.analysis_id[:8] if len(body.analysis_id) >= 8 else body.analysis_id
    filename = f"dstfa_report_{short}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/export/json")
def export_json(body: ExportRequest) -> StreamingResponse:
    raw = analysis_store.get(body.analysis_id)
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown analysis_id")
    try:
        text = generate_json_export(raw)
    except Exception as e:
        logger.exception("JSON export failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JSON export failed",
        ) from e

    short = body.analysis_id[:8] if len(body.analysis_id) >= 8 else body.analysis_id
    filename = f"dstfa_report_{short}.json"
    return StreamingResponse(
        BytesIO(text.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
