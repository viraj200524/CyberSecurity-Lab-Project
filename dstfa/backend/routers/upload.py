"""Upload and sample email routes (Phase 1)."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from config import settings
from models.request_models import RawHeadersUpload, SampleMeta, UploadResponse
from services.email_parser import build_minimal_eml_from_headers, parse_email
from storage import upload_store

router = APIRouter(tags=["upload"])

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "tests" / "sample_emails"

SAMPLE_TITLES: dict[str, tuple[str, str]] = {
    "dkim_valid": ("DKIM-signed sample", "Synthetic message with DKIM-Signature header."),
    "pgp_signed": ("PGP-signed sample", "Multipart message referencing PGP-style signing."),
    "md5_hash_email": ("MD5 / weak hash sample", "Message body referencing MD5 for lab demos."),
    "phishing_sample": ("Phishing-style sample", "Reply-To domain mismatch for suspicious header demo."),
}


def _max_bytes() -> int:
    return max(1, settings.MAX_FILE_SIZE_MB) * 1024 * 1024


def _preview_from_parsed(parsed: dict) -> dict:
    s = parsed.get("input_summary") or {}
    return {
        "subject": s.get("subject", ""),
        "from": s.get("from", ""),
        "to": s.get("to", []) if isinstance(s.get("to"), list) else [],
        "date": s.get("date", ""),
    }


def _ingest_bytes(raw: bytes, filename: str) -> UploadResponse:
    if len(raw) > _max_bytes():
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds MAX_FILE_SIZE_MB={settings.MAX_FILE_SIZE_MB}",
        )
    try:
        parsed = parse_email(raw)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    upload_id = str(uuid.uuid4())
    upload_store[upload_id] = raw

    return UploadResponse(
        upload_id=upload_id,
        filename=filename,
        size_bytes=len(raw),
        detected_type=parsed.get("detected_type", "unknown"),
        preview=_preview_from_parsed(parsed),
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_email(
    request: Request,
    file: UploadFile | None = File(None),
) -> UploadResponse:
    """Accept multipart file (.eml / .msg) or JSON `{ \"raw_headers\": \"...\" }`."""
    ct = (request.headers.get("content-type") or "").lower()

    if "application/json" in ct:
        body = await request.json()
        try:
            payload = RawHeadersUpload.model_validate(body)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}") from e
        raw = build_minimal_eml_from_headers(payload.raw_headers or "")
        return _ingest_bytes(raw, "pasted-headers.eml")

    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail="Missing file or raw_headers JSON body")

    name = file.filename.lower()
    if not (name.endswith(".eml") or name.endswith(".msg")):
        raise HTTPException(status_code=400, detail="Only .eml and .msg files are accepted")

    raw = await file.read()
    return _ingest_bytes(raw, file.filename)


@router.get("/samples", response_model=list[SampleMeta])
def list_samples() -> list[SampleMeta]:
    if not SAMPLES_DIR.is_dir():
        return []
    out: list[SampleMeta] = []
    for p in sorted(SAMPLES_DIR.glob("*.eml")):
        sid = p.stem
        title, desc = SAMPLE_TITLES.get(sid, (sid.replace("_", " ").title(), ""))
        out.append(SampleMeta(id=sid, filename=p.name, title=title, description=desc))
    return out


@router.get("/samples/{sample_id}", response_model=UploadResponse)
def load_sample(sample_id: str) -> UploadResponse:
    path = SAMPLES_DIR / f"{sample_id}.eml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Unknown sample_id")
    raw = path.read_bytes()
    return _ingest_bytes(raw, path.name)
