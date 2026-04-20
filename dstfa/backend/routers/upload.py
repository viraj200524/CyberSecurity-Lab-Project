"""Upload and sample email routes (Phase 1)."""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from config import settings
from models.request_models import RawHeadersUpload, UploadResponse
from models.response_models import SampleListItem, SamplesListResponse
from services.email_parser import build_minimal_eml_from_headers, parse_email
from storage import store_upload

router = APIRouter(tags=["upload"])

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "tests" / "sample_emails"

# PRD §8.1 — gallery metadata (id matches filename stem).
SAMPLE_CATALOG: dict[str, dict[str, str | list[str]]] = {
    "dkim_valid": {
        "label": "Valid DKIM Email",
        "description": "Synthetic message with a DKIM-Signature header for authentication demos.",
        "highlights": ["DKIM", "SPF"],
    },
    "pgp_signed": {
        "label": "PGP Signed Email",
        "description": "Multipart/signed structure with a placeholder OpenPGP signature block.",
        "highlights": ["PGP", "DSA"],
    },
    "md5_phishing": {
        "label": "MD5 Hash — Vulnerable",
        "description": "Body references MD5 for weak-hash demos; Reply-To domain mismatches From for phishing heuristics.",
        "highlights": ["MD5", "Collision Demo"],
    },
    "smime_chain": {
        "label": "S/MIME Certificate Chain",
        "description": "Synthetic PKCS#7 / multipart/signed layout for S/MIME chain-of-trust labs (later-phase verification).",
        "highlights": ["S/MIME", "X.509"],
    },
}

SAMPLE_ORDER = ("dkim_valid", "pgp_signed", "md5_phishing", "smime_chain")


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
    store_upload(upload_id, raw)

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


def _sample_list_item(sid: str) -> SampleListItem:
    meta = SAMPLE_CATALOG.get(sid, {})
    label = str(meta.get("label", sid.replace("_", " ").title()))
    desc = str(meta.get("description", ""))
    hl = meta.get("highlights", [])
    highlights = [str(x) for x in hl] if isinstance(hl, list) else []
    return SampleListItem(id=sid, label=label, description=desc, highlights=highlights)


@router.get("/samples", response_model=SamplesListResponse)
def list_samples() -> SamplesListResponse:
    if not SAMPLES_DIR.is_dir():
        return SamplesListResponse(samples=[])
    stems = {p.stem for p in SAMPLES_DIR.glob("*.eml")}
    ordered = [s for s in SAMPLE_ORDER if s in stems]
    ordered += sorted(s for s in stems if s not in SAMPLE_ORDER)
    return SamplesListResponse(samples=[_sample_list_item(sid) for sid in ordered])


@router.get("/samples/{sample_id}", response_model=UploadResponse)
def load_sample(sample_id: str) -> UploadResponse:
    path = SAMPLES_DIR / f"{sample_id}.eml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Unknown sample_id")
    raw = path.read_bytes()
    return _ingest_bytes(raw, path.name)
