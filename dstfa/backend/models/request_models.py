"""API request bodies (Phase 1+)."""

from typing import Any

from pydantic import BaseModel, Field


class AnalyzeOptions(BaseModel):
    run_llm: bool = False
    syllabus_mode: bool = False
    run_vulnerability_check: bool = False


class AnalyzeRequest(BaseModel):
    upload_id: str
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class RawHeadersUpload(BaseModel):
    raw_headers: str = ""


class UploadResponse(BaseModel):
    """Returned from POST /api/upload and GET /api/samples/{id}."""

    upload_id: str = ""
    filename: str = ""
    size_bytes: int = 0
    detected_type: str = ""
    preview: dict[str, Any] = Field(default_factory=dict)


class SampleMeta(BaseModel):
    id: str = ""
    filename: str = ""
    title: str = ""
    description: str = ""
