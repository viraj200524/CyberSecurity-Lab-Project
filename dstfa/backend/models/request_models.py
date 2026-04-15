"""API request bodies (Phase 1+)."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class AnalyzeOptions(BaseModel):
    run_llm: bool = False
    syllabus_mode: bool = False
    run_vulnerability_check: bool = False


class AnalyzeRequest(BaseModel):
    upload_id: str
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class VulnerabilityRunRequest(BaseModel):
    analysis_id: str
    demo_type: Literal["collision", "length_extension"] = "collision"


class RawHeadersUpload(BaseModel):
    raw_headers: str = ""


class UploadResponse(BaseModel):
    """Returned from POST /api/upload and GET /api/samples/{id}."""

    upload_id: str = ""
    filename: str = ""
    size_bytes: int = 0
    detected_type: str = ""
    preview: dict[str, Any] = Field(default_factory=dict)
