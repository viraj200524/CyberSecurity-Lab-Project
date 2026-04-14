"""API response models — tolerant defaults for partial emails (Phase 1+)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParsedHeader(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = ""
    value: str = ""
    suspicious: bool = False
    explanation: str = ""


class ReceivedHop(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    from_host: str = Field(default="", validation_alias="from", serialization_alias="from")
    by_host: str = Field(default="", validation_alias="by", serialization_alias="by")
    timestamp: str = ""
    delay_seconds: int = 0


class HeadersResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    raw: str = ""
    parsed: list[ParsedHeader] = Field(default_factory=list)
    received_chain: list[ReceivedHop] = Field(default_factory=list)


class InputSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    subject: str = ""
    from_addr: str = Field(default="", validation_alias="from", serialization_alias="from")
    to: list[str] = Field(default_factory=list)
    date: str = ""
    message_id: str = ""
    mime_parts: int = 0


# --- Stubs for full AnalysisResult (filled in later phases) ---


class SPFResult(BaseModel):
    result: str = "none"
    domain: str = ""
    ip: str = ""
    explanation: str = ""


class DKIMResult(BaseModel):
    result: str = "none"
    domain: str = ""
    selector: str = ""
    algorithm: str = ""
    body_hash: str = ""
    signature_valid: bool = False
    key_size_bits: int = 0
    explanation: str = ""


class DMARCResult(BaseModel):
    result: str = "none"
    policy: str = "none"
    alignment_spf: str = ""
    alignment_dkim: str = ""
    explanation: str = ""


class ARCResult(BaseModel):
    present: bool = False
    chain_valid: bool = False
    instance_count: int = 0
    explanation: str = ""


class AuthResult(BaseModel):
    spf: SPFResult = Field(default_factory=SPFResult)
    dkim: DKIMResult = Field(default_factory=DKIMResult)
    dmarc: DMARCResult = Field(default_factory=DMARCResult)
    arc: ARCResult = Field(default_factory=ARCResult)


class HashBody(BaseModel):
    sha256: str = ""
    md5: str = ""
    sha1: str = ""


class HashAttachment(BaseModel):
    filename: str = ""
    sha256: str = ""
    md5: str = ""
    size_bytes: int = 0


class MerkleDamgardBlock(BaseModel):
    block_index: int = 0
    block_hex: str = ""
    input_chaining_vars: list[str] = Field(default_factory=list)
    output_chaining_vars: list[str] = Field(default_factory=list)
    rounds_summary: str = ""


class MerkleDamgardSteps(BaseModel):
    algorithm: str = "SHA-256"
    original_message_length: int = 0
    padded_message_length: int = 0
    padding_explanation: str = ""
    blocks: list[MerkleDamgardBlock] = Field(default_factory=list)
    final_hash: str = ""


class VulnerabilityFlags(BaseModel):
    md5_detected: bool = False
    sha1_detected: bool = False
    length_extension_risk: bool = False
    weak_hash_explanation: str = ""


class HashResult(BaseModel):
    body: HashBody = Field(default_factory=HashBody)
    attachments: list[HashAttachment] = Field(default_factory=list)
    merkle_damgard_steps: MerkleDamgardSteps | None = None
    vulnerability_flags: VulnerabilityFlags = Field(default_factory=VulnerabilityFlags)


class PGPResult(BaseModel):
    present: bool = False
    valid: bool = False
    key_id: str = ""
    fingerprint: str = ""
    algorithm: str = ""
    key_size: int = 0
    signer_uid: str = ""
    signature_date: str = ""
    trust_level: str = "none"
    explanation: str = ""


class SMIMEResult(BaseModel):
    present: bool = False
    valid: bool = False
    subject_cn: str = ""
    issuer_cn: str = ""
    valid_from: str = ""
    valid_to: str = ""
    serial_number: str = ""
    algorithm: str = ""
    chain: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""


class SignaturesResult(BaseModel):
    pgp: PGPResult = Field(default_factory=PGPResult)
    smime: SMIMEResult = Field(default_factory=SMIMEResult)


class TrustChainResult(BaseModel):
    mermaid_diagram: str = ""
    chain_valid: bool = False
    weak_points: list[str] = Field(default_factory=list)
    summary: str = ""


class LLMInsights(BaseModel):
    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    model_used: str = ""
    timestamp: str = ""
    forensic_summary: str = ""
    entity_extraction: dict[str, Any] = Field(default_factory=dict)
    attack_vectors_detected: list[str] = Field(default_factory=list)
    threat_level: str = "low"
    syllabus_links: list[dict[str, Any]] = Field(default_factory=list)
    timeline_reconstruction: list[dict[str, Any]] = Field(default_factory=list)
    chain_of_custody_log: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    analysis_id: str = ""
    timestamp: str = ""
    input_summary: InputSummary = Field(default_factory=InputSummary)
    headers: HeadersResult = Field(default_factory=HeadersResult)
    authentication: AuthResult = Field(default_factory=AuthResult)
    hashes: HashResult = Field(default_factory=HashResult)
    digital_signatures: SignaturesResult = Field(default_factory=SignaturesResult)
    trust_chain: TrustChainResult = Field(default_factory=TrustChainResult)
    llm_insights: LLMInsights = Field(default_factory=LLMInsights)
    vulnerability_available: bool = False
