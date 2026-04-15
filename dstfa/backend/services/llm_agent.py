"""Gemini 2.0 Flash forensic agent (DSTFA Phase 5)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from config import settings
from models.response_models import LLMInsights

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a professional email forensics analyst and cybersecurity educator.
You analyze structured forensic data and produce clear, accurate explanations.
You always base your explanations strictly on the evidence provided — never hallucinate.
You map findings to cryptography concepts from two syllabus units:
- Unit 4: Hash Functions (SHA-256, MD5, Merkle-Damgård construction, HMAC, length-extension attacks)
- Unit 6: Digital Signatures (DSA, PGP/OpenPGP, S/MIME, X.509 certificate chains, chain of trust)

When syllabus_mode is True, add [Unit 4] or [Unit 6] tags inline next to each relevant concept."""

USER_PROMPT_TEMPLATE = """Analyze this email forensic data and provide:

1. FORENSIC SUMMARY (2-3 paragraphs): What happened with this email? Is it legitimate, suspicious, or malicious?

2. KEY FINDINGS: List the 3-5 most important security findings.

3. ENTITY EXTRACTION (return as JSON):
{{
  "senders": [],
  "ips": [],
  "domains": [],
  "bitcoin_addresses": [],
  "urls": [],
  "iocs": []
}}

4. THREAT LEVEL: One of: low, medium, high, critical — with justification.

5. ATTACK VECTORS: List any detected attack patterns (e.g., header spoofing, DKIM bypass, phishing indicators).

6. SYLLABUS CONNECTIONS: For each cryptographic element found, explain:
- What concept it demonstrates (e.g., "DKIM uses RSA-SHA256 digital signature")
- Which unit it belongs to
- Why it matters for security

7. TIMELINE: Reconstruct the email's journey from the Received headers in chronological order.

--- FORENSIC DATA ---
{forensic_data_json}
--- END DATA ---

Respond with valid JSON matching this structure:
{{
  "forensic_summary": "string",
  "key_findings": ["string"],
  "entity_extraction": {{ }},
  "threat_level": "low|medium|high|critical",
  "threat_justification": "string",
  "attack_vectors_detected": ["string"],
  "syllabus_links": [
    {{ "concept": "string", "unit": "string", "explanation": "string", "evidence_field": "string" }}
  ],
  "timeline_reconstruction": [
    {{ "timestamp": "ISO8601", "event": "string", "source": "string" }}
  ]
}}"""


VULN_SYSTEM_PROMPT = """You are a cryptography professor explaining the Merkle-Damgård construction weakness to an advanced undergraduate student.
Be technically precise but clear. Use the actual hash values from the email as evidence for your explanation.
Always tie your explanation back to Unit 4 syllabus concepts."""

VULN_USER_TEMPLATE = """The email we analyzed uses MD5 for its message hash.
MD5 hash of the email body: {md5_hash}
The collision demonstration just ran and produced these two different messages with the SAME MD5:
  Message 1: {m1_hex}
  Message 2: {m2_hex}
  Shared MD5: {shared_md5}

Provide a technical explanation in JSON:
{{
  "why_md5_fails": "2-3 sentence explanation of the fundamental weakness",
  "merkle_damgard_failure_point": "exactly which part of the MD5 Merkle-Damgård construction makes this possible",
  "step_by_step": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "why_sha256_resists": "how SHA-256 mitigates this despite also using Merkle-Damgård",
  "syllabus_note": "direct connection to Unit 4 hash function theory"
}}"""


def extract_json_object(text: str) -> dict[str, Any]:
    """Strip optional markdown fences and parse the first JSON object."""
    s = (text or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9]*\s*", "", s)
        s = re.sub(r"\s*```\s*$", "", s).strip()
    # Sometimes models wrap with prose — find outermost { ... }
    if "{" in s:
        start = s.index("{")
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    return json.loads(s[start : i + 1])
    return json.loads(s)


def call_gemini(system_prompt: str, user_prompt: str) -> str:
    import google.generativeai as genai

    if not (settings.GEMINI_API_KEY or "").strip():
        raise ValueError("GEMINI_API_KEY is not configured")
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        system_instruction=system_prompt,
    )
    response = model.generate_content(user_prompt)
    text = (response.text or "").strip()
    if not text:
        raise ValueError("Empty response from Gemini")
    return text


def _normalize_threat(raw: str) -> str:
    t = (raw or "low").lower().strip()
    return t if t in ("low", "medium", "high", "critical") else "low"


def generate_forensic_explanation(analysis_partial: dict[str, Any], syllabus_mode: bool) -> LLMInsights:
    """
    Build forensic JSON payload from non-LLM analysis fields, call Gemini, return ``LLMInsights``.
    """
    system = SYSTEM_PROMPT
    if syllabus_mode:
        system += "\nThe operator enabled syllabus_mode: include [Unit 4] / [Unit 6] tags inline in the forensic_summary and syllabus_links text where appropriate."

    forensic_json = json.dumps(analysis_partial, indent=2, default=str)
    user = USER_PROMPT_TEMPLATE.format(forensic_data_json=forensic_json)
    prompt_for_hash = f"{system}\n\n{user}"
    prompt_hash = hashlib.sha256(prompt_for_hash.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    raw = call_gemini(system, user)
    try:
        data = extract_json_object(raw)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("LLM JSON parse failed, retrying with strict instruction: %s", e)
        retry_user = (
            "Respond with ONLY valid raw JSON matching the schema from the prior instruction. "
            "No markdown fences, no commentary before or after the JSON.\n\n" + user
        )
        raw2 = call_gemini(system, retry_user)
        data = extract_json_object(raw2)
        raw = raw2

    entities = data.get("entity_extraction") or {}
    if not isinstance(entities, dict):
        entities = {}

    key_findings = data.get("key_findings") or []
    if not isinstance(key_findings, list):
        key_findings = []
    key_findings = [str(x) for x in key_findings]

    attack_vectors = data.get("attack_vectors_detected") or []
    if not isinstance(attack_vectors, list):
        attack_vectors = []
    attack_vectors = [str(x) for x in attack_vectors]

    syllabus_links = data.get("syllabus_links") or []
    if not isinstance(syllabus_links, list):
        syllabus_links = []

    timeline = data.get("timeline_reconstruction") or []
    if not isinstance(timeline, list):
        timeline = []

    threat_justification = str(data.get("threat_justification", "") or "")

    return LLMInsights(
        model_used="gemini-2.0-flash",
        timestamp=now,
        forensic_summary=str(data.get("forensic_summary", "") or ""),
        key_findings=key_findings,
        threat_justification=threat_justification,
        entity_extraction=entities,
        attack_vectors_detected=attack_vectors,
        threat_level=_normalize_threat(str(data.get("threat_level", "low"))),
        syllabus_links=syllabus_links,
        timeline_reconstruction=timeline,
        chain_of_custody_log={
            "prompt_hash": prompt_hash,
            "model": "gemini-2.0-flash",
            "timestamp": now,
            "response_length": len(raw),
            "confidence_note": (threat_justification[:500] if threat_justification else "")
            or "Evidence-only system prompt; verify critical claims against raw forensic JSON.",
        },
    )


def generate_vulnerability_explanation(md5_hash: str, m1_hex: str, m2_hex: str, shared_md5: str) -> dict[str, Any]:
    """Phase 6 helper — MD5 collision narrative from Gemini (JSON)."""
    user = VULN_USER_TEMPLATE.format(md5_hash=md5_hash, m1_hex=m1_hex, m2_hex=m2_hex, shared_md5=shared_md5)
    raw = call_gemini(VULN_SYSTEM_PROMPT, user)
    try:
        return extract_json_object(raw)
    except (json.JSONDecodeError, ValueError):
        raw2 = call_gemini(VULN_SYSTEM_PROMPT, "Return ONLY raw JSON, no markdown:\n" + user)
        return extract_json_object(raw2)
