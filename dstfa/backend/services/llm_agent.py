"""Groq LLM forensic agent (OpenAI-compatible chat completions)."""

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
Where relevant, tie findings to cryptography topics (hash functions and Merkle–Damgård, email authentication,
digital signatures, PGP/OpenPGP, S/MIME, X.509 and chain of trust) using plain language — do not refer to
course syllabi, "units", or academic module labels."""

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

6. CRYPTO CONCEPT LINKS: For each relevant cryptographic idea (from the evidence), provide:
- concept: short name (e.g. "DKIM domain alignment")
- explanation: why it matters for this message
- evidence_field: optional pointer to the JSON field or header you relied on

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
  "concept_links": [
    {{ "concept": "string", "explanation": "string", "evidence_field": "string" }}
  ],
  "timeline_reconstruction": [
    {{ "timestamp": "ISO8601", "event": "string", "source": "string" }}
  ]
}}"""


VULN_SYSTEM_PROMPT = """You are a cryptography professor explaining the Merkle-Damgård construction weakness to an advanced undergraduate student.
Be technically precise but clear. Use the actual hash values from the email as evidence for your explanation."""

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
  "concept_note": "one short paragraph tying the demo to hash-function collision resistance (no course or syllabus wording)"
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


def call_groq(system_prompt: str, user_prompt: str) -> str:
    from groq import Groq

    if not (settings.GROQ_API_KEY or "").strip():
        raise ValueError("GROQ_API_KEY is not configured")
    model = (settings.GROQ_MODEL or "llama-3.3-70b-versatile").strip()
    client = Groq(api_key=settings.GROQ_API_KEY)
    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
    )
    choice = completion.choices[0].message
    text = (choice.content or "").strip()
    if not text:
        raise ValueError("Empty response from Groq")
    return text


def _normalize_threat(raw: str) -> str:
    t = (raw or "low").lower().strip()
    return t if t in ("low", "medium", "high", "critical") else "low"


def generate_forensic_explanation(analysis_partial: dict[str, Any]) -> LLMInsights:
    """
    Build forensic JSON payload from non-LLM analysis fields, call Groq, return ``LLMInsights``.
    """
    forensic_json = json.dumps(analysis_partial, indent=2, default=str)
    user = USER_PROMPT_TEMPLATE.format(forensic_data_json=forensic_json)
    prompt_for_hash = f"{SYSTEM_PROMPT}\n\n{user}"
    prompt_hash = hashlib.sha256(prompt_for_hash.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    model_id = (settings.GROQ_MODEL or "llama-3.3-70b-versatile").strip()

    raw = call_groq(SYSTEM_PROMPT, user)
    try:
        data = extract_json_object(raw)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("LLM JSON parse failed, retrying with strict instruction: %s", e)
        retry_user = (
            "Respond with ONLY valid raw JSON matching the schema from the prior instruction. "
            "No markdown fences, no commentary before or after the JSON.\n\n" + user
        )
        raw2 = call_groq(SYSTEM_PROMPT, retry_user)
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

    raw_links = data.get("concept_links") or data.get("syllabus_links") or []
    if not isinstance(raw_links, list):
        raw_links = []
    concept_links: list[dict[str, Any]] = [x for x in raw_links if isinstance(x, dict)]

    timeline = data.get("timeline_reconstruction") or []
    if not isinstance(timeline, list):
        timeline = []

    threat_justification = str(data.get("threat_justification", "") or "")

    return LLMInsights(
        model_used=model_id,
        timestamp=now,
        forensic_summary=str(data.get("forensic_summary", "") or ""),
        key_findings=key_findings,
        threat_justification=threat_justification,
        entity_extraction=entities,
        attack_vectors_detected=attack_vectors,
        threat_level=_normalize_threat(str(data.get("threat_level", "low"))),
        concept_links=concept_links,
        timeline_reconstruction=timeline,
        chain_of_custody_log={
            "prompt_hash": prompt_hash,
            "model": model_id,
            "provider": "groq",
            "timestamp": now,
            "response_length": len(raw),
            "confidence_note": (threat_justification[:500] if threat_justification else "")
            or "Evidence-only system prompt; verify critical claims against raw forensic JSON.",
        },
    )


def generate_vulnerability_explanation(md5_hash: str, m1_hex: str, m2_hex: str, shared_md5: str) -> dict[str, Any]:
    """Phase 6 helper — MD5 collision narrative from Groq (JSON)."""
    user = VULN_USER_TEMPLATE.format(md5_hash=md5_hash, m1_hex=m1_hex, m2_hex=m2_hex, shared_md5=shared_md5)
    raw = call_groq(VULN_SYSTEM_PROMPT, user)
    try:
        return extract_json_object(raw)
    except (json.JSONDecodeError, ValueError):
        raw2 = call_groq(VULN_SYSTEM_PROMPT, "Return ONLY raw JSON, no markdown:\n" + user)
        return extract_json_object(raw2)
