"""Unit tests for LLM JSON parsing (no live Gemini calls)."""

from __future__ import annotations

import json

import pytest

from services.llm_agent import extract_json_object


def test_extract_json_strips_markdown_fence() -> None:
    raw = """```json
{"forensic_summary": "x", "threat_level": "low"}
```"""
    out = extract_json_object(raw)
    assert out["forensic_summary"] == "x"
    assert out["threat_level"] == "low"


def test_extract_json_from_prose_wrapper() -> None:
    raw = """Here is the analysis:
{"a": 1, "b": {"nested": true}}
Thanks."""
    out = extract_json_object(raw)
    assert out["a"] == 1
    assert out["b"]["nested"] is True


def test_extract_json_invalid_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        extract_json_object("not json")
