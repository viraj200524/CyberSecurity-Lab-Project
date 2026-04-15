"""Tests for ``hash_engine`` (PRD §9.3)."""

from __future__ import annotations

import hashlib

from services.hash_engine import build_hash_result, build_merkle_damgard_steps


def test_sha256_step_count() -> None:
    """PRD §9.3 — SHA-256 Merkle-Damgård stepping uses 64-byte (512-bit) blocks.

    A 119-byte message pads to exactly 128 bytes (two blocks). A 128-byte message pads to
    192 bytes (three blocks); the informal “128-byte => 2 blocks” line in the PRD does not
    match FIPS 180-4 padding.
    """
    assert len(build_merkle_damgard_steps(b"x" * 119, "SHA-256")["blocks"]) == 2
    assert len(build_merkle_damgard_steps(b"x" * 64, "SHA-256")["blocks"]) == 2
    assert len(build_merkle_damgard_steps(b"x" * 128, "SHA-256")["blocks"]) == 3


def test_md5_vulnerability_flag() -> None:
    """PRD §9.3 — MD5 on a non-empty body sets ``md5_detected``; empty body clears it; explanation always present."""
    r = build_hash_result(b"hello", [])
    assert r["vulnerability_flags"]["md5_detected"] is True
    assert r["vulnerability_flags"]["sha1_detected"] is True
    assert r["vulnerability_flags"]["length_extension_risk"] is True
    assert r["vulnerability_flags"]["weak_hash_explanation"]

    empty = build_hash_result(b"", [])
    assert empty["vulnerability_flags"]["md5_detected"] is False
    assert empty["vulnerability_flags"]["sha1_detected"] is False
    assert empty["vulnerability_flags"]["length_extension_risk"] is False
    assert empty["vulnerability_flags"]["weak_hash_explanation"]


def test_merkle_damgard_final_hash_matches() -> None:
    """Step-wise Merkle–Damgård digests must match ``hashlib``."""
    data = b"The quick brown fox jumps over the lazy dog."
    sha = build_merkle_damgard_steps(data, "SHA-256")
    assert sha["final_hash"] == hashlib.sha256(data).hexdigest()

    md = build_merkle_damgard_steps(data, "MD5")
    assert md["final_hash"] == hashlib.md5(data).hexdigest()
