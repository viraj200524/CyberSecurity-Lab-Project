"""
DSTFA Phase 2 — hash computation and Merkle–Damgård stepping (SHA-256, MD5).

Public entry points for integration:
  - get_body_bytes(raw_email)
  - compute_hashes(body_bytes, attachments)
  - build_merkle_damgard_steps(data, algorithm)
  - build_hash_result(body_bytes, attachments)
"""

from __future__ import annotations

import email
import hashlib
import struct
from typing import Any

# --- SHA-256 constants (FIPS 180-4) ---
_SHA256_K: tuple[int, ...] = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

_SHA256_H0: tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


def _rotr32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _sha256_pad(message: bytes) -> bytes:
    bit_len = (len(message) * 8) & ((1 << 64) - 1)
    pad_len = (64 - ((len(message) + 1 + 8) % 64)) % 64
    return message + b"\x80" + (b"\x00" * pad_len) + struct.pack(">Q", bit_len)


def _sha256_compress_block(block: bytes, H: list[int]) -> list[int]:
    assert len(block) == 64
    W: list[int] = [struct.unpack(">I", block[i : i + 4])[0] for i in range(0, 64, 4)]
    for t in range(16, 64):
        s0 = _rotr32(W[t - 15], 7) ^ _rotr32(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = _rotr32(W[t - 2], 17) ^ _rotr32(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = H
    for t in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + S1 + ch + _SHA256_K[t] + W[t]) & 0xFFFFFFFF
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    return [(H[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])]


def _md5_pad(message: bytes) -> bytes:
    bit_len = (len(message) * 8) & ((1 << 64) - 1)
    pad_len = (64 - ((len(message) + 1 + 8) % 64)) % 64
    return message + b"\x80" + (b"\x00" * pad_len) + struct.pack("<Q", bit_len)


def _rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


_MD5_S = (
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
)

# RFC 1321: T[i] = floor(2^32 * abs(sin(i + 1)))
_MD5_T = (
    3614090360,
    3905402710,
    606105819,
    3250441966,
    4118548399,
    1200080426,
    2821735955,
    4249261313,
    1770035416,
    2336552879,
    4294925233,
    2304563134,
    1804603682,
    4254626195,
    2792965006,
    1236535329,
    4129170786,
    3225465664,
    643717713,
    3921069994,
    3593408605,
    38016083,
    3634488961,
    3889429448,
    568446438,
    3275163606,
    4107603335,
    1163531501,
    2850285829,
    4243563512,
    1735328473,
    2368359562,
    4294588738,
    2272392833,
    1839030562,
    4259657740,
    2763975236,
    1272893353,
    4139469664,
    3200236656,
    681279174,
    3936430074,
    3572445317,
    76029189,
    3654602809,
    3873151461,
    530742520,
    3299628645,
    4096336452,
    1126891415,
    2878612391,
    4237533241,
    1700485571,
    2399980690,
    4293915773,
    2240044497,
    1873313359,
    4264355552,
    2734768916,
    1309151649,
    4149444226,
    3174756917,
    718787259,
    3951481745,
)


def _md5_compress_block(block: bytes, state: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    assert len(block) == 64
    X = struct.unpack("<16I", block)
    a, b, c, d = state
    aa, bb, cc, dd = a, b, c, d
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif i < 32:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d))
            g = (7 * i) % 16
        f = (f + a + X[g] + _MD5_T[i]) & 0xFFFFFFFF
        a, b, c, d = d, (b + _rotl32(f, _MD5_S[i])) & 0xFFFFFFFF, b, c
    return (
        (aa + a) & 0xFFFFFFFF,
        (bb + b) & 0xFFFFFFFF,
        (cc + c) & 0xFFFFFFFF,
        (dd + d) & 0xFFFFFFFF,
    )


def _word_hex_sha256(w: int) -> str:
    return f"{w & 0xFFFFFFFF:08x}"


def _word_hex_md5(w: int) -> str:
    return f"{w & 0xFFFFFFFF:08x}"


def _digest_sha256(H: list[int]) -> str:
    return "".join(f"{x:08x}" for x in H)


def _digest_md5(state: tuple[int, int, int, int]) -> str:
    a, b, c, d = state
    return struct.pack("<IIII", a, b, c, d).hex()


def get_body_bytes(raw_email: bytes) -> bytes:
    """Extract a best-effort body payload from raw .eml bytes (text/plain preferred)."""
    msg = email.message_from_bytes(raw_email)

    def _as_bytes(payload: Any) -> bytes:
        if payload is None:
            return b""
        if isinstance(payload, bytes):
            return payload
        return str(payload).encode("utf-8", errors="replace")

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() == "text/plain":
                raw = part.get_payload(decode=True)
                return _as_bytes(raw)
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            raw = part.get_payload(decode=True)
            return _as_bytes(raw)
        return b""

    raw = msg.get_payload(decode=True)
    return _as_bytes(raw)


def compute_hashes(body_bytes: bytes, attachments: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute SHA-256, MD5, SHA-1 for body and each attachment.

    Each attachment dict should include at least: filename, raw_bytes (bytes), size_bytes (optional).
    """
    body = {
        "sha256": hashlib.sha256(body_bytes).hexdigest(),
        "md5": hashlib.md5(body_bytes).hexdigest(),
        "sha1": hashlib.sha1(body_bytes).hexdigest(),
    }
    out_attach: list[dict[str, Any]] = []
    for att in attachments:
        raw = att.get("raw_bytes") or b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw)
        sz = att.get("size_bytes")
        if not isinstance(sz, int) or sz < 0:
            sz = len(raw)
        out_attach.append(
            {
                "filename": str(att.get("filename", "")),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "md5": hashlib.md5(raw).hexdigest(),
                "size_bytes": sz,
            }
        )
    return {"body": body, "attachments": out_attach}


def build_merkle_damgard_steps(data: bytes, algorithm: str) -> dict[str, Any]:
    """
    Build Merkle–Damgård step trace for SHA-256 or MD5.

    SHA-256: 512-bit blocks, big-endian 64-bit bit-length suffix.
    MD5: 512-bit blocks, little-endian 64-bit bit-length suffix.
    """
    alg = algorithm.strip().upper().replace(" ", "")
    if alg in ("SHA256", "SHA-256"):
        return _build_sha256_steps(data)
    if alg == "MD5":
        return _build_md5_steps(data)
    raise ValueError(f"Unsupported Merkle–Damgård algorithm: {algorithm!r}")


def _build_sha256_steps(data: bytes) -> dict[str, Any]:
    orig_len = len(data)
    padded = _sha256_pad(data)
    explanation = (
        "SHA-256 pads the message with a 1 bit (0x80 byte), then zero bits until the "
        "length in bits plus padding occupies a multiple of 512 bits, leaving room for a final "
        "64-bit big-endian bit-length field. Every 512-bit chunk is fed through the compression function."
    )
    H = list(_SHA256_H0)
    blocks_out: list[dict[str, Any]] = []
    for bi in range(0, len(padded), 64):
        chunk = padded[bi : bi + 64]
        block_hex = chunk.hex()
        inp = [_word_hex_sha256(x) for x in H]
        H = _sha256_compress_block(chunk, H)
        outp = [_word_hex_sha256(x) for x in H]
        blocks_out.append(
            {
                "block_index": bi // 64,
                "block_hex": block_hex,
                "input_chaining_vars": inp,
                "output_chaining_vars": outp,
                "rounds_summary": "64 rounds of bitwise operations (Ch, Maj, Σ0, Σ1) mixing the 16 expanded words into eight 32-bit state words.",
            }
        )

    final = _digest_sha256(H)
    ref = hashlib.sha256(data).hexdigest()
    if final != ref:
        raise RuntimeError(f"SHA-256 Merkle–Damgård final mismatch: {final!r} vs {ref!r}")

    return {
        "algorithm": "SHA-256",
        "original_message_length": orig_len,
        "padded_message_length": len(padded),
        "padding_explanation": explanation,
        "blocks": blocks_out,
        "final_hash": final,
    }


def _build_md5_steps(data: bytes) -> dict[str, Any]:
    orig_len = len(data)
    padded = _md5_pad(data)
    explanation = (
        "MD5 pads with 0x80, then zero bytes until the message length in bits is congruent to 448 modulo 512, "
        "then appends the original bit length as a 64-bit little-endian integer. Each 512-bit block updates a 128-bit chaining value (A, B, C, D)."
    )
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    blocks_out: list[dict[str, Any]] = []
    for bi in range(0, len(padded), 64):
        chunk = padded[bi : bi + 64]
        block_hex = chunk.hex()
        inp = [_word_hex_md5(x) for x in state]
        state = _md5_compress_block(chunk, state)
        outp = [_word_hex_md5(x) for x in state]
        blocks_out.append(
            {
                "block_index": bi // 64,
                "block_hex": block_hex,
                "input_chaining_vars": inp,
                "output_chaining_vars": outp,
                "rounds_summary": "Four rounds of 16 steps each using non-linear F, G, H, I and per-step left rotates.",
            }
        )

    final = _digest_md5(state)
    ref = hashlib.md5(data).hexdigest()
    if final != ref:
        raise RuntimeError(f"MD5 Merkle–Damgård final mismatch: {final!r} vs {ref!r}")

    return {
        "algorithm": "MD5",
        "original_message_length": orig_len,
        "padded_message_length": len(padded),
        "padding_explanation": explanation,
        "blocks": blocks_out,
        "final_hash": final,
    }


def _vulnerability_flags(body_bytes: bytes) -> dict[str, Any]:
    has_body = len(body_bytes) > 0

    explanation = (
        "MD5 is broken for collision resistance; SHA-1 is deprecated for collision resistance. "
        "Both use the Merkle–Damgård construction without a modern domain-separation tweak, so length-extension "
        "attacks apply when they are misused as MACs (always prefer HMAC-SHA-256 or a keyed modern primitive)."
    )

    return {
        "md5_detected": has_body,
        "sha1_detected": has_body,
        "length_extension_risk": has_body,
        "weak_hash_explanation": explanation,
    }


def build_hash_result(body_bytes: bytes, attachments: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Full hashes section compatible with ``HashResult`` (plain dict for JSON / Pydantic).

    ``merkle_damgard_steps`` traces SHA-256 over the body bytes (including empty body).
    """
    partial = compute_hashes(body_bytes, attachments)
    merkle = build_merkle_damgard_steps(body_bytes, "SHA-256")
    flags = _vulnerability_flags(body_bytes)
    return {
        "body": partial["body"],
        "attachments": partial["attachments"],
        "merkle_damgard_steps": merkle,
        "vulnerability_flags": flags,
    }
