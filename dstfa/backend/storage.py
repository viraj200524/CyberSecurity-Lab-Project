"""In-memory stores for uploads and completed analyses (Phase 1+ / Phase 7 cleanup)."""

from __future__ import annotations

import time

# TTL for automatic eviction (Phase 7.6)
STORE_TTL_SECONDS = 3600

upload_store: dict[str, bytes] = {}
_upload_created: dict[str, float] = {}

analysis_store: dict[str, dict] = {}
_analysis_created: dict[str, float] = {}


def store_upload(upload_id: str, raw: bytes) -> None:
    upload_store[upload_id] = raw
    _upload_created[upload_id] = time.monotonic()


def store_analysis(analysis_id: str, payload: dict) -> None:
    analysis_store[analysis_id] = payload
    _analysis_created[analysis_id] = time.monotonic()


def cleanup_old_entries() -> None:
    """Remove uploads and analyses older than STORE_TTL_SECONDS."""
    cutoff = time.monotonic() - STORE_TTL_SECONDS
    for uid, ts in list(_upload_created.items()):
        if ts < cutoff:
            upload_store.pop(uid, None)
            _upload_created.pop(uid, None)
    for aid, ts in list(_analysis_created.items()):
        if ts < cutoff:
            analysis_store.pop(aid, None)
            _analysis_created.pop(aid, None)
