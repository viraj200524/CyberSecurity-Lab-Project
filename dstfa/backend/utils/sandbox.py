"""Sandboxed execution of short Python snippets (Phase 6)."""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Any, TypedDict


class SandboxResult(TypedDict):
    stdout: str
    stderr: str
    returncode: int
    execution_time_ms: int
    success: bool


def run_sandboxed(script: str, timeout: int = 10) -> SandboxResult:
    """
    Run ``script`` as ``python -c <script>`` using the current interpreter.

    On timeout: ``success`` is False and stderr describes the timeout.
    """
    start = time.time()
    cmd = [sys.executable, "-c", script]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "stdout": "",
            "stderr": f"Execution timed out after {timeout}s",
            "returncode": -1,
            "execution_time_ms": elapsed_ms,
            "success": False,
        }
    except Exception as e:  # pragma: no cover - platform-specific
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "execution_time_ms": elapsed_ms,
            "success": False,
        }

    elapsed_ms = int((time.time() - start) * 1000)
    return {
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "returncode": result.returncode,
        "execution_time_ms": elapsed_ms,
        "success": result.returncode == 0,
    }
