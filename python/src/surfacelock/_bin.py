"""Locating the surfacelock binary.

Order: explicit argument → SURFACELOCK_BIN → the binary bundled in this wheel →
PATH. The bundled binary is the normal case for an installed wheel; the env var
is the dev/test seam; PATH is the fallback for a source checkout beside a
system-installed CLI.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from ._errors import SurfacelockError

_BUNDLED_NAME = "surfacelock.exe" if sys.platform == "win32" else "surfacelock"


def find_binary(explicit: Optional[str] = None) -> str:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise SurfacelockError(f"surfacelock binary not found at {str(p)!r}")
        return str(p)

    env = os.environ.get("SURFACELOCK_BIN")
    if env:
        p = Path(env)
        if not p.is_file():
            raise SurfacelockError(f"SURFACELOCK_BIN points at {env!r}, which is not a file")
        return str(p)

    bundled = Path(__file__).resolve().parent / "_bin" / _BUNDLED_NAME
    if bundled.is_file():
        return str(bundled)

    on_path = shutil.which("surfacelock")
    if on_path:
        return on_path

    raise SurfacelockError(
        "no surfacelock binary: this install carries none for this platform, "
        "SURFACELOCK_BIN is unset, and none is on PATH"
    )
