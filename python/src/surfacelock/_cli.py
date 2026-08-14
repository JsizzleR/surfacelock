"""Console-script entry point: `surfacelock` / `uvx surfacelock`.

Replaces this process with the bundled binary (execv), so signals, stdio, and
exit codes pass through untranslated — the proxy verb in particular must own
its stdin/stdout and see the client's signals directly. No Python stays
resident between the MCP client and the Go proxy.
"""

from __future__ import annotations

import os
import sys

from ._bin import find_binary
from ._errors import SurfacelockError


def main() -> int:
    try:
        binary = find_binary()
    except SurfacelockError as e:
        print(f"surfacelock: {e}", file=sys.stderr)
        return 2
    os.execv(binary, [binary, *sys.argv[1:]])
    raise AssertionError("unreachable")
