"""Test wiring: build the Go CLI once per session and point the bindings at it.

Offline by construction: `go build` against the warm module cache, a local
stdio fixture server, no network. SURFACELOCK_TEST_BIN skips the build (the
wheel-proof venv sets it to the wheel's own bundled binary).
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent.parent
SRC = TESTS.parent / "src"

# When running from the source tree (not an installed wheel), import from src/.
if "surfacelock" not in sys.modules and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def cli_binary(tmp_path_factory: pytest.TempPathFactory) -> str:
    pre = os.environ.get("SURFACELOCK_TEST_BIN")
    if pre:
        return pre
    out = tmp_path_factory.mktemp("bin") / "surfacelock"
    subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/surfacelock"],
        cwd=REPO, check=True, capture_output=True,
    )
    return str(out)


@pytest.fixture(autouse=True)
def _bind_binary(cli_binary: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SURFACELOCK_BIN", cli_binary)


@pytest.fixture
def fixture_argv() -> list:
    return [sys.executable, str(TESTS / "fixture_server.py")]
