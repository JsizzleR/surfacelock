#!/usr/bin/env python3
"""Build per-platform wheels carrying the surfacelock binary (stdlib only).

The ruff/uv distribution shape without their build backend: each wheel is pure
Python plus one vendored Go binary at surfacelock/_bin/surfacelock, tagged
py3-none-<platform>. Input binaries come from scripts/build-dist.sh
(CGO_ENABLED=0, so the linux binaries are static: one wheel honestly serves
glibc and musl, hence the compound manylinux+musllinux tags).

Deterministic by construction: fixed zip timestamps, sorted entries — the same
inputs produce byte-identical wheels (the same property SPEC.md §4 claims for
the lockfile itself).

Usage: python3 build_wheels.py [--bins ../dist/bin] [--out ../dist/wheels]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import pathlib
import re
import sys
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "src" / "surfacelock"

# (goos, goarch) -> wheel platform tag. Windows is absent because the Go side
# does not build there yet (unix-only process-group teardown in client/ and
# proxy/) — a porting item, not a packaging choice.
PLATFORM_TAGS = {
    ("darwin", "arm64"): "macosx_12_0_arm64",
    ("darwin", "amd64"): "macosx_12_0_x86_64",
    ("linux", "amd64"): "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
    ("linux", "arm64"): "manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64",
}

# Fixed timestamp for reproducibility (zip format cannot express "no time").
ZIP_DATE = (2026, 1, 1, 0, 0, 0)


def read_version() -> str:
    text = (SRC / "__init__.py").read_text()
    m = re.search(r'^__version__ = "([^"]+)"$', text, re.M)
    if not m:
        sys.exit("no __version__ in src/surfacelock/__init__.py")
    return m.group(1)


def metadata(version: str) -> bytes:
    readme = (HERE / "README.md").read_text()
    head = "\n".join(
        [
            "Metadata-Version: 2.4",
            "Name: surfacelock",
            f"Version: {version}",
            "Summary: Pin and verify MCP tool surfaces — tools.lock bindings and CLI",
            "License-Expression: Apache-2.0",
            "Requires-Python: >=3.10",
            "Project-URL: Repository, https://github.com/JsizzleR/surfacelock",
            "Description-Content-Type: text/markdown",
            "",
            "",
        ]
    )
    return (head + readme).encode()


def wheel_file(tag: str) -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: surfacelock-build\n"
        "Root-Is-Purelib: false\n"
        f"Tag: py3-none-{tag}\n"
    ).encode()


ENTRY_POINTS = b"[console_scripts]\nsurfacelock = surfacelock._cli:main\n"


def record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build_wheel(out_dir: pathlib.Path, version: str, tag: str, binary: pathlib.Path) -> pathlib.Path:
    dist_info = f"surfacelock-{version}.dist-info"
    entries: list[tuple[str, bytes, bool]] = []  # (archive name, bytes, executable)

    for py in sorted(SRC.glob("*.py")):
        entries.append((f"surfacelock/{py.name}", py.read_bytes(), False))
    entries.append(("surfacelock/py.typed", b"", False))
    entries.append(("surfacelock/_bin/surfacelock", binary.read_bytes(), True))
    entries.append((f"{dist_info}/METADATA", metadata(version), False))
    entries.append((f"{dist_info}/WHEEL", wheel_file(tag), False))
    entries.append((f"{dist_info}/entry_points.txt", ENTRY_POINTS, False))

    record = "\n".join(record_line(n, d) for n, d, _ in entries)
    record += f"\n{dist_info}/RECORD,,\n"
    entries.append((f"{dist_info}/RECORD", record.encode(), False))

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"surfacelock-{version}-py3-none-{tag}.whl"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, executable in entries:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # unix, so external_attr mode bits apply
            info.external_attr = (0o755 if executable else 0o644) << 16
            zf.writestr(info, data)
    path.write_bytes(buf.getvalue())
    return path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bins", default=str(HERE.parent / "dist" / "bin"))
    ap.add_argument("--out", default=str(HERE.parent / "dist" / "wheels"))
    args = ap.parse_args()

    version = read_version()
    bins = pathlib.Path(args.bins)
    out = pathlib.Path(args.out)
    built = 0
    for (goos, goarch), tag in sorted(PLATFORM_TAGS.items()):
        binary = bins / f"{goos}-{goarch}" / "surfacelock"
        if not binary.is_file():
            print(f"skip {goos}/{goarch}: no binary at {binary}", file=sys.stderr)
            continue
        path = build_wheel(out, version, tag, binary)
        print(f"built {path.name} ({path.stat().st_size} bytes)")
        built += 1
    if built == 0:
        sys.exit("no wheels built: run scripts/build-dist.sh first")


if __name__ == "__main__":
    main()
