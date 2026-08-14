#!/usr/bin/env python3
"""Assemble the npm distribution (stdlib only): one launcher package plus one
platform package per binary, into dist/npm/.

The esbuild/ruff shape: `surfacelock` carries only launcher.js and names every
platform package in optionalDependencies; npm installs the one matching
os/cpu. Package names are UNSCOPED (surfacelock, surfacelock-darwin-arm64, …):
whether to claim an npm scope instead is a publish-time decision that rides
the upload step — nothing is registered by building these.

Version comes from the Python package's __version__ (one source), translated
PEP 440 → semver (0.1.0.dev0 → 0.1.0-dev.0).

Usage: python3 npm/build_npm.py [--bins dist/bin] [--out dist/npm]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent

# (goos, goarch) -> (npm os, npm cpu). Windows is absent for the same reason
# it is absent from the wheels: the Go side does not compile there yet.
NODE_PLATFORMS = {
    ("darwin", "arm64"): ("darwin", "arm64"),
    ("darwin", "amd64"): ("darwin", "x64"),
    ("linux", "arm64"): ("linux", "arm64"),
    ("linux", "amd64"): ("linux", "x64"),
}

DESCRIPTION = "Pin and verify MCP tool surfaces — the tools.lock CLI"
REPO_URL = "https://github.com/JsizzleR/surfacelock"


def npm_version() -> str:
    text = (REPO / "python" / "src" / "surfacelock" / "__init__.py").read_text()
    m = re.search(r'^__version__ = "([^"]+)"$', text, re.M)
    if not m:
        sys.exit("no __version__ in python/src/surfacelock/__init__.py")
    ver = m.group(1)
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:\.dev(\d+))?", ver)
    if not m:
        sys.exit(f"cannot translate version {ver!r} to semver")
    base, dev = m.group(1), m.group(2)
    return f"{base}-dev.{dev}" if dev is not None else base


def write_pkg(pkg_dir: pathlib.Path, manifest: dict) -> None:
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bins", default=str(REPO / "dist" / "bin"))
    ap.add_argument("--out", default=str(REPO / "dist" / "npm"))
    args = ap.parse_args()
    bins = pathlib.Path(args.bins)
    out = pathlib.Path(args.out)
    version = npm_version()

    optional = {}
    for (goos, goarch), (nos, ncpu) in sorted(NODE_PLATFORMS.items()):
        binary = bins / f"{goos}-{goarch}" / "surfacelock"
        if not binary.is_file():
            print(f"skip {goos}/{goarch}: no binary at {binary}", file=sys.stderr)
            continue
        name = f"surfacelock-{nos}-{ncpu}"
        pkg_dir = out / name
        write_pkg(pkg_dir, {
            "name": name,
            "version": version,
            "description": f"{DESCRIPTION} ({nos}/{ncpu} binary)",
            "repository": {"type": "git", "url": f"git+{REPO_URL}.git"},
            "license": "Apache-2.0",
            "os": [nos],
            "cpu": [ncpu],
        })
        (pkg_dir / "bin").mkdir(exist_ok=True)
        dest = pkg_dir / "bin" / "surfacelock"
        shutil.copyfile(binary, dest)
        dest.chmod(0o755)
        optional[name] = version
        print(f"built {name}")

    if not optional:
        sys.exit("no platform packages built: run scripts/build-dist.sh first")

    main_dir = out / "surfacelock"
    write_pkg(main_dir, {
        "name": "surfacelock",
        "version": version,
        "description": DESCRIPTION,
        "repository": {"type": "git", "url": f"git+{REPO_URL}.git"},
        "license": "Apache-2.0",
        "bin": {"surfacelock": "bin/surfacelock.js"},
        "optionalDependencies": optional,
        "engines": {"node": ">=18"},
    })
    (main_dir / "bin").mkdir(exist_ok=True)
    shutil.copyfile(HERE / "launcher.js", main_dir / "bin" / "surfacelock.js")
    (main_dir / "bin" / "surfacelock.js").chmod(0o755)
    print(f"built surfacelock (launcher, {len(optional)} platform deps)")


if __name__ == "__main__":
    main()
