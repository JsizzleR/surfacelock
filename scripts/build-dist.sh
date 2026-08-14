#!/bin/sh
# Build the distributable binaries (CGO off, stripped, per platform) into
# dist/bin/<goos>-<goarch>/surfacelock, then pack the Python wheels.
# Windows is deliberately absent: client/ and proxy/ use unix-only
# process-group teardown (syscall.Setpgid / syscall.Kill) and do not compile
# there yet — port first, then add the target here and in build_wheels.py.
set -eu
cd "$(dirname "$0")/.."

for plat in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
	goos=${plat%/*}
	goarch=${plat#*/}
	out="dist/bin/$goos-$goarch/surfacelock"
	mkdir -p "$(dirname "$out")"
	echo "building $plat"
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/surfacelock
done

python3 python/build_wheels.py
