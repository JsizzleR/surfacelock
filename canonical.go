// Package surfacelock implements the tools.lock format (SPEC.md): pinning an MCP
// server's tool surface — names, schemas, descriptions, server instructions — in a
// reviewable, deterministic lockfile.
//
// Everything a server sends is hostile input. This package fails closed on surfaces
// it cannot admit; the hashes are the authority, never the server's self-report.
package surfacelock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// AbsentSentinel stands in for a hash whose field does not exist (SPEC.md §2).
// Absence is part of the surface: a description appearing where there was none is drift.
const AbsentSentinel = "absent"

// Canonicalize returns the RFC 8785 (JCS) form of a JSON value.
func Canonicalize(raw json.RawMessage) ([]byte, error) {
	return jcs.Transform(raw)
}

// HashCanonical returns "sha256:<hex>" over the RFC 8785 form of a JSON value.
func HashCanonical(raw json.RawMessage) (string, error) {
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	return hashBytes(canon), nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// renderIndented re-indents RFC 8785 canonical bytes with the whitespace-only
// algorithm of SPEC.md §4.1 (encoding/json.Indent, two spaces) and appends one LF.
// Stripping insignificant whitespace from the output yields exactly the input.
func renderIndented(canon []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, canon, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
