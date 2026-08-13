package surfacelock

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// DecodeExact decodes a JSON object with exact-key discipline (SPEC.md §3.4): it
// refuses a value that (a) is not canonicalizable — which catches duplicate member
// names at any depth — or (b) carries a case-variant alias of any consumed key.
// encoding/json struct decoding matches field names case-insensitively last-wins,
// so {"instructions":"I","INSTRUCTIONS":"K"} would hash one value while an
// exact-case reader consumes the other — a parser differential that lets one
// (era, hash) pair cover two different prompt-bearing surfaces. Every reader that
// CONSUMES a key from a hostile JSON object goes through this one function.
func DecodeExact(raw json.RawMessage, what string, consumed ...string) (map[string]json.RawMessage, error) {
	if _, err := Canonicalize(raw); err != nil {
		return nil, fmt.Errorf("%s: not canonicalizable: %v", what, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s: not a JSON object: %w", what, err)
	}
	for k := range obj {
		for _, want := range consumed {
			if k != want && strings.EqualFold(k, want) {
				return nil, fmt.Errorf("%s: carries a case-variant of %q: %q", what, want, k)
			}
		}
	}
	return obj, nil
}

// Sanitize renders a string with every control rune (C0, DEL, and other Unicode
// control runes) replaced, so untrusted content — tool names, rpc error strings,
// HTTP body snippets — cannot rewrite the terminal or a CI log that quotes it.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}
