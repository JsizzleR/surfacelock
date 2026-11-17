package surfacelock

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

// ExactString decodes a JSON string token that encoding/json represents
// exactly. Raw invalid UTF-8 and an unpaired surrogate escape (PairedSurrogates)
// both decode to U+FFFD, so two different wire values would read as one Go
// string while the peer that sent them keeps them apart; such a token is
// refused as inadmissible, never approximated. A token that is not a JSON
// string at all is a plain error ("is not a string"), so each caller keeps its
// own wording for that case. A reader that keys or compares a hostile cursor or
// era decodes it through this function.
func ExactString(raw []byte) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", errors.New("is not a string")
	}
	if !utf8.Valid(raw) {
		return "", inexactError("is not valid UTF-8")
	}
	if !PairedSurrogates(raw) {
		return "", inexactError("has no exact string form (a lone surrogate escape)")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("is not a string")
	}
	return s, nil
}

// inexactError reads as a suffix to the field it names ("cursor has no exact
// string form ...") and is ErrInadmissible to errors.Is.
type inexactError string

func (e inexactError) Error() string { return string(e) }
func (e inexactError) Unwrap() error { return ErrInadmissible }

// PairedSurrogates reports whether every \u escape of a UTF-16 surrogate in a
// JSON string token is one half of a high-low pair. A lone half has no UTF-8
// form: encoding/json decodes it to U+FFFD, a JavaScript or Python peer keeps
// it, so two different names compare equal after decoding. A reader that
// compares a decoded name against another decoder's reading runs this on the
// raw token first. (The JCS canonicalizer is no test for this: measured, it
// refuses "\ud800" at the end of a string and accepts "\ud83d\u0041".)
func PairedSurrogates(raw []byte) bool {
	hex4 := func(at int) (uint64, bool) {
		if at+4 > len(raw) {
			return 0, false
		}
		v, err := strconv.ParseUint(string(raw[at:at+4]), 16, 32)
		return v, err == nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++ // the escaped byte; only \u carries a code unit
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		r, ok := hex4(i + 1)
		if !ok {
			return false
		}
		i += 4 // the last hex digit
		switch {
		case r >= 0xD800 && r <= 0xDBFF:
			if i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
				if lo, ok := hex4(i + 3); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 6
					continue
				}
			}
			return false
		case r >= 0xDC00 && r <= 0xDFFF:
			return false
		}
	}
	return true
}
