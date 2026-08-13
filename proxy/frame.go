package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// A frame is one JSON-RPC message crossing the proxy in either direction. Both
// directions are hostile bytes: the server end by the threat model, the client
// end because a compromised client-side config can drive arbitrary frames at a
// server whose responses we then vouch for. Every frame the proxy consumes a
// field from goes through envelope discipline first.

// envelopeKeys are the JSON-RPC members the proxy consumes for routing and
// verification decisions. A case-variant alias or a duplicate of one of these is
// a parser differential: encoding/json (and any sloppy decoder) could route on
// one member while an exact-case reader sees the other, so a frame carrying one
// has no trustworthy identity and is refused/dropped, never forwarded.
var envelopeKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}

var errNotObject = errors.New("frame is not a JSON object")

// checkEnvelope walks the TOP LEVEL of a JSON object and refuses duplicate member
// names and case-variant aliases of the consumed envelope keys. It deliberately
// does not canonicalize: nested content (tool-call arguments, tool results) is not
// consumed by the proxy and may be arbitrarily large, so the check must be a
// single bounded pass over tokens, not a full transform.
func checkEnvelope(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return errNotObject
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return errNotObject
	}
	seen := map[string]bool{}
	depth := 1
	expectKey := true // at depth 1, tokens alternate key / complete value
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("frame does not parse: %w", err)
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 1 {
					expectKey = true // a nested value just closed; next is a key
				}
			}
			continue
		}
		if depth != 1 {
			continue // content of a nested value; not consumed by the proxy
		}
		if !expectKey {
			expectKey = true // a scalar value was consumed; next is a key
			continue
		}
		k, ok := t.(string)
		if !ok {
			return errors.New("frame has a non-string member name")
		}
		if seen[k] {
			return fmt.Errorf("frame has a duplicate top-level member %.32q", k)
		}
		seen[k] = true
		for _, want := range envelopeKeys {
			if k != want && strings.EqualFold(k, want) {
				return fmt.Errorf("frame carries a case-variant of %q: %.32q", want, k)
			}
		}
		expectKey = false // next token is this member's value
	}
	// json.Decoder tracks nesting itself; when the object closes, anything left is
	// trailing content — two documents on one line are not one frame.
	if dec.More() {
		return errors.New("trailing content after the frame")
	}
	return nil
}

// frame is a parsed message envelope. The obj values alias nothing: they are
// copies made by json.Unmarshal, safe to hold after the wire buffer is reused.
type frame struct {
	raw    []byte
	obj    map[string]json.RawMessage
	idKey  string // normalized pending-map key; "" when id is absent
	idRaw  json.RawMessage
	method string // "" when method is absent
}

func (f *frame) isRequest() bool      { return f.method != "" && f.idKey != "" }
func (f *frame) isNotification() bool { return f.method != "" && f.idKey == "" }
func (f *frame) isResponse() bool     { return f.method == "" && f.idKey != "" }

// parseFrame validates the envelope and extracts the routed fields. The returned
// error means the frame has no trustworthy identity and must not be forwarded.
func parseFrame(raw []byte) (*frame, error) {
	if err := checkEnvelope(raw); err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("frame does not parse: %w", err)
	}
	f := &frame{raw: raw, obj: obj}
	if idRaw, ok := obj["id"]; ok && !isJSONNull(idRaw) {
		key, err := idKeyFor(idRaw)
		if err != nil {
			return nil, err
		}
		f.idKey = key
		f.idRaw = idRaw
	}
	if mRaw, ok := obj["method"]; ok {
		var m string
		if err := json.Unmarshal(mRaw, &m); err != nil {
			return nil, errors.New("frame method is not a string")
		}
		if m == "" {
			return nil, errors.New("frame method is empty")
		}
		f.method = m
	}
	return f, nil
}

// idKeyFor normalizes a JSON-RPC id to a pending-map key. Ids are matched by
// exact token with one measured tolerance: some servers echo a numeric id back
// as a string, so responseIDKeys returns both forms for a string id. An id that
// is neither a string nor a number has no reliable identity and is refused.
func idKeyFor(idRaw json.RawMessage) (string, error) {
	var num json.Number
	if err := json.Unmarshal(idRaw, &num); err == nil {
		return "n:" + num.String(), nil
	}
	var s string
	if err := json.Unmarshal(idRaw, &s); err == nil {
		return "s:" + s, nil
	}
	return "", errors.New("frame id is not a string or number")
}

// responseIDKeys returns the pending-map keys an inbound response id may answer:
// its own key, plus the numeric key when a server echoed a number back as a
// string (measured: real servers do this; without the second lookup the response
// would be unmatchable and its surface bytes would have to be dropped).
func responseIDKeys(idRaw json.RawMessage) []string {
	key, err := idKeyFor(idRaw)
	if err != nil {
		return nil
	}
	keys := []string{key}
	if s, ok := strings.CutPrefix(key, "s:"); ok {
		var num json.Number
		if err := json.Unmarshal([]byte(s), &num); err == nil && num.String() == s {
			keys = append(keys, "n:"+s)
		}
	}
	return keys
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})) == "null"
}

// errorFrame builds a JSON-RPC error response the proxy sends in place of a
// refused upstream response (or as the immediate answer to a refused client
// request). The message is built by the caller from non-secret, bounded,
// sanitized parts; this function only assembles the envelope.
func errorFrame(idRaw json.RawMessage, code int, msg string) []byte {
	if idRaw == nil {
		idRaw = json.RawMessage("null")
	}
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      idRaw,
		"error":   map[string]any{"code": code, "message": msg},
	})
	if err != nil {
		// msg is proxy-authored and sanitized; id was parsed from valid JSON.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"surfacelock: internal error building refusal"}}`)
	}
	return b
}

// Proxy-authored JSON-RPC error codes, in the implementation-defined server
// range. Drift and transport refusals are DIFFERENT refusals with different
// remedies and must never share a code (a pipeline or a human reading a client
// log must be able to tell "the surface changed" from "the server is down").
const (
	codeDriftRefused        = -32050 // drift: review, then re-pin
	codeInadmissibleRefused = -32051 // hostile/inadmissible bytes: no verdict possible
	codeTransportFailed     = -32052 // upstream transport failure: honest error, never a drift verdict
	codeProxyRefused        = -32053 // proxy-level refusal of a client frame (caps, unverifiable envelope)
)
