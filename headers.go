package surfacelock

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Headers are static HTTP request headers a caller attaches to every request an
// http-transport session or proxy backend makes — the channel a token-gated
// upstream needs, and the reason it exists: an MCP endpoint behind an edge
// authenticator refuses an unauthenticated fetch with a transport failure, which
// is an honest error and not a verdict about any surface.
//
// THREE PROPERTIES ARE LOAD-BEARING AND ALL THREE ARE ENFORCED RATHER THAN
// DOCUMENTED.
//
//  1. They are NEVER recorded in a lockfile. A credential is not part of a
//     server's reviewed surface, and `tools.lock` is a file people commit.
//     Nothing in lockfile.go reads this type; EntryFromSurface takes transport,
//     target and args, and headers are not among them.
//
//  2. A name the protocol owns cannot be set AT ALL. An earlier draft relied on
//     apply-then-overwrite ordering for this and that was not sufficient: the
//     transport Sets Mcp-Session-Id and MCP-Protocol-Version only when it HAS
//     them, so on the initialize request — the one that decides the dialect —
//     both are empty and a static value went out unopposed, choosing an era the
//     lockfile then recorded without recording why. Ordering cannot make an
//     INTENTIONAL ABSENCE win. reservedNames refuses those names instead, and
//     the apply-first ordering in Apply stays as a second line rather than the
//     only one.
//
//  3. The value cannot be printed by accident. String and GoString render the
//     NAMES and redact every value, so a future `%v` on a struct that carries a
//     Headers — client.Ref and proxy.Config both do — cannot spill a credential
//     into a log. Making the safe rendering the DEFAULT is the point; a
//     convention that each call site must remember is the thing that fails.
type Headers map[string]string

// reservedNames may never be set by a caller. Two different reasons, kept apart
// because they refuse for different lengths of time:
//
//   - PROTOCOL STATE AND FRAMING — the transport owns these, and a caller who
//     sets one is either changing what the session negotiated (Mcp-Session-Id,
//     MCP-Protocol-Version) or breaking how a response is read (Content-Type,
//     Accept). The transport Sets all four, so the value is at best ignored.
//   - net/http DERIVES OR DROPS THESE — Host comes from the URL, and
//     Content-Length, Transfer-Encoding and Trailer are excluded from the
//     written header set. Setting one is a silent no-op whose consequence
//     surfaces as a gateway refusal, i.e. a true statement about the wrong
//     cause, which is exactly what the --header-env unset refusal exists to
//     stop.
//
// User-Agent is deliberately NOT here: the transport Sets it, so a static one
// loses, and unlike the four above there is no correctness claim attached to
// its value — refusing it would be an opinion, not a safety property.
var reservedNames = map[string]string{
	"CONTENT-TYPE":         "the transport owns request framing",
	"ACCEPT":               "the transport owns response negotiation",
	"MCP-SESSION-ID":       "the session owns its own id",
	"MCP-PROTOCOL-VERSION": "the handshake owns the negotiated era",
	"HOST":                 "net/http derives it from the URL",
	"CONTENT-LENGTH":       "net/http derives it from the body",
	"TRANSFER-ENCODING":    "net/http derives it",
	"TRAILER":              "net/http derives it",
}

// Validate refuses anything that cannot be a header safely. It is deliberately
// stricter than net/http, which accepts a bad value at Set and only fails when
// the request is written — by which point the error names a write, not the
// caller's input.
func (h Headers) Validate() error {
	seen := map[string]string{}
	for _, name := range h.sortedNames() {
		value := h[name]
		if name == "" {
			return fmt.Errorf("header name is empty")
		}
		if !validHeaderName(name) {
			return fmt.Errorf("header name %q is not a valid HTTP field name", name)
		}
		// HTTP field names are case-insensitive and Header.Set canonicalizes,
		// so two spellings are ONE header — and with map iteration order
		// unspecified, whichever value won would differ between runs. The CLI
		// refuses this at parse time; a Go caller building the map directly
		// reaches only here.
		fold := strings.ToUpper(name)
		if prev, dup := seen[fold]; dup {
			return fmt.Errorf("headers %q and %q are the same HTTP field name", prev, name)
		}
		seen[fold] = name
		if why, reserved := reservedNames[fold]; reserved {
			return fmt.Errorf("header %q may not be set: %s", name, why)
		}
		// The value must carry no control characters at all. A value holding CR
		// or LF is header injection: on an interface whose whole purpose is
		// carrying a credential, an injected second header is a request the
		// operator did not write.
		for i := 0; i < len(value); i++ {
			if c := value[i]; c < 0x20 || c == 0x7f {
				return fmt.Errorf("header %q: value carries a control character at byte %d", name, i)
			}
		}
		// A blank value is an ABSENT credential wearing a present one's shape:
		// the upstream answers 401 and the operator is told their server is
		// unreachable. Whitespace-only counts as blank — it is bytes 0x20, so
		// the control-character rule above admits it.
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("header %q has a blank value; an absent credential is refused upstream and reported as a transport failure", name)
		}
	}
	return nil
}

// Clone returns an independent copy. Both transports take one at construction:
// the caller keeps a reference to the map it passed, and without this a
// mutation after Validate would both defeat the validation and race the request
// goroutines iterating it — a concurrent map read and write, which is a panic
// rather than a stale read.
func (h Headers) Clone() Headers {
	if h == nil {
		return nil
	}
	c := make(Headers, len(h))
	for k, v := range h {
		c[k] = v
	}
	return c
}

// sortedNames gives Validate a deterministic order, so a map with two problems
// reports the SAME one every time. A validator whose message depends on map
// iteration order is a validator whose failures cannot be regression-tested.
func (h Headers) sortedNames() []string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// String renders the names and redacts every value. See property 3.
func (h Headers) String() string {
	if len(h) == 0 {
		return "surfacelock.Headers{}"
	}
	var b strings.Builder
	b.WriteString("surfacelock.Headers{")
	for i, n := range h.sortedNames() {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q: <redacted>", n)
	}
	b.WriteString("}")
	return b.String()
}

// GoString is String: %#v must redact for the same reason %v must.
func (h Headers) GoString() string { return h.String() }

// validHeaderName reports whether s is an RFC 9110 field-name (a token).
func validHeaderName(s string) bool {
	const tokenExtra = "!#$%&'*+-.^_`|~"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(tokenExtra, c) >= 0:
		default:
			return false
		}
	}
	return len(s) > 0
}

// Apply writes the static headers onto req. Callers Set the protocol's own
// headers AFTER this returns, so those win even for a name reservedNames does
// not cover — two independent mechanisms, because property 2 is the one a
// future header name would silently escape.
func (h Headers) Apply(req *http.Request) {
	for name, value := range h {
		req.Header.Set(name, value)
	}
}
