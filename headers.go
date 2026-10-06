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
//  1. This package never COPIES one into a lockfile. Nothing in lockfile.go
//     reads this type; EntryFromSurface takes transport, target and args, and
//     headers are not among them. THAT IS THE WHOLE OF THE CLAIM, and it is
//     narrower than "a credential can never reach a lockfile": a server that
//     ECHOES what it was sent — into `instructions`, or a tool description —
//     gets those bytes recorded verbatim, because recording the served surface
//     is the format's job. Measured, not argued. The CLI refuses to WRITE such
//     a lockfile (refuseReflectedCredential), which is a guard at one boundary
//     and not an invariant of this type: a Go caller that renders its own
//     lockfile is on its own.
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
//  3. fmt cannot print the value by accident. String and GoString render the
//     NAMES and redact every value, so a future `%v` or `%+v` on a struct that
//     carries a Headers — client.Ref and proxy.Config both do — cannot spill a
//     credential into a log. Making the safe rendering the DEFAULT is the
//     point; a convention that each call site must remember is what fails.
//     SCOPED TO fmt, deliberately: a Stringer is invisible to encoding/json
//     and to slog's JSONHandler, both of which would serialize the map's
//     values. Nothing in this module marshals either struct — checked — but
//     the type cannot stop a caller who does.
type Headers map[string]string

// reservedNames may never be set by a caller. Two different reasons, kept apart
// because they refuse for different lengths of time:
//
//   - PROTOCOL STATE AND FRAMING — the transport owns these, and a caller who
//     sets one is either changing what the session negotiated (Mcp-Session-Id,
//     MCP-Protocol-Version) or breaking how a response is read (Content-Type,
//     Accept). Do NOT read this as "the transport overwrites them anyway": it
//     Sets the session pair only when it HAS them (empty on the initialize
//     request), Content-Type only on a POST and Accept not on the DELETE, so
//     absent this refusal a static value is HONOURED on exactly the requests
//     that matter. That is the same misreading property 2 exists to correct,
//     and this sentence said it in the first draft.
//   - THE TRANSPORT ALWAYS SETS THESE, so a static one is accepted and then
//     silently ignored — which is the same silent-drop this change refuses
//     everywhere else. Refusing is the honest answer: the caller learns their
//     header does nothing instead of believing it was sent.
//   - net/http DERIVES OR DROPS THESE — Host comes from the URL, and
//     Content-Length, Transfer-Encoding and Trailer are excluded from the
//     written header set. Setting one is a silent no-op whose consequence
//     surfaces as a gateway refusal, i.e. a true statement about the wrong
//     cause, which is exactly what the --header-env unset refusal exists to
//     stop.
//
// An earlier draft admitted User-Agent, reasoning that a static one merely
// loses to the transport's. The re-verify layer refuted that: accepted-then-
// ignored IS the silent drop, and it also means the reflection scan looks for a
// value that was never transmitted. It is reserved.
var reservedNames = map[string]string{
	"CONTENT-TYPE":         "the transport owns request framing",
	"ACCEPT":               "the transport owns response negotiation",
	"ACCEPT-ENCODING":      "the transport owns content coding (setting it disables net/http's automatic decompression)",
	"USER-AGENT":           "the transport sets it, so a static one is accepted and then ignored",
	"MCP-SESSION-ID":       "the session owns its own id",
	"MCP-PROTOCOL-VERSION": "the handshake owns the negotiated era",
	"MCP-METHOD":           "the transport mirrors it from the request body",
	"MCP-NAME":             "the transport mirrors it from the request body",
	"LAST-EVENT-ID":        "the stream owns its own resume position",
	"HOST":                 "net/http derives it from the URL",
	"CONTENT-LENGTH":       "net/http derives it from the body",
	"TRANSFER-ENCODING":    "net/http derives it",
	"TRAILER":              "net/http derives it",
	// Hop-by-hop controls: these govern the connection rather than the request,
	// and net/http owns the connection.
	"CONNECTION":       "net/http owns the connection",
	"KEEP-ALIVE":       "net/http owns the connection",
	"PROXY-CONNECTION": "net/http owns the connection",
	"TE":               "net/http owns transfer coding negotiation",
	"UPGRADE":          "net/http owns protocol upgrades",
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
// mutation AFTER Validate would both defeat the validation and race the request
// goroutines iterating it — a concurrent map read and write, which is a panic
// rather than a stale read.
//
// It does not, and cannot, cover a caller mutating the map DURING Validate or
// Clone. The ownership rule is the ordinary Go one and is stated rather than
// enforced: do not write to a Headers you have handed to this package.
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
// headers AFTER this returns, so a name the transport sets UNCONDITIONALLY is
// overwritten. That ordering is a description, not a defence: a protocol header
// set CONDITIONALLY is absent exactly when it matters, and only reservedNames
// closes that. See property 2.
func (h Headers) Apply(req *http.Request) {
	for name, value := range h {
		req.Header.Set(name, value)
	}
}
