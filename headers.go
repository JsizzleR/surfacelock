package surfacelock

import (
	"fmt"
	"net/http"
	"strings"
)

// Headers are static HTTP request headers a caller attaches to every request an
// http-transport session or proxy backend makes — the channel a token-gated
// upstream needs, and the reason it exists: an MCP endpoint behind an edge
// authenticator refuses an unauthenticated fetch with a transport failure, which
// is an honest error and not a verdict about any surface.
//
// TWO PROPERTIES ARE LOAD-BEARING AND BOTH ARE ENFORCED RATHER THAN DOCUMENTED.
//
//  1. They are NEVER recorded in a lockfile. A credential is not part of a
//     server's reviewed surface, and `tools.lock` is a file people commit.
//     Nothing in lockfile.go reads this type; EntryFromSurface takes transport,
//     target and args, and headers are not among them.
//
//  2. The protocol's own headers WIN. Apply is called before the caller's
//     required headers are Set, so a static "Content-Type", "Mcp-Session-Id" or
//     "MCP-Protocol-Version" cannot displace the value the session computed:
//     session state and framing are the transport's to decide, not an
//     operator's. This is the same order conformance.HTTPConn takes with its
//     Static map, and it is what makes the flag safe to expose.
type Headers map[string]string

// Validate refuses anything that cannot be a header safely. It is deliberately
// stricter than net/http, which accepts a bad value at Set and only fails when
// the request is written — by which point the error names a write, not the
// caller's input.
//
// The name must be a valid HTTP field name; the value must carry no control
// characters at all. A value holding CR or LF is header injection: on an
// interface whose whole purpose is carrying a credential, an injected second
// header is a request the operator did not write.
func (h Headers) Validate() error {
	for name, value := range h {
		if name == "" {
			return fmt.Errorf("header name is empty")
		}
		if !validHeaderName(name) {
			return fmt.Errorf("header name %q is not a valid HTTP field name", name)
		}
		for i := 0; i < len(value); i++ {
			if c := value[i]; c < 0x20 || c == 0x7f {
				return fmt.Errorf("header %q: value carries a control character at byte %d", name, i)
			}
		}
	}
	return nil
}

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
// headers AFTER this returns, so those always win (property 2 above).
func (h Headers) Apply(req *http.Request) {
	for name, value := range h {
		req.Header.Set(name, value)
	}
}
