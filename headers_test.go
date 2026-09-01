package surfacelock

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeadersValidateRefusesInjectionAndBadNames(t *testing.T) {
	// Each case is a DISTINCT refusal reason, named, so a future relaxation of
	// one cannot quietly take the others with it.
	for _, tc := range []struct {
		name    string
		h       Headers
		wantErr string
	}{
		{"CR injects a second header", Headers{"Authorization": "Bearer x\rX-Evil: 1"}, "control character"},
		{"LF injects a second header", Headers{"Authorization": "Bearer x\nX-Evil: 1"}, "control character"},
		{"CRLF pair", Headers{"Authorization": "Bearer x\r\nX-Evil: 1"}, "control character"},
		{"NUL", Headers{"X-A": "a\x00b"}, "control character"},
		{"DEL", Headers{"X-A": "a\x7fb"}, "control character"},
		{"ESC (terminal control, printable-looking)", Headers{"X-A": "a\x1b[2Jb"}, "control character"},
		{"empty name", Headers{"": "v"}, "empty"},
		{"space in name", Headers{"X A": "v"}, "not a valid HTTP field name"},
		{"colon in name", Headers{"X:A": "v"}, "not a valid HTTP field name"},
		{"newline in name", Headers{"X\nA": "v"}, "not a valid HTTP field name"},
		{"non-ASCII name", Headers{"X-Ä": "v"}, "not a valid HTTP field name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.h.Validate()
			if err == nil {
				t.Fatalf("Validate() admitted %q", tc.h)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}
}

func TestHeadersValidateAdmitsOrdinaryCredentials(t *testing.T) {
	// The control for the table above: without this, a Validate that refused
	// EVERYTHING would pass every case there.
	h := Headers{
		"Authorization": "Bearer eyJhbGciOi.J9-_~+/=",
		"X-Api-Key":     "k",
		"Cookie":        "a=1; b=2",
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate() refused an ordinary credential set: %v", err)
	}
}

func TestHeadersApplyIsOverriddenByTheProtocolsOwnHeaders(t *testing.T) {
	// The ordering property the whole flag rests on: Apply runs FIRST and the
	// transport's own Set calls run after, so an operator cannot displace
	// session state or framing. A mutant that moved Apply after them would make
	// this fail on all three names.
	req := httptest.NewRequest(http.MethodPost, "http://example/mcp", nil)
	Headers{
		"Content-Type":         "text/plain",
		"Mcp-Session-Id":       "attacker-chosen",
		"MCP-Protocol-Version": "1999-01-01",
		"Authorization":        "Bearer t",
	}.Apply(req)
	// Exactly what the transports do after calling Apply.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", "real-session")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")

	for _, tc := range []struct{ name, want string }{
		{"Content-Type", "application/json"},
		{"Mcp-Session-Id", "real-session"},
		{"MCP-Protocol-Version", "2025-11-25"},
		{"Authorization", "Bearer t"}, // the one the transport never sets survives
	} {
		if got := req.Header.Get(tc.name); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHeadersApplyIsCaseInsensitiveAboutFieldNames(t *testing.T) {
	// Set canonicalizes, so a lowercase spelling from a config file reaches the
	// wire under the canonical name and is NOT sent twice.
	req := httptest.NewRequest(http.MethodPost, "http://example/mcp", nil)
	Headers{"authorization": "Bearer t"}.Apply(req)
	if got := req.Header.Get("Authorization"); got != "Bearer t" {
		t.Fatalf("Authorization = %q, want the value set under a lowercase name", got)
	}
	if n := len(req.Header["Authorization"]); n != 1 {
		t.Fatalf("Authorization has %d values, want 1", n)
	}
}

func TestNilHeadersApplyAndValidateAreNoOps(t *testing.T) {
	// The zero value is the common case (every caller that sends nothing).
	var h Headers
	if err := h.Validate(); err != nil {
		t.Fatalf("nil Headers.Validate() = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://example/mcp", nil)
	h.Apply(req)
	if len(req.Header) != 0 {
		t.Fatalf("nil Headers.Apply wrote %v", req.Header)
	}
}
