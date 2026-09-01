package surfacelock

import (
	"fmt"
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
		{"blank value", Headers{"X-A": ""}, "blank value"},
		{"whitespace-only value", Headers{"X-A": "   "}, "blank value"},
		{"reserved: framing", Headers{"Content-Type": "text/plain"}, "may not be set"},
		{"reserved: negotiation", Headers{"Accept": "text/plain"}, "may not be set"},
		{"reserved: session state", Headers{"Mcp-Session-Id": "pinned"}, "may not be set"},
		{"reserved: the negotiated era", Headers{"MCP-Protocol-Version": "2024-11-05"}, "may not be set"},
		{"reserved, lowercase spelling", Headers{"mcp-protocol-version": "2024-11-05"}, "may not be set"},
		{"derived by net/http: Host", Headers{"Host": "other"}, "may not be set"},
		{"derived by net/http: Content-Length", Headers{"Content-Length": "9"}, "may not be set"},
		{"case-variant duplicate", Headers{"Authorization": "a", "authorization": "b"}, "same HTTP field name"},
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

// TestHeadersValidateIsDeterministicOverAMapWithTwoProblems: map iteration
// order is unspecified, so a validator that reported whichever it hit first
// would have an untestable message. Names are sorted before checking.
func TestHeadersValidateIsDeterministicOverAMapWithTwoProblems(t *testing.T) {
	h := Headers{"Content-Type": "text/plain", "Zzz-Bad Name": "v"}
	first := h.Validate()
	if first == nil {
		t.Fatal("precondition: the map has two problems and neither was refused")
	}
	for i := 0; i < 50; i++ {
		if got := h.Validate(); got.Error() != first.Error() {
			t.Fatalf("Validate is order-dependent: %v then %v", first, got)
		}
	}
}

// TestHeadersRedactValuesWhenPrinted: client.Ref and proxy.Config both carry a
// Headers, so ONE `%v` on either would spill a credential into a log. The safe
// rendering has to be the default, not a convention every call site remembers.
func TestHeadersRedactValuesWhenPrinted(t *testing.T) {
	h := Headers{"Authorization": "Bearer SECRET-abc", "X-Api-Key": "SECRET-key"}
	for _, got := range []string{
		fmt.Sprintf("%v", h), fmt.Sprintf("%s", h), fmt.Sprintf("%#v", h),
		fmt.Sprintf("%v", struct{ H Headers }{h}), // the shape that actually happens
		h.String(), h.GoString(),
	} {
		if strings.Contains(got, "SECRET") {
			t.Errorf("a value leaked into %q", got)
		}
		if !strings.Contains(got, "Authorization") {
			t.Errorf("the NAMES should survive (they are what makes the log useful): %q", got)
		}
	}
}

// TestHeadersCloneIsIndependent: both transports clone at construction, so a
// caller mutating its own map afterwards can neither defeat the validation nor
// race the goroutines iterating it (a concurrent map read and write is a panic,
// not a stale read).
func TestHeadersCloneIsIndependent(t *testing.T) {
	orig := Headers{"Authorization": "Bearer a"}
	c := orig.Clone()
	orig["Authorization"] = "Bearer b"
	orig["X-Added"] = "later"
	if c["Authorization"] != "Bearer a" {
		t.Fatalf("clone followed the original: %q", c["Authorization"])
	}
	if _, added := c["X-Added"]; added {
		t.Fatal("clone gained a key added to the original afterwards")
	}
	if Headers(nil).Clone() != nil {
		t.Fatal("a nil Headers should clone to nil, not to an empty map")
	}
}

func TestHeadersApplyIsOverriddenByTheProtocolsOwnHeaders(t *testing.T) {
	// The ordering property the whole flag rests on: Apply runs FIRST and the
	// transport's own Set calls run after, so an operator cannot displace
	// session state or framing. A mutant that moved Apply after them would make
	// this fail on all three names.
	// User-Agent rather than the protocol names: those are REFUSED outright now
	// (reservedNames), because ordering cannot make an intentional ABSENCE win
	// — on the initialize request the transport has no session id or era to
	// Set, so there is nothing there to outrank a static one. This leg is the
	// SECOND line of defence, on a name the transport sets unconditionally and
	// does not reserve.
	req := httptest.NewRequest(http.MethodPost, "http://example/mcp", nil)
	Headers{
		"User-Agent":    "operator-chosen/9",
		"Authorization": "Bearer t",
	}.Apply(req)
	// Exactly what the transports do after calling Apply.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "surfacelock/0.1")

	for _, tc := range []struct{ name, want string }{
		{"User-Agent", "surfacelock/0.1"},
		{"Content-Type", "application/json"},
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
