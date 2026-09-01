package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JsizzleR/surfacelock"
)

// TestHTTPBackendSendsStaticHeadersOnEVERYRequest is the reason the static
// headers exist and the reason they are applied in one constructor. The backend
// makes requests by three different methods and a credential absent from any
// one of them fails DIFFERENTLY: a missing POST header is a visible 401 the
// operator reads as a transport failure; a missing GET header silently kills
// the notification stream, so `notifications/tools/list_changed` never arrives
// and mid-session re-verification — the thing the proxy exists for — never
// runs; a missing DELETE header leaks a session on the upstream and reports
// nothing at all, because that teardown's failure is swallowed by design.
//
// The assertion is therefore PER METHOD. A test that only checked "some
// request carried it" passes with two of the three defects present.
func TestHTTPBackendSendsStaticHeadersOnEVERYRequest(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // method -> Authorization

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if _, dup := seen[r.Method]; !dup {
			seen[r.Method] = r.Header.Get("Authorization")
		}
		mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			// Hold the SSE stream open; the request is what this asserts on.
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Mcp-Session-Id", "sess-1") // makes Close send the DELETE
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
		}
	}))
	t.Cleanup(ts.Close)

	b, err := newHTTPBackend(ts.URL, surfacelock.Headers{"Authorization": "Bearer tok"},
		func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatal(err)
	}
	collectFrame(t, b.Frames())
	b.StartNotificationStream()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); _, ok := seen[http.MethodGet]; return ok },
		"the notification GET never arrived")
	b.Close() // sends the teardown DELETE, then waits
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); _, ok := seen[http.MethodDelete]; return ok },
		"the teardown DELETE never arrived")

	mu.Lock()
	defer mu.Unlock()
	for _, m := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		got, ok := seen[m]
		if !ok {
			t.Errorf("%s request was never made — this leg cannot speak for it", m)
			continue
		}
		if got != "Bearer tok" {
			t.Errorf("%s carried Authorization %q, want %q", m, got, "Bearer tok")
		}
	}
}

// TestHTTPBackendCannotSetATransportOwnedHeader replaces an earlier leg that
// proved the apply-then-overwrite ORDERING at the wire. That leg is gone
// because the property it tested is gone: every header the transport sets is
// now reserved, so there is no name left for a caller to lose the race on. The
// re-verify layer is why — accepted-then-ignored is the same silent drop this
// change refuses everywhere else, and it also made the reflection scan look for
// a value that was never transmitted.
//
// What survives is the stronger statement: the caller cannot set one at all,
// and a name the transport does NOT touch is delivered untouched.
func TestHTTPBackendCannotSetATransportOwnedHeader(t *testing.T) {
	got := make(chan http.Header, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Clone():
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(ts.Close)

	if _, err := newHTTPBackend(ts.URL, surfacelock.Headers{"User-Agent": "operator-chosen/9"},
		func(string, ...any) {}, func() {}); err == nil {
		t.Fatal("a transport-owned header was admitted")
	}

	// The control: a name the transport never sets arrives exactly as given, so
	// the refusal above is about ownership and not about headers being dropped.
	b, err := newHTTPBackend(ts.URL, surfacelock.Headers{"Authorization": "Bearer tok"},
		func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatal(err)
	}
	h := <-got
	if a := h.Get("Authorization"); a != "Bearer tok" {
		t.Errorf("Authorization = %q, want it delivered untouched", a)
	}
	if ua := h.Get("User-Agent"); ua != "surfacelock-proxy/0.1" {
		t.Errorf("User-Agent = %q, want the transport's own", ua)
	}
}

// TestNewHTTPBackendRefusesReservedNames: ordering cannot make an INTENTIONAL
// ABSENCE win — the transport Sets Mcp-Session-Id and MCP-Protocol-Version only
// when it HAS them, so on the initialize request both are empty and a static
// value would go out unopposed, choosing a dialect the lockfile then records
// without recording why. These are refused, not merely outranked.
func TestNewHTTPBackendRefusesReservedNames(t *testing.T) {
	for _, name := range []string{"Content-Type", "Accept", "Mcp-Session-Id", "MCP-Protocol-Version", "mcp-protocol-version", "Host", "Content-Length"} {
		if _, err := newHTTPBackend("http://example/mcp", surfacelock.Headers{name: "v"},
			func(string, ...any) {}, func() {}); err == nil {
			t.Errorf("newHTTPBackend admitted the reserved header %q", name)
		}
	}
}

func TestNewHTTPBackendRefusesInjectedHeaders(t *testing.T) {
	// Validation at CONSTRUCTION, not at write time: a library caller that is
	// not the CLI (Bastle's capture is one) gets the refusal before any request.
	if _, err := newHTTPBackend("http://example/mcp",
		surfacelock.Headers{"Authorization": "Bearer x\r\nX-Evil: 1"},
		func(string, ...any) {}, func() {}); err == nil {
		t.Fatal("newHTTPBackend admitted a CRLF-injected header value")
	}
}

// TestEveryHTTPRequestInThisFileIsBuiltByNewRequest is the inventory gate
// (the guard-has-the-same-bypass-problem rule): the property is not "the three
// sites I edited call Apply", it is "no request is built any other way". A
// fourth request path added later — a HEAD probe, a retry — would be written
// the way the three were BEFORE this change and would silently omit the
// credential. Counting occurrences, never grep -q, so a second raw site is
// caught even while the first is still there.
func TestEveryHTTPRequestInThisFileIsBuiltByNewRequest(t *testing.T) {
	src, err := os.ReadFile("backend_http.go")
	if err != nil {
		t.Fatal(err)
	}
	raw := regexp.MustCompile(`http\.NewRequest(WithContext)?\(`).FindAllIndex(src, -1)
	// Exactly one: the one inside (*httpBackend).newRequest.
	if len(raw) != 1 {
		t.Fatalf("backend_http.go builds %d raw http requests, want exactly 1 (inside newRequest); "+
			"every request must go through newRequest so it carries the static headers", len(raw))
	}
	inNewRequest := regexp.MustCompile(`(?s)func \(b \*httpBackend\) newRequest\(.*?\n\}`).Find(src)
	if inNewRequest == nil {
		t.Fatal("(*httpBackend).newRequest is gone; this gate no longer means anything")
	}
	if !regexp.MustCompile(`http\.NewRequestWithContext\(`).Match(inNewRequest) {
		t.Fatal("the one raw request is not the one inside newRequest")
	}
	if !regexp.MustCompile(`b\.headers\.Apply\(req\)`).Match(inNewRequest) {
		t.Fatal("newRequest no longer applies the static headers")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	// Adaptive rather than tuned: poll until a generous ceiling, fail with the
	// stated reason rather than sleeping a guessed interval once.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestHTTPBackendDoesNotFollowARedirect is the exfiltration leg. net/http's
// default client follows up to 10 redirects and strips only six credential
// header names, comparing HOSTNAMES — so `Authorization` survives to a
// subdomain, to another port and from https to http, and a vendor name like
// `X-Api-Key` survives to an unrelated host entirely. The upstream chooses the
// Location, and the upstream is the thing this proxy exists to distrust.
//
// The leg asserts the CREDENTIAL NEVER ARRIVES at the second server, not merely
// that the request failed: a proxy that failed for some other reason would
// satisfy a status-only assertion while still having sent the token.
func TestHTTPBackendDoesNotFollowARedirect(t *testing.T) {
	var mu sync.Mutex
	var collectorSaw []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		collectorSaw = append(collectorSaw, r.Header.Get("X-Api-Key")+"|"+r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, collector.URL+"/collect", http.StatusFound)
	}))
	t.Cleanup(upstream.Close)

	var findings []string
	b, err := newHTTPBackend(upstream.URL, surfacelock.Headers{
		"Authorization": "Bearer tok",
		"X-Api-Key":     "vendor-key",
	}, func(f string, a ...any) { mu.Lock(); findings = append(findings, fmt.Sprintf(f, a...)); mu.Unlock() },
		func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatal(err)
	}
	frame := collectFrame(t, b.Frames())

	mu.Lock()
	defer mu.Unlock()
	if len(collectorSaw) != 0 {
		t.Fatalf("the redirect target received %d request(s) carrying %v", len(collectorSaw), collectorSaw)
	}
	// And the 3xx is reported honestly, as a transport failure naming the status
	// — never as drift, and never as a silent retarget.
	if !bytes.Contains(frame, []byte("302")) {
		t.Fatalf("the redirect was not reported to the client as a transport failure: %s", frame)
	}
}

// TestProxyRefusesHeadersWithABackendOverride: newHTTPBackend is the only
// constructor that validates, and a Config carrying a Backend override never
// reaches it — so without the hoisted check a caller's credential is dropped,
// unvalidated, in silence. That is the one posture every other arm of this
// change refuses.
func TestProxyRefusesHeadersWithABackendOverride(t *testing.T) {
	_, err := Run(context.Background(), Config{
		Name:    "e",
		Entry:   &surfacelock.ServerLock{Transport: "http", Target: "http://example/mcp"},
		Headers: surfacelock.Headers{"Authorization": "Bearer tok"},
		Backend: newFakeBackend(),
	}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("Run honoured neither the headers nor a refusal")
	}
	if strings.Contains(err.Error(), "Bearer tok") {
		t.Fatalf("the refusal echoed the credential: %v", err)
	}
}

// TestProxyRefusesHeadersOnAStdioEntry: the library half of the CLI refusal.
func TestProxyRefusesHeadersOnAStdioEntry(t *testing.T) {
	_, err := Run(context.Background(), Config{
		Name:    "e",
		Entry:   &surfacelock.ServerLock{Transport: "stdio", Target: "/bin/echo"},
		Headers: surfacelock.Headers{"Authorization": "Bearer tok"},
	}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("Run dropped headers on a stdio entry instead of refusing")
	}
	if !strings.Contains(err.Error(), "stdio") {
		t.Fatalf("error = %v, want one naming the transport", err)
	}
	// AND IT NAMES THE ENTRY, not the transport twice. The first draft printed
	// cfg.Entry.Transport in the %q slot, so the message read `entry "stdio" is
	// stdio` — which tells an operator with a many-entry lockfile nothing about
	// WHICH entry to fix.
	if !strings.Contains(err.Error(), `"e"`) {
		t.Fatalf("error = %v, want one naming the entry", err)
	}
}

// TestProxyRefusesAnInvalidHeaderSet asserts exactly what its body checks: an
// invalid set is refused by Run. It does NOT speak to WHERE the check sits — an
// earlier comment here claimed the refusal was hoisted above the findings
// goroutine "so a refused Run leaks nothing", which this body cannot see and a
// mutant moving Validate below `go c.drainFindings()` would survive. Naming a
// property no leg checks is how a suite comes to be believed for things it
// never tested.
func TestProxyRefusesAnInvalidHeaderSet(t *testing.T) {
	_, err := Run(context.Background(), Config{
		Name:    "e",
		Entry:   &surfacelock.ServerLock{Transport: "http", Target: "http://example/mcp"},
		Headers: surfacelock.Headers{"Mcp-Session-Id": "pinned"},
	}, strings.NewReader(""), io.Discard)
	if err == nil {
		t.Fatal("Run admitted a reserved header name")
	}
	if !strings.Contains(err.Error(), "Config.Headers") {
		t.Fatalf("error = %v, want one naming the field at fault", err)
	}
}
