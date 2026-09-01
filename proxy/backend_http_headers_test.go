package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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

// TestHTTPBackendProtocolHeadersOverrideStatic proves the ordering at the wire
// rather than on a bare *http.Request: an operator must not be able to pin a
// session id or break framing through the credential channel.
func TestHTTPBackendProtocolHeadersOverrideStatic(t *testing.T) {
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

	b, err := newHTTPBackend(ts.URL, surfacelock.Headers{
		"Content-Type":  "text/plain",
		"Authorization": "Bearer tok",
	}, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatal(err)
	}
	h := <-got
	if ct := h.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want the transport's own value to win", ct)
	}
	if a := h.Get("Authorization"); a != "Bearer tok" {
		t.Errorf("Authorization = %q, want it preserved", a)
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
