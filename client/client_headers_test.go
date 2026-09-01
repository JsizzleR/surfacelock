package client

import (
	"context"
	"encoding/json"
	"fmt"
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

// mcpFixture answers a full modern handshake and one tools/list page, recording
// the first Authorization value seen per method.
func mcpFixture(t *testing.T, seen map[string]string, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if _, dup := seen[r.Method]; !dup {
			seen[r.Method] = r.Header.Get("Authorization")
		}
		mu.Unlock()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "sess-1")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fx","version":"0"}}}`, req.ID)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"t","description":"d","inputSchema":{"type":"object"}}]}}`, req.ID)
		default:
			if len(req.ID) == 0 || string(req.ID) == "null" {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestFetchSendsStaticHeadersOnEveryRequest covers the capture path — the one
// Bastle's deploy-gate attestation uses. Asserted per METHOD: the session
// teardown DELETE is a separate request builder and its failure is silent.
func TestFetchSendsStaticHeadersOnEveryRequest(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	ts := mcpFixture(t, seen, &mu)

	raw, err := Fetch(context.Background(), Ref{
		Transport: "http", Target: ts.URL,
		Headers: surfacelock.Headers{"Authorization": "Bearer tok"},
	}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw == nil {
		t.Fatal("Fetch returned no surface")
	}
	// The DELETE is best-effort and fired from a deferred close; wait for it
	// rather than racing it.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, ok := seen[http.MethodDelete]
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
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

// TestFetchRefusesInjectedHeadersBeforeTheFirstRequest: the refusal must land
// before any byte is written, so a bad header cannot half-run a capture.
func TestFetchRefusesInjectedHeadersBeforeTheFirstRequest(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	ts := mcpFixture(t, seen, &mu)

	_, err := Fetch(context.Background(), Ref{
		Transport: "http", Target: ts.URL,
		Headers: surfacelock.Headers{"Authorization": "Bearer x\r\nX-Evil: 1"},
	}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("Fetch admitted a CRLF-injected header value")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("Fetch error = %v, want one naming the control character", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("the refusal ran AFTER %d request(s) had been made: %v", len(seen), seen)
	}
}

// TestHeadersNeverReachTheLockfile is the artifact property: `tools.lock` is a
// file people commit, and a credential in it is a credential in git history.
// The check is over the RENDERED BYTES, not over the struct's field list — a
// field added later that happens to serialize the value would pass a field
// check and fail this one.
func TestHeadersNeverReachTheLockfile(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	ts := mcpFixture(t, seen, &mu)

	const secret = "s3cret-token-value"
	raw, err := Fetch(context.Background(), Ref{
		Transport: "http", Target: ts.URL,
		Headers: surfacelock.Headers{"Authorization": "Bearer " + secret},
	}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	s, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	entry, err := surfacelock.EntryFromSurface("http", ts.URL, nil, s)
	if err != nil {
		t.Fatalf("EntryFromSurface: %v", err)
	}
	lf := surfacelock.NewLockfile()
	lf.Servers["fx"] = entry
	b, err := lf.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, needle := range []string{secret, "Bearer", "Authorization", "authorization"} {
		if strings.Contains(string(b), needle) {
			t.Fatalf("the rendered lockfile carries %q:\n%s", needle, b)
		}
	}
}

// TestEveryHTTPRequestInClientIsBuiltByNewRequest — the inventory gate, same
// reasoning as the proxy's: the property is that no request is built any other
// way, not that the two sites I edited were edited.
func TestEveryHTTPRequestInClientIsBuiltByNewRequest(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	raw := regexp.MustCompile(`http\.NewRequest(WithContext)?\(`).FindAllIndex(src, -1)
	if len(raw) != 1 {
		t.Fatalf("client.go builds %d raw http requests, want exactly 1 (inside newRequest); "+
			"every request must go through newRequest so it carries the static headers", len(raw))
	}
	fn := regexp.MustCompile(`(?s)func \(h \*httpSession\) newRequest\(.*?\n\}`).Find(src)
	if fn == nil {
		t.Fatal("(*httpSession).newRequest is gone; this gate no longer means anything")
	}
	if !regexp.MustCompile(`http\.NewRequestWithContext\(`).Match(fn) {
		t.Fatal("the one raw request is not the one inside newRequest")
	}
	if !regexp.MustCompile(`h\.headers\.Apply\(req\)`).Match(fn) {
		t.Fatal("newRequest no longer applies the static headers")
	}
}
