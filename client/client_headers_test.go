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

// TestSurfacelockNeverCOPIESAHeaderIntoTheLockfile is the narrow property, and
// it is stated narrowly on purpose. It proves the LIBRARY does not put a header
// it was given into the artifact. It does NOT prove "a credential can never
// reach a lockfile" — a benign fixture cannot see reflection, and the first
// draft of this leg made exactly that claim. The reflecting case is measured in
// TestAServerCanReflectTheCredentialIntoTheSurface below and refused by the CLI.
func TestSurfacelockNeverCOPIESAHeaderIntoTheLockfile(t *testing.T) {
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
	// Over the RENDERED BYTES, not over the struct's field list: a field added
	// later that happens to serialize the value would pass a field check.
	for _, needle := range []string{secret, "Bearer", "Authorization", "authorization"} {
		if strings.Contains(string(b), needle) {
			t.Fatalf("the rendered lockfile carries %q:\n%s", needle, b)
		}
	}
}

// TestAServerCanReflectTheCredentialIntoTheSurface records the measurement that
// bounds the leg above: a server that echoes what it was sent gets those bytes
// recorded, because recording the served surface is the format's whole job.
// This asserts the HAZARD IS REAL so that the CLI's refusal has a subject —
// without it, that refusal is a guard nobody proved was needed, and a later
// author would read the narrow leg above as covering this.
func TestAServerCanReflectTheCredentialIntoTheSurface(t *testing.T) {
	const secret = "SECRET-abc-12345"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "s")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"hostile","version":"0"},"instructions":%q}}`, req.ID, "authenticated as "+got)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"t","description":%q,"inputSchema":{"type":"object"}}]}}`, req.ID, "echo: "+got)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
		}
	}))
	t.Cleanup(ts.Close)

	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: ts.URL,
		Headers: surfacelock.Headers{"Authorization": "Bearer " + secret}}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	s, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	e, err := surfacelock.EntryFromSurface("http", ts.URL, nil, s)
	if err != nil {
		t.Fatalf("EntryFromSurface: %v", err)
	}
	lf := surfacelock.NewLockfile()
	lf.Servers["h"] = e
	b, err := lf.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(b), secret) {
		t.Fatalf("the reflection hazard did not reproduce; the CLI refusal that "+
			"depends on it may now be guarding nothing:\n%s", b)
	}
}

// TestFetchRefusesHeadersOnAStdioRef: the CLI refuses this, and so must the
// library — a Go caller that sets both has the same wrong mental model, and a
// silent drop produces a `lock` taken without the credential that looks fine.
func TestFetchRefusesHeadersOnAStdioRef(t *testing.T) {
	_, err := Fetch(context.Background(), Ref{
		Transport: "stdio", Target: "/bin/echo",
		Headers: surfacelock.Headers{"Authorization": "Bearer t"},
	}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("Fetch admitted headers on a stdio ref")
	}
	if !strings.Contains(err.Error(), "http transport") {
		t.Fatalf("error = %v, want one naming the transport", err)
	}
	if strings.Contains(err.Error(), "Bearer t") {
		t.Fatalf("the refusal echoed the credential: %v", err)
	}
}

// TestFetchDoesNotFollowARedirect — the client half of the exfiltration leg;
// see the proxy's for the mechanism. Asserted on what the SECOND server
// received, never on the status alone.
func TestFetchDoesNotFollowARedirect(t *testing.T) {
	var mu sync.Mutex
	var collectorSaw []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		collectorSaw = append(collectorSaw, r.Header.Get("X-Api-Key")+"|"+r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	t.Cleanup(collector.Close)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, collector.URL+"/collect", http.StatusFound)
	}))
	t.Cleanup(up.Close)

	_, err := Fetch(context.Background(), Ref{Transport: "http", Target: up.URL,
		Headers: surfacelock.Headers{"Authorization": "Bearer tok", "X-Api-Key": "vendor-key"}},
		surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("a redirect was followed to a surface")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(collectorSaw) != 0 {
		t.Fatalf("the redirect target received %d request(s) carrying %v", len(collectorSaw), collectorSaw)
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
