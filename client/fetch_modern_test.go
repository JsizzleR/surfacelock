package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// rpcIn is the decoded shape of one incoming JSON-RPC request in the fakes.
type rpcIn struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Meta   map[string]json.RawMessage `json:"_meta"`
		Cursor string                     `json:"cursor"`
	} `json:"params"`
}

func rpcResult(t *testing.T, w http.ResponseWriter, id json.RawMessage, result any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result}); err != nil {
		t.Errorf("encode result: %v", err)
	}
}

func rpcErrorReply(t *testing.T, w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}); err != nil {
		t.Errorf("encode error: %v", err)
	}
}

func fullMeta(in rpcIn) bool {
	for _, k := range []string{metaProtocolVersionKey, metaClientInfoKey, metaClientCapabilitiesKey} {
		if _, ok := in.Params.Meta[k]; !ok {
			return false
		}
	}
	return true
}

// modernOnlyHandler mimics the measured bridge face: initialize is refused with
// HTTP 400 (the handshake was removed), server/discover and tools/list demand the
// full three-key _meta envelope. Pages carry the modern envelope extras
// (cacheScope/resultType), which admission must tolerate.
func modernOnlyHandler(t *testing.T, sawDiscover *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("bad request body: %v", err)
			return
		}
		switch in.Method {
		case "initialize":
			http.Error(w, "this bridge speaks the 2026-07-28 stateless MCP protocol; the initialize handshake was removed (SEP-2575) — use a 2026-07-28 client", http.StatusBadRequest)
		case "server/discover":
			sawDiscover.Add(1)
			if !fullMeta(in) {
				rpcErrorReply(t, w, in.ID, -32602, "params._meta must carry the reserved envelope keys")
				return
			}
			rpcResult(t, w, in.ID, map[string]any{
				"supportedVersions": []string{ModernRevision},
				"serverInfo":        map[string]any{"name": "modern-fake", "version": "1"},
				"instructions":      "Always call frob before quux.",
				"capabilities":      map[string]any{"tools": map[string]any{}},
				"resultType":        "complete",
			})
		case "tools/list":
			if !fullMeta(in) {
				rpcErrorReply(t, w, in.ID, -32602, "params._meta must carry the reserved envelope keys")
				return
			}
			if in.Params.Cursor == "" {
				rpcResult(t, w, in.ID, map[string]any{
					"cacheScope": "private", "resultType": "complete",
					"tools":      []map[string]any{{"name": "frob", "description": "Frob.", "inputSchema": map[string]any{"type": "object"}}},
					"nextCursor": "p2",
				})
				return
			}
			rpcResult(t, w, in.ID, map[string]any{
				"cacheScope": "private", "resultType": "complete",
				"tools": []map[string]any{{"name": "quux", "description": "Quux.", "inputSchema": map[string]any{"type": "object"}}},
			})
		default:
			rpcErrorReply(t, w, in.ID, -32601, "method not found")
		}
	}
}

// statefulClassicHandler mimics the measured v2 SDK stateful HTTP face: a cold
// server/discover is refused (-32600 "Missing session ID"), classic initialize
// negotiates 2025-11-25 and issues a session id, and tools/list requires it.
func statefulClassicHandler(t *testing.T) http.HandlerFunc {
	const sid = "sess-1"
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete { // bodyless session teardown from close()
			w.WriteHeader(http.StatusOK)
			return
		}
		var in rpcIn
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("bad request body: %v", err)
			return
		}
		switch in.Method {
		case "server/discover":
			rpcErrorReply(t, w, in.ID, -32600, "Bad Request: Missing session ID")
		case "initialize":
			w.Header().Set("Mcp-Session-Id", sid)
			rpcResult(t, w, in.ID, map[string]any{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]any{"name": "classic-fake", "version": "1"},
				"instructions":    "Classic-side instructions.",
				"capabilities":    map[string]any{"tools": map[string]any{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != sid {
				rpcErrorReply(t, w, in.ID, -32600, "Bad Request: Missing session ID")
				return
			}
			rpcResult(t, w, in.ID, map[string]any{
				"tools": []map[string]any{{"name": "echo", "description": "Echo.", "inputSchema": map[string]any{"type": "object"}}},
			})
		default:
			rpcErrorReply(t, w, in.ID, -32601, "method not found")
		}
	}
}

func TestFetchModernOnlyServer(t *testing.T) {
	var discovers atomic.Int64
	srv := httptest.NewServer(modernOnlyHandler(t, &discovers))
	defer srv.Close()

	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Era != ModernRevision {
		t.Errorf("era = %q, want %q", raw.Era, ModernRevision)
	}
	if len(raw.Pages) != 2 {
		t.Errorf("pages = %d, want 2 (cursor pagination)", len(raw.Pages))
	}
	s, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Admit of a modern surface (envelope extras present): %v", err)
	}
	if s.Instructions == nil || *s.Instructions != "Always call frob before quux." {
		t.Errorf("instructions not captured from server/discover: %+v", s.Instructions)
	}
	if len(s.Tools) != 2 || s.Tools[0].Name != "frob" || s.Tools[1].Name != "quux" {
		t.Errorf("tools = %+v, want frob+quux", s.Tools)
	}
	if got := discovers.Load(); got != 1 {
		t.Errorf("server/discover called %d times, want 1", got)
	}
}

func TestFetchFallsBackToClassicOnStatefulServer(t *testing.T) {
	srv := httptest.NewServer(statefulClassicHandler(t))
	defer srv.Close()

	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Era != "2025-11-25" {
		t.Errorf("era = %q, want the classic-negotiated 2025-11-25", raw.Era)
	}
	if _, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits()); err != nil {
		t.Fatalf("Admit: %v", err)
	}
}

// A pre-discover server that answers -32601 for server/discover (the measured
// legacy-child shape) must also reach the classic fallback.
func TestFetchFallsBackToClassicOnMethodNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Method {
		case "server/discover":
			rpcErrorReply(t, w, in.ID, -32601, "method not found")
		case "initialize":
			rpcResult(t, w, in.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "old", "version": "1"},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			rpcResult(t, w, in.ID, map[string]any{"tools": []map[string]any{{"name": "t", "inputSchema": map[string]any{}}}})
		}
	}))
	defer srv.Close()

	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Era != "2025-06-18" {
		t.Errorf("era = %q, want 2025-06-18", raw.Era)
	}
}

// Offering a pre-stateless revision must speak classic directly: a verifier
// re-offering a recorded era reproduces the recorded flow, and never pays (or
// leaks era decisions to) a discover round-trip.
func TestFetchClassicOfferNeverCallsDiscover(t *testing.T) {
	var discovers atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Method {
		case "server/discover":
			discovers.Add(1)
			rpcErrorReply(t, w, in.ID, -32601, "method not found")
		case "initialize":
			rpcResult(t, w, in.ID, map[string]any{"protocolVersion": "2025-11-25", "serverInfo": map[string]any{"name": "s", "version": "1"}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			rpcResult(t, w, in.ID, map[string]any{"tools": []map[string]any{}})
		}
	}))
	defer srv.Close()

	if _, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, surfacelock.DefaultLimits()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := discovers.Load(); got != 0 {
		t.Errorf("server/discover called %d times for a classic offer, want 0", got)
	}
}

// A server refusing BOTH flows must report both refusals, so a modern-only
// endpoint's transient discover failure is not misattributed to the classic
// handshake it never supported.
func TestFetchDoubleRefusalReportsBothFlows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("Fetch succeeded against a server refusing everything")
	}
	if !strings.Contains(err.Error(), "server/discover") || !strings.Contains(err.Error(), "initialize fallback") {
		t.Errorf("error does not name both flows: %v", err)
	}
}

// supportedVersions that omit the offered revision mean the dialect the bytes
// would be served under is unknown — the modern attempt fails and the classic
// fallback decides.
func TestFetchModernRequiresOfferedInSupportedVersions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Method {
		case "server/discover":
			rpcResult(t, w, in.ID, map[string]any{"supportedVersions": []string{"2099-01-01"}, "serverInfo": map[string]any{"name": "future", "version": "1"}})
		case "initialize":
			rpcResult(t, w, in.ID, map[string]any{"protocolVersion": "2025-11-25", "serverInfo": map[string]any{"name": "future", "version": "1"}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			rpcResult(t, w, in.ID, map[string]any{"tools": []map[string]any{}})
		}
	}))
	defer srv.Close()

	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Era != "2025-11-25" {
		t.Errorf("era = %q, want the classic fallback's 2025-11-25", raw.Era)
	}
}

// The injected HTTP client must carry the requests: a unix-socket upstream is
// unreachable by a default client, so success proves the seam is honored.
func TestFetchHTTPClientInjectionOverUnixSocket(t *testing.T) {
	// A macOS unix socket path is capped at ~104 bytes and t.TempDir() sits under
	// a long /var/folders prefix, so bind the socket in a short-lived short dir.
	dir, err := os.MkdirTemp("/tmp", "sl")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "cand.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var discovers atomic.Int64
	srv := &http.Server{Handler: modernOnlyHandler(t, &discovers)}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects refused")
		},
	}
	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: "http://candidate/mcp", HTTPClient: client}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch over unix socket: %v", err)
	}
	if raw.Era != ModernRevision || len(raw.Pages) != 2 {
		t.Errorf("era=%q pages=%d, want %q/2", raw.Era, len(raw.Pages), ModernRevision)
	}
}
