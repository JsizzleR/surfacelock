package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- stdio backend ----

// TestHelperProcess is the re-exec'd toy stdio MCP server. It is not a test.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("SURFACELOCK_PROXY_HELPER")
	if mode == "" {
		return
	}
	// Non-JSON stdout noise before any frame: endemic in real servers, must be
	// tolerated by the relay.
	fmt.Println("helper: starting up (this is log noise on stdout)")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil || msg.ID == nil {
			continue
		}
		switch msg.Method {
		case "initialize":
			fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"helper","version":"1"}}}`+"\n", msg.ID)
		case "tools/list":
			fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"alpha","description":"Adds numbers.","inputSchema":{"type":"object"}}]}}`+"\n", msg.ID)
		default:
			fmt.Printf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"nope"}}`+"\n", msg.ID)
		}
		if mode == "die-after-first" {
			os.Exit(3)
		}
	}
	os.Exit(0)
}

func helperBackend(t *testing.T, mode string) *stdioBackend {
	t.Helper()
	b, err := newStdioBackend(os.Args[0], []string{"-test.run=TestHelperProcess"},
		[]string{"SURFACELOCK_PROXY_HELPER=" + mode}, io.Discard)
	if err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

// nextJSONFrame skips stdout noise and returns the next frame that parses as a
// JSON object, failing after a timeout.
func nextJSONFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case fr, ok := <-frames:
			if !ok {
				t.Fatal("frames closed while waiting for a JSON frame")
			}
			if len(fr) > 0 && fr[0] == '{' {
				return fr
			}
		case <-deadline:
			t.Fatal("timed out waiting for a JSON frame")
		}
	}
}

func TestStdioBackendRoundTripToleratesNoise(t *testing.T) {
	b := helperBackend(t, "echo")
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	fr := nextJSONFrame(t, b.Frames())
	if !bytes.Contains(fr, []byte("protocolVersion")) {
		t.Fatalf("unexpected frame: %s", fr)
	}
	b.Close() // must reap the child and return; a hang here is the failure
	if err := b.Err(); err != nil {
		t.Fatalf("caller-initiated close must not report a transport error, got: %v", err)
	}
}

func TestStdioBackendChildDeathIsReported(t *testing.T) {
	b := helperBackend(t, "die-after-first")
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	nextJSONFrame(t, b.Frames())
	// Drain to the close: the child exited on its own, so Err must say so.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-b.Frames():
			if !ok {
				if b.Err() == nil {
					t.Fatal("child death must be reported by Err")
				}
				return
			}
		case <-deadline:
			t.Fatal("frames never closed after child death")
		}
	}
}

// ---- http backend ----

func collectFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	select {
	case fr, ok := <-frames:
		if !ok {
			t.Fatal("frames closed while a frame was expected")
		}
		return fr
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func TestHTTPBackendJSONRoundTripAndSessionHeaders(t *testing.T) {
	var mu sync.Mutex
	var seenSession, seenProto []string
	var sawDelete string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenSession = append(seenSession, r.Header.Get("Mcp-Session-Id"))
		seenProto = append(seenProto, r.Header.Get("MCP-Protocol-Version"))
		if r.Method == http.MethodDelete {
			sawDelete = r.Header.Get("Mcp-Session-Id")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		mu.Unlock()
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, req.ID)
	}))
	t.Cleanup(ts.Close)

	b, err := newHTTPBackend(ts.URL, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)); err != nil {
		t.Fatal(err)
	}
	collectFrame(t, b.Frames())
	b.SetProto("2025-11-25")
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	collectFrame(t, b.Frames())
	b.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(seenSession) < 2 || seenSession[1] != "sess-1" {
		t.Fatalf("second POST did not carry the captured session id: %v", seenSession)
	}
	if seenProto[1] != "2025-11-25" {
		t.Fatalf("second POST did not carry the negotiated protocol version: %v", seenProto)
	}
	if sawDelete != "sess-1" {
		t.Fatalf("Close did not DELETE the session: %q", sawDelete)
	}
}

func TestHTTPBackendStreamsSSEEventsAsTheyArrive(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		// A notification interleaved BEFORE the response — it must be relayed
		// immediately, not after the stream ends (the response is gated on the
		// test observing the notification first).
		fmt.Fprintf(w, "data: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n\n", req.ID)
	}))
	t.Cleanup(ts.Close)

	b, err := newHTTPBackend(ts.URL, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call"}`)); err != nil {
		t.Fatal(err)
	}
	first := collectFrame(t, b.Frames())
	if !bytes.Contains(first, []byte("list_changed")) {
		t.Fatalf("interleaved notification did not arrive first (buffered relay?): %s", first)
	}
	close(release) // only now may the response be written
	second := collectFrame(t, b.Frames())
	if !bytes.Contains(second, []byte(`"id":9`)) {
		t.Fatalf("response frame missing: %s", second)
	}
}

func TestHTTPBackendNon2xxIsTransportNeverDrift(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "kaboom", http.StatusBadGateway)
	}))
	t.Cleanup(ts.Close)
	var findings []string
	transported := false
	var mu sync.Mutex
	b, err := newHTTPBackend(ts.URL,
		func(format string, args ...any) {
			mu.Lock()
			findings = append(findings, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
		func() { mu.Lock(); transported = true; mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)); err != nil {
		t.Fatal(err)
	}
	fr := collectFrame(t, b.Frames())
	var env struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(fr, &env); err != nil || env.Error == nil {
		t.Fatalf("expected a synthetic error frame: %s", fr)
	}
	if env.Error.Code != codeTransportFailed {
		t.Fatalf("upstream 502 must map to the transport code, got %d", env.Error.Code)
	}
	if strings.Contains(strings.ToLower(env.Error.Message), "drift") &&
		!strings.Contains(env.Error.Message, "not drift") {
		t.Fatalf("transport failure must never read as drift: %q", env.Error.Message)
	}
	mu.Lock()
	defer mu.Unlock()
	if !transported || len(findings) == 0 {
		t.Fatalf("transport hook/finding not invoked: %v %v", transported, findings)
	}
}

func TestHTTPBackendStreamEndingWithoutResponseIsTransport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/progress"}`)
	}))
	t.Cleanup(ts.Close)
	b, err := newHTTPBackend(ts.URL, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":6,"method":"tools/list"}`)); err != nil {
		t.Fatal(err)
	}
	collectFrame(t, b.Frames()) // the notification relays
	fr := collectFrame(t, b.Frames())
	if !bytes.Contains(fr, []byte(fmt.Sprint(codeTransportFailed))) {
		t.Fatalf("want a synthetic transport error for the abandoned request, got: %s", fr)
	}
}

func TestHTTPBackendGETNotificationStreamRelays(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(ts.Close)
	b, err := newHTTPBackend(ts.URL, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	b.StartNotificationStream()
	fr := collectFrame(t, b.Frames())
	if !bytes.Contains(fr, []byte("list_changed")) {
		t.Fatalf("GET-stream notification was not relayed: %s", fr)
	}
}
