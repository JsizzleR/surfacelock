package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// metaFrame builds a stateless (2026-07-28) request frame: the reserved _meta
// protocolVersion key is what marks it, and extra params ride beside it.
func metaFrame(id int, method string, extra string) []byte {
	p := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	if extra != "" {
		p = extra + "," + p
	}
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{%s}}`, id, method, p))
}

// seenMetadata is what the upstream saw on one POST: every value of each
// request-metadata header (Values, so a duplicate is visible), and the body
// fields they must mirror.
type seenMetadata struct {
	proto, method, name []string
	bodyMethod          string
}

// TestHTTPBackendMirrorsRequestMetadataOnStatelessFrames: the 2026-07-28
// Streamable HTTP transport requires MCP-Protocol-Version, Mcp-Method and — for
// tools/call, prompts/get and resources/read — Mcp-Name on every POST, agreeing
// with the body (a spec-conformant server refuses -32020 otherwise; measured on
// SDK 2.3.1 and Python mcp 2.3.0). The proxy's front is stdio, which has no
// headers, so the backend is the only place they can come from. A value that is
// not header-safe travels in the =?base64?...?= sentinel, and so does a plain one
// that LOOKS like the sentinel. A classic frame carries no Mcp-Method/Mcp-Name.
func TestHTTPBackendMirrorsRequestMetadataOnStatelessFrames(t *testing.T) {
	var mu sync.Mutex
	var seen []seenMetadata
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, seenMetadata{
			proto: r.Header.Values("MCP-Protocol-Version"), method: r.Header.Values("Mcp-Method"),
			name: r.Header.Values("Mcp-Name"), bodyMethod: req.Method,
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, req.ID)
	}))
	t.Cleanup(ts.Close)

	b, err := newHTTPBackend(ts.URL, nil, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	b64 := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	cases := []struct {
		frame    []byte
		wantName []string // nil: no Mcp-Name header at all
	}{
		{metaFrame(1, "server/discover", ""), nil},
		{metaFrame(2, "tools/list", `"cursor":"p2"`), nil},
		{metaFrame(3, "tools/call", `"name":"frob","arguments":{}`), []string{"frob"}},
		{metaFrame(4, "prompts/get", `"name":"greet"`), []string{"greet"}},
		{metaFrame(5, "resources/read", `"uri":"file:///projects/app/config.json"`), []string{"file:///projects/app/config.json"}},
		{metaFrame(6, "tools/call", `"name":"frøb"`), []string{b64("frøb")}},
		{metaFrame(7, "tools/call", `"name":" padded "`), []string{b64(" padded ")}},
		{metaFrame(8, "tools/call", `"name":"line1\nline2"`), []string{b64("line1\nline2")}},
		{metaFrame(9, "tools/call", `"name":"tab\there"`), []string{b64("tab\there")}},
		{metaFrame(10, "tools/call", `"name":"=?base64?literal?="`), []string{b64("=?base64?literal?=")}},
		// Overlapping markers still match the spec's literal predicate
		// (starts with =?base64?, ends with ?=), so it is encoded.
		{metaFrame(11, "tools/call", `"name":"=?base64?="`), []string{b64("=?base64?=")}},
		// A name the body does not carry as a string has no header to mirror;
		// the upstream's own validation decides (it refuses the absent header).
		{metaFrame(12, "tools/call", `"name":7`), nil},
		// null decodes into a Go string as "" with no error; it is absent too.
		{metaFrame(14, "tools/call", `"name":null`), nil},
		{metaFrame(15, "tasks/get", `"taskId":"t-1"`), []string{"t-1"}},
		{metaFrame(16, "tasks/cancel", `"taskId":"t-2"`), []string{"t-2"}},
		// The method is never sentinel-encoded, even when it looks like one.
		{metaFrame(17, "=?base64?eA==?=", ""), nil},
	}
	for _, c := range cases {
		if err := b.Send(context.Background(), c.frame); err != nil {
			t.Fatal(err)
		}
		collectFrame(t, b.Frames())
	}
	// Classic: the era comes from the negotiated handshake, not the frame.
	b.SetProto("2025-11-25")
	if err := b.Send(context.Background(), []byte(`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"frob"}}`)); err != nil {
		t.Fatal(err)
	}
	collectFrame(t, b.Frames())

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(cases)+1 {
		t.Fatalf("upstream saw %d POSTs, want %d", len(seen), len(cases)+1)
	}
	for i, c := range cases {
		s := seen[i]
		if strings.Join(s.proto, ",") != "2026-07-28" {
			t.Errorf("frame %d (%s): MCP-Protocol-Version = %q, want exactly [2026-07-28]", i+1, s.bodyMethod, s.proto)
		}
		if strings.Join(s.method, ",") != s.bodyMethod || len(s.method) != 1 {
			t.Errorf("frame %d: Mcp-Method = %q, want exactly [%s]", i+1, s.method, s.bodyMethod)
		}
		if fmt.Sprint(s.name) != fmt.Sprint(c.wantName) || len(s.name) != len(c.wantName) {
			t.Errorf("frame %d (%s): Mcp-Name = %q, want %q", i+1, s.bodyMethod, s.name, c.wantName)
		}
	}
	last := seen[len(cases)]
	if strings.Join(last.proto, ",") != "2025-11-25" || len(last.method) != 0 || len(last.name) != 0 {
		t.Errorf("classic frame: MCP-Protocol-Version=%q Mcp-Method=%q Mcp-Name=%q; want the negotiated era and neither mirror", last.proto, last.method, last.name)
	}
}

// TestHTTPBackendMirroredMethodCannotInjectAHeader: Mcp-Method is copied from a
// frame the stdio client wrote, so a method carrying CR/LF is an attempt to
// write a second header the operator never chose. It must never reach the
// upstream as one; net/http's write barrier refuses the value, and the client
// gets a transport-labelled error frame for its id instead of a hang.
func TestHTTPBackendMirroredMethodCannotInjectAHeader(t *testing.T) {
	var mu sync.Mutex
	var injected []string
	posts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		injected = append(injected, r.Header.Values("X-Injected")...)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(ts.Close)
	b, err := newHTTPBackend(ts.URL, nil, func(string, ...any) {}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Send(context.Background(), metaFrame(1, "tools/list\r\nX-Injected: 1", "")); err != nil {
		t.Fatal(err)
	}
	fr := collectFrame(t, b.Frames())
	if !strings.Contains(string(fr), `"error"`) {
		t.Errorf("an unsendable method produced %s, want a transport error frame", fr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(injected) != 0 || posts != 0 {
		t.Errorf("upstream saw %d POSTs and X-Injected %q; want the request refused before it was written", posts, injected)
	}
}
