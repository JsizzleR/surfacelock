package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/JsizzleR/surfacelock"
)

// fakeMCP is a scriptable Streamable HTTP MCP server.
type fakeMCP struct {
	t            *testing.T
	sse          bool   // answer in text/event-stream instead of application/json
	protoVersion any    // initialize result protocolVersion; nil to omit
	instructions string // initialize result instructions; "" to omit
	pages        []string
	cursorLoop   bool // always return the same nextCursor
	rawBody      string
	contentType  string
	sawProtoHdr  string // MCP-Protocol-Version seen on tools/list
	sawOffered   string // protocolVersion the client offered at initialize
	sawInit      bool   // notifications/initialized received
}

func (f *fakeMCP) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor          string `json:"cursor"`
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.ID == nil { // notification
			if req.Method == "notifications/initialized" {
				f.sawInit = true
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			f.sawOffered = req.Params.ProtocolVersion
			w.Header().Set("Mcp-Session-Id", "sess-1")
			res := map[string]any{"serverInfo": map[string]any{"name": "fake", "version": "0"}}
			if f.protoVersion != nil {
				res["protocolVersion"] = f.protoVersion
			}
			if f.instructions != "" {
				res["instructions"] = f.instructions
			}
			result = res
		case "tools/list":
			f.sawProtoHdr = r.Header.Get("MCP-Protocol-Version")
			if f.rawBody != "" {
				ct := f.contentType
				if ct == "" {
					ct = "application/json"
				}
				w.Header().Set("Content-Type", ct)
				fmt.Fprint(w, f.rawBody)
				return
			}
			idx := 0
			if req.Params.Cursor != "" {
				fmt.Sscanf(req.Params.Cursor, "page-%d", &idx)
			}
			if idx >= len(f.pages) {
				http.Error(w, "bad cursor", http.StatusBadRequest)
				return
			}
			var page map[string]any
			if err := json.Unmarshal([]byte(f.pages[idx]), &page); err != nil {
				f.t.Fatalf("bad test page: %v", err)
			}
			switch {
			case f.cursorLoop:
				page["nextCursor"] = "page-0"
			case idx+1 < len(f.pages):
				page["nextCursor"] = fmt.Sprintf("page-%d", idx+1)
			}
			result = page
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
			return
		}
		resp, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if err != nil {
			f.t.Fatalf("marshal: %v", err)
		}
		if f.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			// A notification event first: the client must skip to its response id.
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
			fmt.Fprintf(w, "data: %s\n\n", resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}
}

func fetchFrom(t *testing.T, f *fakeMCP, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	// A classic offer drives the classic flow directly (SPEC.md §3.4), which is
	// the pipeline these fixtures were written against (initialize is request id
	// 1, tools/list id 2). The stateless flow's own legs live in
	// fetch_modern_test.go; the pagination caps under test here are shared code.
	return Fetch(ctx, Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, lim)
}

const pageOne = `{"tools":[{"name":"alpha","description":"a"}]}`
const pageTwo = `{"tools":[{"name":"beta","description":"b"}]}`

func TestHTTPFetchJSON(t *testing.T) {
	f := &fakeMCP{t: t, protoVersion: "2025-11-25", instructions: "be nice", pages: []string{pageOne, pageTwo}}
	raw, err := fetchFrom(t, f, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if raw.Era != "2025-11-25" || raw.Offered != "2025-11-25" {
		t.Fatalf("era %q offered %q", raw.Era, raw.Offered)
	}
	if len(raw.Pages) != 2 {
		t.Fatalf("pages = %d", len(raw.Pages))
	}
	if string(raw.Instructions) != `"be nice"` {
		t.Fatalf("instructions = %s", raw.Instructions)
	}
	// The negotiated version must be echoed on post-initialize requests.
	if f.sawProtoHdr != "2025-11-25" {
		t.Fatalf("MCP-Protocol-Version header = %q", f.sawProtoHdr)
	}
	// SPEC.md §3.1/§9: the client must OFFER the caller's chosen version (reproducible
	// negotiation) and send notifications/initialized before tools/list.
	if f.sawOffered != "2025-11-25" {
		t.Fatalf("offered protocolVersion = %q, want the fetchFrom offer verbatim", f.sawOffered)
	}
	if !f.sawInit {
		t.Fatal("notifications/initialized was never sent")
	}
	s, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tools) != 2 || s.Tools[0].Name != "alpha" || s.Tools[1].Name != "beta" {
		t.Fatalf("tools: %+v", s.Tools)
	}
}

func TestHTTPFetchSSE(t *testing.T) {
	f := &fakeMCP{t: t, sse: true, protoVersion: "2025-11-25", pages: []string{pageOne}}
	raw, err := fetchFrom(t, f, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.Pages) != 1 {
		t.Fatalf("pages = %d", len(raw.Pages))
	}
	// The content the SSE path yielded must match what admission sees on the JSON
	// path — not merely arrive as one page.
	s, err := surfacelock.Admit(*raw, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tools) != 1 || s.Tools[0].Name != "alpha" {
		t.Fatalf("SSE tools: %+v", s.Tools)
	}
}

// The SSE per-event byte cap must fire and be classified inadmissible (exit 5), not
// leak an unbounded stream or misreport as "no response".
func TestHTTPSSEEventCap(t *testing.T) {
	bigTool := `{"tools":[{"name":"a","description":"` + strings.Repeat("x", 4000) + `"}]}`
	f := &fakeMCP{t: t, sse: true, protoVersion: "2025-11-25", pages: []string{bigTool}}
	lim := surfacelock.DefaultLimits()
	lim.MaxPageBytes = 512
	_, err := fetchFrom(t, f, lim)
	if err == nil || !errors.Is(err, surfacelock.ErrInadmissible) {
		t.Fatalf("oversized SSE event not refused as inadmissible: %v", err)
	}
	if !strings.Contains(err.Error(), "sse event exceeds") {
		t.Fatalf("wrong SSE cap error: %v", err)
	}
}

// The client must re-offer the caller's chosen protocolVersion verbatim, so a
// verifier reproduces the era the lockfile recorded (SPEC.md §3.1).
func TestHTTPOffersRequestedVersion(t *testing.T) {
	f := &fakeMCP{t: t, protoVersion: "2025-11-25", pages: []string{pageOne}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	if _, err := Fetch(ctx, Ref{Transport: "http", Target: srv.URL, Offered: "2024-11-05"}, surfacelock.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if f.sawOffered != "2024-11-05" {
		t.Fatalf("offered %q, want the caller's 2024-11-05", f.sawOffered)
	}
}

// A control-char era must be refused as inadmissible (exit 5) BEFORE it is used as an
// HTTP header value — not surface later as an opaque transport error.
func TestHTTPControlCharEraRefused(t *testing.T) {
	f := &fakeMCP{t: t, protoVersion: "202511", pages: []string{pageOne}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	_, err := Fetch(ctx, Ref{Transport: "http", Target: srv.URL, Offered: "2026-07-28"}, surfacelock.DefaultLimits())
	if err == nil || !errors.Is(err, surfacelock.ErrInadmissible) {
		t.Fatalf("control-char era not refused as inadmissible: %v", err)
	}
}

func TestHTTPHostileResponses(t *testing.T) {
	lim := surfacelock.DefaultLimits()
	small := lim
	small.MaxPageBytes = 256
	fewPages := lim
	fewPages.MaxPages = 2
	cases := []struct {
		name         string
		f            *fakeMCP
		lim          surfacelock.Limits
		inadmissible bool
		want         string
	}{
		{"cursor loop", &fakeMCP{protoVersion: "e", pages: []string{pageOne}, cursorLoop: true}, lim, true, "cursor loop"},
		{"page cap", &fakeMCP{protoVersion: "e", pages: []string{pageOne, pageTwo, pageOne, pageTwo}}, fewPages, true, "pages"},
		// Distinct cursors but > MaxPages: the loop above uses distinct page-N cursors.
		{"non-string cursor", &fakeMCP{protoVersion: "e", rawBody: `{"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":7}}`}, lim, true, "not a string"},
		{"oversized cursor", &fakeMCP{protoVersion: "e", rawBody: `{"jsonrpc":"2.0","id":2,"result":{"tools":[],"nextCursor":"` + strings.Repeat("c", 5000) + `"}}`}, lim, true, "cursor exceeds"},
		{"oversized body", &fakeMCP{protoVersion: "e", rawBody: `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","description":"` + strings.Repeat("x", 400) + `"}]}}`}, small, true, "exceeds 256 bytes"},
		{"non-json body", &fakeMCP{protoVersion: "e", rawBody: "<html>error</html>"}, lim, false, "bad json"},
		{"wrong content type", &fakeMCP{protoVersion: "e", rawBody: "x", contentType: "text/plain"}, lim, false, "unexpected content-type"},
		{"missing protocolVersion", &fakeMCP{pages: []string{pageOne}}, lim, false, "no protocolVersion"},
		{"non-string protocolVersion", &fakeMCP{protoVersion: 7, pages: []string{pageOne}}, lim, false, "no protocolVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.t = t
			// Cursor-abuse bodies replace only tools/list; make page-count abuse
			// terminate: rawBody responses never paginate, so loop/caps come from
			// pages+cursorLoop.
			_, err := fetchFrom(t, tc.f, tc.lim)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := errors.Is(err, surfacelock.ErrInadmissible); got != tc.inadmissible {
				t.Fatalf("ErrInadmissible = %v, want %v (err: %v)", got, tc.inadmissible, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestHTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	_, err := Fetch(ctx, Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, surfacelock.ErrInadmissible) {
		t.Fatal("auth failure misclassified as inadmissible surface")
	}
}

// ---- stdio transport, via the helper-process pattern ----

func helperRef(mode string, offered string) Ref {
	return Ref{
		Transport: "stdio",
		Target:    os.Args[0],
		Args:      []string{"-test.run=TestHelperProcess", "--"},
		Env:       []string{"GO_HELPER_MODE=" + mode, "GO_WANT_HELPER_PROCESS=1"},
		Offered:   offered,
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("GO_HELPER_MODE")
	dec := json.NewDecoder(os.Stdin)
	respond := func(id json.RawMessage, result string) {
		fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, result)
	}
	for {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := dec.Decode(&req); err != nil {
			os.Exit(0)
		}
		if req.ID == nil {
			continue
		}
		switch req.Method {
		case "initialize":
			if mode == "die-early" {
				os.Exit(1)
			}
			respond(req.ID, `{"protocolVersion":"2025-11-25","serverInfo":{"name":"helper","version":"0"}}`)
		case "tools/list":
			switch mode {
			case "happy":
				respond(req.ID, `{"tools":[{"name":"alpha","description":"a"}]}`)
			case "chatty":
				fmt.Println("WARN: starting up, please ignore")
				fmt.Println("not json at all {{{")
				respond(req.ID, `{"tools":[{"name":"alpha","description":"a"}]}`)
			case "huge-line":
				fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[{\"name\":\"a\",\"description\":\"%s\"}]}}\n",
					req.ID, strings.Repeat("x", 1<<20))
			case "silent":
				// Never answer; the client's deadline must bound this.
			}
		default:
			// Real pre-stateless servers answer an unknown method (e.g. a modern
			// client's server/discover) with -32601 (spike-measured), which is what
			// lets the fetcher's classic fallback proceed promptly.
			fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\n", req.ID)
		}
	}
}

func TestStdioFetch(t *testing.T) {
	if _, err := exec.LookPath(os.Args[0]); err != nil && !strings.Contains(os.Args[0], "/") {
		t.Skip("cannot re-exec test binary")
	}
	t.Run("happy", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		raw, err := Fetch(ctx, helperRef("happy", "2026-07-28"), surfacelock.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if raw.Era != "2025-11-25" || len(raw.Pages) != 1 {
			t.Fatalf("era %q pages %d", raw.Era, len(raw.Pages))
		}
	})
	t.Run("chatty stdout tolerated", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		raw, err := Fetch(ctx, helperRef("chatty", "2026-07-28"), surfacelock.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(raw.Pages) != 1 {
			t.Fatalf("pages = %d", len(raw.Pages))
		}
	})
	t.Run("huge line refused", func(t *testing.T) {
		lim := surfacelock.DefaultLimits()
		lim.MaxPageBytes = 64 << 10
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := Fetch(ctx, helperRef("huge-line", "2026-07-28"), lim)
		if err == nil || !errors.Is(err, surfacelock.ErrInadmissible) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("server death reported", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := Fetch(ctx, helperRef("die-early", "2026-07-28"), surfacelock.DefaultLimits())
		if err == nil || !strings.Contains(err.Error(), "closed stdout") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("silent server bounded by deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := Fetch(ctx, helperRef("silent", "2026-07-28"), surfacelock.DefaultLimits())
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
}
