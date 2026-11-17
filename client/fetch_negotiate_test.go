package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// ---- the pre-commit fallback reads a modern refusal before it falls back ----
//
// The reference client's probe classifier (@modelcontextprotocol/client 2.0.0,
// src/client/probeClassifier.ts, measured from its published dist): only a
// -32022 UnsupportedProtocolVersion whose data.supported is a non-empty array
// of strings is era evidence. A list naming the offered revision earns ONE
// corrective retry of the probe; a list naming only other modern revisions
// (from 2026-07-28 on, compared as strings) is an error with no classic
// fallback; a legacy-only list falls back. -32020, -32021, -32001 and every
// other code are not era evidence and fall back. A non-2xx body is classified
// the same way (classifyHttpError parses it as a JSON-RPC error).

// discoverAnswer writes one server/discover answer; n is 1 for the first.
type discoverAnswer func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64)

// dualEraHandler is an honest dual-era server: classic initialize at
// 2025-11-25, a modern tools/list, and server/discover answered by answer (a
// clean modern result when answer is nil or declines by writing nothing).
func dualEraHandler(t *testing.T, answer discoverAnswer, discovers, initializes *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
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
			n := discovers.Add(1)
			if answer != nil {
				answer(t, w, in, n)
				return
			}
			modernDiscoverResult(t, w, in)
		case "initialize":
			initializes.Add(1)
			rpcResult(t, w, in.ID, map[string]any{"protocolVersion": "2025-11-25", "serverInfo": map[string]any{"name": "dual", "version": "1"}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			rpcResult(t, w, in.ID, map[string]any{"tools": []map[string]any{{"name": "frob", "description": "Frob.", "inputSchema": map[string]any{"type": "object"}}}})
		default:
			rpcErrorReply(t, w, in.ID, -32601, "method not found")
		}
	}
}

func modernDiscoverResult(t *testing.T, w http.ResponseWriter, in rpcIn) {
	rpcResult(t, w, in.ID, map[string]any{
		"supportedVersions": []string{ModernRevision, "2025-11-25"},
		"serverInfo":        map[string]any{"name": "dual", "version": "1"},
		"capabilities":      map[string]any{"tools": map[string]any{}},
	})
}

// rawReply writes body verbatim with the given status and content type.
func rawReply(w http.ResponseWriter, status int, ctype, body string) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

// unsupported32022 is a -32022 error message naming the given supported list
// (a raw JSON value, so the legs can send shapes a typed encoder cannot).
func unsupported32022(id json.RawMessage, supported string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":%s,"requested":"2026-07-28"}}}`, id, supported)
}

// refuseFirst answers the first discover with body (at status) and every later
// one with a clean modern result.
func refuseFirst(status int, ctype string, body func(id json.RawMessage) string) discoverAnswer {
	return func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64) {
		if n == 1 {
			rawReply(w, status, ctype, body(in.ID))
			return
		}
		modernDiscoverResult(t, w, in)
	}
}

// refuseAlways answers every discover with body (at status).
func refuseAlways(status int, ctype string, body func(id json.RawMessage) string) discoverAnswer {
	return func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64) {
		rawReply(w, status, ctype, body(in.ID))
	}
}

func sse(body string) string { return "event: message\ndata: " + body + "\n\n" }

const jsonCT, sseCT = "application/json", "text/event-stream"

// A correctable modern refusal earns one corrective retry of server/discover,
// and the fetch then commits to the stateless flow, never the classic one.
func TestFetchCorrectiveRetryOnUnsupportedVersionListingTheOffer(t *testing.T) {
	offerAndLegacy := func(id json.RawMessage) string {
		return unsupported32022(id, `["2026-07-28","2025-11-25"]`)
	}
	cases := []struct {
		name   string
		answer discoverAnswer
	}{
		{"HTTP 400 carrying -32022", refuseFirst(http.StatusBadRequest, jsonCT, offerAndLegacy)},
		{"HTTP 200 JSON-RPC error -32022", refuseFirst(http.StatusOK, jsonCT, offerAndLegacy)},
		{"HTTP 200 SSE JSON-RPC error -32022", refuseFirst(http.StatusOK, sseCT, func(id json.RawMessage) string { return sse(offerAndLegacy(id)) })},
		{"HTTP 404 carrying -32022, a text/plain content type", refuseFirst(http.StatusNotFound, "text/plain", offerAndLegacy)},
		{"the offer alone", refuseFirst(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string { return unsupported32022(id, `["2026-07-28"]`) })},
		{"code written -32022.0 (a JSON number equal to it)", refuseFirst(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return strings.Replace(unsupported32022(id, `["2026-07-28"]`), `-32022`, `-32022.0`, 1)
		})},
		{"duplicate supported member, the last one names the offer (JSON.parse is last-wins)", refuseFirst(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"m","data":{"supported":["2025-11-25"],"supported":["2026-07-28"]}}}`, id)
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, tc.answer, &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if raw.Flow != FlowStateless || raw.Era != ModernRevision {
				t.Errorf("flow %q era %q, want %q %q: a correctable modern refusal fell back to classic", raw.Flow, raw.Era, FlowStateless, ModernRevision)
			}
			if got := discovers.Load(); got != 2 {
				t.Errorf("server/discover sent %d times, want 2 (one corrective retry)", got)
			}
			if got := initializes.Load(); got != 0 {
				t.Errorf("initialize sent %d times, want 0", got)
			}
		})
	}
}

// Modern evidence with no way forward ends the fetch: a server that refuses
// the offer it lists after the one retry, or that lists only other modern
// revisions, is a modern server, and a classic lock of it would attest a flow
// no modern client uses with it.
func TestFetchModernRefusalForbidsTheClassicFallback(t *testing.T) {
	cases := []struct {
		name          string
		answer        discoverAnswer
		wantDiscovers int64
	}{
		{"-32022 listing the offer, twice", refuseAlways(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return unsupported32022(id, `["2026-07-28","2025-11-25"]`)
		}), 2},
		{"-32022 listing only a later modern revision", refuseAlways(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return unsupported32022(id, `["2027-03-01"]`)
		}), 1},
		{"-32022 listing a later modern and a legacy revision", refuseAlways(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return unsupported32022(id, `["2027-03-01","2025-11-25"]`)
		}), 1},
		{"-32022 in a 2xx JSON-RPC error, a later modern revision", refuseAlways(http.StatusOK, jsonCT, func(id json.RawMessage) string {
			return unsupported32022(id, `["2027-03-01"]`)
		}), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, tc.answer, &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if err == nil {
				t.Fatalf("Fetch locked flow %q era %q, want a refusal with no classic fallback", raw.Flow, raw.Era)
			}
			if !strings.Contains(err.Error(), "-32022") || !strings.Contains(err.Error(), "no classic fallback") {
				t.Errorf("error %q does not name the -32022 refusal and the withheld fallback", err)
			}
			if errors.Is(err, surfacelock.ErrInadmissible) {
				t.Errorf("error %q classed inadmissible; a negotiation failure is a protocol failure", err)
			}
			if got := discovers.Load(); got != tc.wantDiscovers {
				t.Errorf("server/discover sent %d times, want %d", got, tc.wantDiscovers)
			}
			if got := initializes.Load(); got != 0 {
				t.Errorf("initialize sent %d times after modern evidence, want 0", got)
			}
		})
	}
}

// Everything that is not modern evidence still falls back to ONE classic
// attempt, as it did before: the positive controls of the classifier.
func TestFetchNonEvidenceStillFallsBack(t *testing.T) {
	msg := func(code, data string) func(id json.RawMessage) string {
		return func(id json.RawMessage) string {
			d := ""
			if data != "" {
				d = `,"data":` + data
			}
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%s,"message":"m"%s}}`, id, code, d)
		}
	}
	cases := []struct {
		name   string
		status int
		body   func(id json.RawMessage) string
	}{
		{"-32022 listing only legacy revisions", http.StatusBadRequest, msg("-32022", `{"supported":["2025-11-25","2025-06-18"]}`)},
		{"-32020 HeaderMismatch (not era evidence)", http.StatusBadRequest, msg("-32020", `{"supported":["2026-07-28"]}`)},
		{"-32021 MissingRequiredClientCapability", http.StatusBadRequest, msg("-32021", "")},
		{"-32001 session not found", http.StatusNotFound, msg("-32001", "")},
		{"-32601 method not found, 2xx", http.StatusOK, msg("-32601", "")},
		{"-32022 with no data", http.StatusBadRequest, msg("-32022", "")},
		{"-32022 with an empty list", http.StatusBadRequest, msg("-32022", `{"supported":[]}`)},
		{"-32022 with a non-string element", http.StatusBadRequest, msg("-32022", `{"supported":["2026-07-28",1]}`)},
		{"-32022 with a null element", http.StatusBadRequest, msg("-32022", `{"supported":["2026-07-28",null]}`)},
		{"-32022 with a non-array list", http.StatusBadRequest, msg("-32022", `{"supported":"2026-07-28"}`)},
		{"-32022 with data an array", http.StatusBadRequest, msg("-32022", `[{"supported":["2026-07-28"]}]`)},
		{"-32022 under a case-variant data key (JSON.parse is case-sensitive)", http.StatusBadRequest, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"m","DATA":{"supported":["2026-07-28"]}}}`, id)
		}},
		{"-32022 under a case-variant supported key", http.StatusBadRequest, msg("-32022", `{"Supported":["2026-07-28"]}`)},
		{"-32022 written as a string code", http.StatusBadRequest, msg(`"-32022"`, `{"supported":["2026-07-28"]}`)},
		{"a 400 with a plain-text body", http.StatusBadRequest, func(json.RawMessage) string { return "Bad Request: no such method" }},
		{"a 405 with no body", http.StatusMethodNotAllowed, func(json.RawMessage) string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, refuseAlways(tc.status, jsonCT, tc.body), &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if err != nil {
				t.Fatalf("Fetch: %v (want the classic fallback)", err)
			}
			if raw.Flow != FlowClassic || raw.Era != "2025-11-25" {
				t.Errorf("flow %q era %q, want the classic fallback at 2025-11-25", raw.Flow, raw.Era)
			}
			if got := discovers.Load(); got != 1 {
				t.Errorf("server/discover sent %d times, want 1 (no retry on non-evidence)", got)
			}
			if got := initializes.Load(); got != 1 {
				t.Errorf("initialize sent %d times, want 1", got)
			}
		})
	}
}

// A pinned stateless flow (a verify of a stateless lock) takes the same
// corrective retry; it never had a fallback.
func TestFetchPinnedStatelessTakesTheCorrectiveRetry(t *testing.T) {
	var discovers, initializes atomic.Int64
	srv := httptest.NewServer(dualEraHandler(t, refuseFirst(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
		return unsupported32022(id, `["2026-07-28"]`)
	}), &discovers, &initializes))
	defer srv.Close()
	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Flow: FlowStateless}, surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Flow != FlowStateless || discovers.Load() != 2 || initializes.Load() != 0 {
		t.Errorf("flow %q, %d discovers, %d initializes; want stateless, 2, 0", raw.Flow, discovers.Load(), initializes.Load())
	}
}

// stdio carries the same JSON-RPC refusal; the helper answers the first
// discover -32022 listing the offer, then a clean modern result.
func TestFetchStdioCorrectiveRetry(t *testing.T) {
	raw, err := Fetch(context.Background(), helperRef("modern-corrective", ""), surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if raw.Flow != FlowStateless || raw.Era != ModernRevision {
		t.Errorf("flow %q era %q, want %q %q", raw.Flow, raw.Era, FlowStateless, ModernRevision)
	}
}

// The reference ends its HTTP probe, with no classic fallback, on 401, 403
// and any status from 500 whatever the body, on a refusal body it cannot read
// whole, and wherever no answer is left to read.
func TestFetchHTTPProbeEndsWithoutFallback(t *testing.T) {
	offer := func(id json.RawMessage) string { return unsupported32022(id, `["2026-07-28"]`) }
	plain := func(json.RawMessage) string { return "nope" }
	cases := []struct {
		name   string
		answer discoverAnswer
		lim    func(*surfacelock.Limits)
	}{
		{"HTTP 401", refuseAlways(http.StatusUnauthorized, "text/plain", plain), nil},
		{"HTTP 403 carrying a -32022 listing the offer", refuseAlways(http.StatusForbidden, jsonCT, offer), nil},
		{"HTTP 500", refuseAlways(http.StatusInternalServerError, "text/plain", plain), nil},
		{"HTTP 503 carrying a -32022 listing the offer", refuseAlways(http.StatusServiceUnavailable, jsonCT, offer), nil},
		{"a 2xx of another content type", refuseAlways(http.StatusOK, "text/html", plain), nil},
		{"a 2xx JSON body that does not parse", refuseAlways(http.StatusOK, jsonCT, plain), nil},
		{"a 2xx JSON-RPC answer to another id", refuseAlways(http.StatusOK, jsonCT, func(json.RawMessage) string {
			return `{"jsonrpc":"2.0","id":99,"error":{"code":-32601,"message":"m"}}`
		}), nil},
		{"an SSE stream with no answer", refuseAlways(http.StatusOK, sseCT, func(json.RawMessage) string {
			return sse(`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`)
		}), nil},
		{"a 202 with no body", refuseAlways(http.StatusAccepted, jsonCT, func(json.RawMessage) string { return "" }), nil},
		{"a 400 refusal body past the page cap", refuseAlways(http.StatusBadRequest, jsonCT, func(id json.RawMessage) string {
			return strings.Replace(offer(id), `"requested"`, `"pad":"`+strings.Repeat("x", 600)+`","requested"`, 1)
		}), func(l *surfacelock.Limits) { l.MaxPageBytes = 512 }},
		{"the connection dropped", func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, tc.answer, &discovers, &initializes))
			defer srv.Close()
			lim := surfacelock.DefaultLimits()
			if tc.lim != nil {
				tc.lim(&lim)
			}
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, lim)
			if err == nil {
				t.Fatalf("Fetch locked flow %q era %q, want the probe to end with no classic fallback", raw.Flow, raw.Era)
			}
			if !strings.Contains(err.Error(), "no classic fallback") {
				t.Errorf("error %q does not say the fallback was withheld", err)
			}
			if got := initializes.Load(); got != 0 {
				t.Errorf("initialize sent %d times, want 0", got)
			}
			if got := discovers.Load(); got != 1 {
				t.Errorf("server/discover sent %d times, want 1", got)
			}
			assertNoRetainedBody(t, err)
		})
	}
}

// The status rows' neighbours still fall back: a 4xx other than 401/403 with
// no modern evidence (the honest legacy population: 400, 404, 405).
func TestFetchOtherClientErrorStatusesFallBack(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusConflict, 499} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, refuseAlways(status, "text/plain", func(json.RawMessage) string { return "no" }), &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if err != nil || raw.Flow != FlowClassic || initializes.Load() != 1 {
				t.Fatalf("Fetch: %v; want the classic fallback", err)
			}
		})
	}
}

// After the corrective retry the reference classifies the second answer
// afresh: no modern evidence there falls back, as it does on a first answer.
func TestFetchRetryThenNonEvidenceFallsBack(t *testing.T) {
	var discovers, initializes atomic.Int64
	answer := func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64) {
		if n == 1 {
			rawReply(w, http.StatusBadRequest, jsonCT, unsupported32022(in.ID, `["2026-07-28"]`))
			return
		}
		rpcErrorReply(t, w, in.ID, -32601, "method not found")
	}
	srv := httptest.NewServer(dualEraHandler(t, answer, &discovers, &initializes))
	defer srv.Close()
	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil || raw.Flow != FlowClassic || discovers.Load() != 2 || initializes.Load() != 1 {
		t.Fatalf("Fetch: %v, %d discovers, %d initializes; want the classic fallback after one retry", err, discovers.Load(), initializes.Load())
	}
}

// The corrective retry is a whole stateless request: both discovers carry the
// _meta envelope and the request-metadata headers that mirror it.
func TestFetchCorrectiveRetryCarriesTheModernHeaders(t *testing.T) {
	var discovers, initializes atomic.Int64
	answer := func(t *testing.T, w http.ResponseWriter, in rpcIn, n int64) {
		if !fullMeta(in) {
			t.Errorf("discover %d carried no full _meta envelope", n)
		}
		if n == 1 {
			rawReply(w, http.StatusBadRequest, jsonCT, unsupported32022(in.ID, `["2026-07-28"]`))
			return
		}
		modernDiscoverResult(t, w, in)
	}
	srv := httptest.NewServer(headerCheckingDualEra(t, answer, &discovers, &initializes))
	defer srv.Close()
	if _, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if discovers.Load() != 2 {
		t.Fatalf("%d discovers, want 2", discovers.Load())
	}
}

// headerCheckingDualEra is dualEraHandler with each discover's headers checked
// against its body (the -32020 rung a conformant server applies).
func headerCheckingDualEra(t *testing.T, answer discoverAnswer, discovers, initializes *atomic.Int64) http.HandlerFunc {
	inner := dualEraHandler(t, nil, discovers, initializes)
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in rpcIn
		_ = json.Unmarshal(body, &in)
		if in.Method == "server/discover" {
			if why := modernHeaderMismatch(r, in); why != "" {
				t.Errorf("discover: %s", why)
			}
			answer(t, w, in, discovers.Add(1))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		inner(w, r)
	}
}

// A -32022 after the commit point never restarts negotiation: the server has
// confirmed the stateless flow, so its tools/list refusal is terminal.
func TestFetchPostCommitUnsupportedVersionIsTerminal(t *testing.T) {
	var discovers, initializes, lists atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Method {
		case "server/discover":
			discovers.Add(1)
			modernDiscoverResult(t, w, in)
		case "tools/list":
			lists.Add(1)
			rawReply(w, http.StatusBadRequest, jsonCT, unsupported32022(in.ID, `["2026-07-28"]`))
		case "initialize":
			initializes.Add(1)
			rpcResult(t, w, in.ID, map[string]any{"protocolVersion": "2025-11-25"})
		}
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits()); err == nil {
		t.Fatal("Fetch succeeded on a refused tools/list")
	}
	if discovers.Load() != 1 || lists.Load() != 1 || initializes.Load() != 0 {
		t.Errorf("%d discovers, %d lists, %d initializes; want 1, 1, 0", discovers.Load(), lists.Load(), initializes.Load())
	}
}

// No response body outlives its classification in a returned error.
func TestFetchReturnsNoRefusalBody(t *testing.T) {
	var discovers, initializes atomic.Int64
	// Modern refusal with no evidence, then a failing classic attempt: the
	// joined error carries both arms.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Method == "server/discover" {
			discovers.Add(1)
		} else {
			initializes.Add(1)
		}
		rawReply(w, http.StatusBadRequest, jsonCT, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32600,"message":"m","data":"%s"}}`, in.ID, strings.Repeat("y", 4000)))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err == nil || discovers.Load() != 1 || initializes.Load() != 1 {
		t.Fatalf("Fetch: %v; want both arms to fail", err)
	}
	// Neither arm's body survives: not the discover refusal, and not the
	// classic initialize's, which no classifier reads.
	assertNoRetainedBody(t, err)
}

// The same after the commit point, for a JSON-RPC error answer (status 200),
// which no classifier reads: fetchOnce drops its message bytes too.
func TestFetchPostCommitErrorAnswerRetainsNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in rpcIn
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Method {
		case "server/discover":
			modernDiscoverResult(t, w, in)
		case "tools/list":
			rawReply(w, http.StatusOK, jsonCT, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"m","data":"%s"}}`, in.ID, strings.Repeat("y", 4000)))
		}
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("Fetch succeeded on a refused tools/list")
	}
	var rc *rpcCallError
	if !errors.As(err, &rc) {
		t.Fatalf("Fetch: %v; want the tools/list error answer in the chain", err)
	}
	assertNoRetainedBody(t, err)
}

func assertNoRetainedBody(t *testing.T, err error) {
	t.Helper()
	for _, e := range unwrapAll(err) {
		switch v := e.(type) {
		case *httpStatusError:
			if len(v.body) > 0 {
				t.Errorf("a refusal body (%d bytes) survived in the returned error", len(v.body))
			}
		case *rpcCallError:
			if len(v.raw) > 0 {
				t.Errorf("a refusal message (%d bytes) survived in the returned error", len(v.raw))
			}
		}
	}
}

// unwrapAll walks an error tree (Unwrap() error and Unwrap() []error).
func unwrapAll(err error) []error {
	var out []error
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		out = append(out, e)
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return out
}
