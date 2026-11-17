package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// bs spells a JSON escape's backslash, so a leg's wire bytes carry the escape
// itself, never the character an editor might substitute for it.
const bs = `\`

const confirmResult = `{"supportedVersions":["2026-07-28"],"serverInfo":{"name":"s","version":"1"}}`

func modernOnlyFoldedNull(id json.RawMessage) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"u","data":{"supported":["2027-03-01"]}},"ERROR":null}`, id)
}

// A message an exact-key reader and the envelope's case-folding struct decode
// read differently ends the probe: neither reading is the answer, so neither a
// classic fallback nor a modern commit may follow it. So does an answer to the
// request that carries neither a result nor an error.
func TestFetchUnreadableAnswerEndsTheProbe(t *testing.T) {
	cases := []struct {
		name  string
		ctype string
		body  func(id json.RawMessage) string
	}{
		{"a modern-only refusal hidden by a folded null", jsonCT, modernOnlyFoldedNull},
		{"the same over SSE", sseCT, func(id json.RawMessage) string { return sse(modernOnlyFoldedNull(id)) }},
		{"a folded result beside an exact refusal", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"u","data":{"supported":["2027-03-01"]}},"ERROR":null,"RESULT":%s}`, id, confirmResult)
		}},
		{"a folded error beside an exact result", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s,"Error":{"code":-32601,"message":"m"}}`, id, confirmResult)
		}},
		{"a folded id answering for another", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":999,"ID":%s,"result":%s}`, id, confirmResult)
		}},
		{"an answer with neither result nor error", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s}`, id)
		}},
		{"the same over SSE", sseCT, func(id json.RawMessage) string { return sse(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s}`, id)) }},
		// An exact reader picks one of the two; which one it picks decides
		// between a commit and a fallback (here a legacy -32601).
		{"an answer with both a result and an error", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s,"error":{"code":-32601,"message":"m"}}`, id, confirmResult)
		}},
		{"a result beside a null error", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s,"error":null}`, id, confirmResult)
		}},
		{"a string error code", jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":"-32601","message":"m"}}`, id)
		}},
		// SSE joins an event's data lines with a line feed, so "-326" then "01"
		// is no number to any SSE reader; concatenated, it read as a -32601 and
		// fell back.
		{"an SSE code split across two data lines", sseCT, func(id json.RawMessage) string {
			return fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-326\ndata: 01,\"message\":\"m\"}}\n\n", id)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			srv := httptest.NewServer(dualEraHandler(t, refuseAlways(http.StatusOK, tc.ctype, tc.body), &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if err == nil {
				t.Fatalf("Fetch locked flow %q era %q, want the probe to end", raw.Flow, raw.Era)
			}
			if !strings.Contains(err.Error(), "no classic fallback") {
				t.Errorf("error %q does not say the fallback was withheld", err)
			}
			if got := discovers.Load(); got != 1 {
				t.Errorf("server/discover sent %d times, want 1", got)
			}
			if got := initializes.Load(); got != 0 {
				t.Errorf("initialize sent %d times, want 0", got)
			}
		})
	}
}

// Over stdio the same message ends the probe too: a closed child is no modern
// evidence, but an unreadable answer is not a closed child.
func TestFetchStdioUnreadableAnswerEndsTheProbe(t *testing.T) {
	raw, err := Fetch(context.Background(), helperRef("alias-at-discover", ""), surfacelock.DefaultLimits())
	if err == nil {
		t.Fatalf("Fetch locked flow %q era %q, want the probe to end", raw.Flow, raw.Era)
	}
	if !strings.Contains(err.Error(), "case-variant") || !strings.Contains(err.Error(), "no classic fallback") {
		t.Errorf("error %q does not name the case-variant key and the withheld fallback", err)
	}
}

// Positive control: a child that exits at server/discover is a pre-revision
// server as far as the probe can tell, and the classic fallback locks it.
func TestFetchStdioDeadChildAtDiscoverFallsBack(t *testing.T) {
	raw, err := Fetch(context.Background(), helperRef("die-at-discover", ""), surfacelock.DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch: %v, want the classic fallback", err)
	}
	if raw.Flow != FlowClassic || raw.Era != "2025-11-25" {
		t.Errorf("flow %q era %q, want %q %q", raw.Flow, raw.Era, FlowClassic, "2025-11-25")
	}
}

// A discover result with no exact form is refused, with no classic fallback,
// whichever form its inexact token takes: the canonicalizer refuses some
// (a trailing lone half) and passes others (two halves in a row), and either
// way the result is a modern answer that names the offer.
func TestFetchInexactDiscoverResultIsRefused(t *testing.T) {
	for _, el := range []string{
		`"` + bs + `ud800"`,
		`"` + bs + `ud800` + bs + `ud800"`,
		`"` + bs + `ude00` + bs + `ud83d"`,
		`"` + bs + `ud800` + bs + `u0041"`,
		"\"\xff\"",
	} {
		t.Run(el, func(t *testing.T) {
			var discovers, initializes atomic.Int64
			answer := refuseAlways(http.StatusOK, jsonCT, func(id json.RawMessage) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"supportedVersions":["2026-07-28",%s],"serverInfo":{"name":"s","version":"1"}}}`, id, el)
			})
			srv := httptest.NewServer(dualEraHandler(t, answer, &discovers, &initializes))
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
			if !errors.Is(err, surfacelock.ErrInadmissible) {
				t.Fatalf("Fetch: %v (flow %v), want ErrInadmissible", err, raw)
			}
			if got := initializes.Load(); got != 0 {
				t.Errorf("initialize sent %d times, want 0", got)
			}
		})
	}
	t.Run("paired control", func(t *testing.T) {
		var discovers, initializes atomic.Int64
		answer := refuseAlways(http.StatusOK, jsonCT, func(id json.RawMessage) string {
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"supportedVersions":["2026-07-28","`+bs+`ud83d`+bs+`ude00"],"serverInfo":{"name":"s","version":"1"}}}`, id)
		})
		srv := httptest.NewServer(dualEraHandler(t, answer, &discovers, &initializes))
		defer srv.Close()
		raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
		if err != nil || raw.Flow != FlowStateless {
			t.Fatalf("Fetch: %v (%v), want the stateless flow", err, raw)
		}
	})
}

// A long number is still a number: the code it prints is bounded.
func TestRPCErrorCodeTextIsBounded(t *testing.T) {
	e := newRPCCallError("m", &rpcError{Code: rpcCode("-3" + strings.Repeat("0", 5000)), Message: "x"}, nil)
	if n := len(e.Error()); n > 100 {
		t.Errorf("error text is %d bytes for a 5000-digit code", n)
	}
}

// A code that is not a number is refused in fixed words: json.Number's own
// refusal quotes the whole string. Measured: 5082 bytes for a 5000-byte code.
func TestRPCErrorStringCodeTextIsBounded(t *testing.T) {
	var discovers, initializes atomic.Int64
	long := strings.Repeat("A", 5000)
	answer := refuseAlways(http.StatusOK, jsonCT, func(id json.RawMessage) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":"%s","message":"m"}}`, id, long)
	})
	srv := httptest.NewServer(dualEraHandler(t, answer, &discovers, &initializes))
	defer srv.Close()
	_, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatal("Fetch succeeded on a string error code")
	}
	if strings.Contains(err.Error(), "AAAA") || len(err.Error()) > 1000 {
		t.Errorf("error text (%d bytes) quotes the hostile code", len(err.Error()))
	}
}

// Positive controls: a number of another spelling is a code, and an SSE event
// split between tokens reads as one message once its lines are joined.
func TestRPCCodeSpellingsAndSplitSSEAreRead(t *testing.T) {
	var c rpcCode
	for _, in := range []string{`-32022`, `-32022.0`, `-3.2022e4`, `null`} {
		if err := json.Unmarshal([]byte(in), &c); err != nil {
			t.Errorf("code %s refused: %v", in, err)
		}
	}
	for _, in := range []string{`"-32022"`, `true`, `{}`, `[]`} {
		if err := json.Unmarshal([]byte(in), &c); err == nil {
			t.Errorf("code %s accepted as %q", in, c)
		}
	}
	var discovers, initializes atomic.Int64
	answer := refuseAlways(http.StatusOK, sseCT, func(id json.RawMessage) string {
		return fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\ndata: \"result\":%s}\n\n", id, confirmResult)
	})
	srv := httptest.NewServer(dualEraHandler(t, answer, &discovers, &initializes))
	defer srv.Close()
	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL}, surfacelock.DefaultLimits())
	if err != nil || raw.Flow != FlowStateless {
		t.Fatalf("Fetch: %v (%v), want the stateless flow from a split SSE event", err, raw)
	}
}
