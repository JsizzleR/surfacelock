package conformance

// The validity controls (PREDICATES.md): the harness's verdicts are void
// without a deliberately non-conformant fake that FAILS its era's predicates
// and a conformant one that PASSES. Both are in-process. The live SDK control
// (CTRL-SDK) runs through `conformance/gen` against the official reference
// server; its outcome — including the H3 predicate bug it caught — is
// recorded in PREDICATES.md and its capture is retained.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// fakeClassic is a configurable 2025-11-25 Streamable-HTTP fake. The zero
// config is CTRL-GOOD; the planted* knobs are CTRL-BAD's defects, each shaped
// to isolate to its own predicate cell (the D-400 masking rule).
type fakeClassic struct {
	// S1's planted defect is modeled as a server that validates the
	// MCP-Protocol-Version header but forgot the session check: S1.nosession
	// (header, no session) is then SERVED while H3.cold (neither) is still
	// refused — each planted defect gets its own cell (the D-400 masking rule;
	// PREDICATES.md CTRL-BAD, amended pre-probe).
	plantedEchoOffered   bool // H2: echo any offered version verbatim
	plantedIgnoreSession bool // S1: mint a session id but never require it
	plantedAcceptBatch   bool // B1: answer a batch with a batch response
	plantedDuplicateTool bool // T1: same tool name on both pages
}

const fakeSession = "sess-1"

func (f *fakeClassic) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := readCappedBody(r)
		if err != nil {
			http.Error(w, "oversized", http.StatusRequestEntityTooLarge)
			return
		}
		trimmed := strings.TrimSpace(string(body))
		if strings.HasPrefix(trimmed, "[") {
			if f.plantedAcceptBatch {
				var reqs []struct {
					ID json.RawMessage `json:"id"`
				}
				_ = json.Unmarshal(body, &reqs)
				parts := make([]string, 0, len(reqs))
				for _, q := range reqs {
					parts = append(parts, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}`, q.ID))
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, "[%s]", strings.Join(parts, ","))
				return
			}
			http.Error(w, "batching was removed in 2025-06-18", http.StatusBadRequest)
			return
		}
		var in struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
				Cursor          string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch in.Method {
		case "initialize":
			version := "2025-11-25"
			if f.plantedEchoOffered {
				version = in.Params.ProtocolVersion
			}
			w.Header().Set("Mcp-Session-Id", fakeSession)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q,"serverInfo":{"name":"ctrl","version":"1"},"capabilities":{"tools":{"listChanged":false}}}}`, in.ID, version)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if f.plantedIgnoreSession {
				if r.Header.Get("MCP-Protocol-Version") == "" {
					http.Error(w, "initialize first", http.StatusBadRequest)
					return
				}
			} else if r.Header.Get("Mcp-Session-Id") != fakeSession {
				http.Error(w, "Missing session ID", http.StatusBadRequest)
				return
			}
			switch in.Params.Cursor {
			case "":
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"alpha","description":"a","inputSchema":{"type":"object"}}],"nextCursor":"p2"}}`, in.ID)
			case "p2":
				name := "beta"
				if f.plantedDuplicateTool {
					name = "alpha"
				}
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":%q,"description":"b","inputSchema":{"type":"object"}}]}}`, in.ID, name)
			default:
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"invalid cursor"}}`, in.ID)
			}
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, in.ID)
		}
	})
}

func readCappedBody(r *http.Request) ([]byte, error) {
	b := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := r.Body.Read(buf)
		total += n
		if total > maxBodyBytes {
			return nil, fmt.Errorf("oversized")
		}
		b = append(b, buf[:n]...)
		if err != nil {
			return b, nil
		}
	}
}

func gradeFake(t *testing.T, f *fakeClassic) *Report {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	rep, err := Check(context.Background(), "ctrl", NewHTTPDialer(srv.URL, srv.Client(), nil), "2025-11-25")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return rep
}

func cellOf(t *testing.T, r *Report, probe string) Cell {
	t.Helper()
	for _, c := range r.Cells {
		if c.Probe == probe {
			return c
		}
	}
	t.Fatalf("no %s cell in report: %+v", probe, r.Cells)
	return Cell{}
}

// CTRL-GOOD: the conformant fake grades CONFORMANT with zero violations.
func TestControlGoodFakeIsConformant(t *testing.T) {
	rep := gradeFake(t, &fakeClassic{})
	if rep.Verdict != Conformant {
		t.Fatalf("verdict = %s, want CONFORMANT; cells: %+v", rep.Verdict, rep.Cells)
	}
	for _, c := range rep.Cells {
		if c.Outcome == MustViolation || c.Outcome == ShouldViolation {
			t.Errorf("conformant control flagged: %s %s — %s", c.Probe, c.Outcome, c.Evidence)
		}
	}
	// The graded cells the era requires must actually have been graded — a
	// verdict resting on unreached cells is the vacuity this control exists to
	// catch.
	for _, p := range []string{"H1.init", "H2.newer", "H3.cold", "D1.discover", "S1.session", "T1.tools", "T2.badcursor", "B1.batch"} {
		c := cellOf(t, rep, p)
		if c.Outcome == Unreached {
			t.Errorf("%s unreached on the good control: %s", p, c.Evidence)
		}
	}
}

// CTRL-BAD: each planted defect flags its own cell — (b)/(c)/(d) as MUST
// violations at the claimed era, (a) as the H2 cross-grade flag whose
// cross-grade at the echoed era is NONCONFORMANT (PREDICATES.md, amended
// pre-probe), and nothing else is flagged.
func TestControlBadFakeFlagsExactlyThePlantedDefects(t *testing.T) {
	bad := &fakeClassic{
		plantedEchoOffered:   true,
		plantedIgnoreSession: true,
		plantedAcceptBatch:   true,
		plantedDuplicateTool: true,
	}
	rep := gradeFake(t, bad)
	if rep.Verdict != Nonconformant {
		t.Fatalf("verdict = %s, want NONCONFORMANT", rep.Verdict)
	}
	wantMust := map[string]bool{"S1.session": true, "B1.batch": true, "T1.tools": true}
	for _, c := range rep.Cells {
		switch c.Outcome {
		case MustViolation:
			if !wantMust[c.Probe] {
				t.Errorf("unplanted MUST violation: %s — %s", c.Probe, c.Evidence)
			}
			delete(wantMust, c.Probe)
		case ShouldViolation:
			t.Errorf("unplanted SHOULD violation: %s — %s", c.Probe, c.Evidence)
		}
	}
	for p := range wantMust {
		t.Errorf("planted defect not flagged: %s", p)
	}
	// Planted (a): the H2 echo is flagged for cross-grading...
	h2 := cellOf(t, rep, "H2.newer")
	if h2.Outcome != Observed || !strings.Contains(h2.Evidence, "cross-grade") {
		t.Errorf("H2 echo not flagged for cross-grading: %s — %s", h2.Outcome, h2.Evidence)
	}
	// ...and the cross-grade at the echoed era is NONCONFORMANT (the fake
	// speaks no server/discover, mints sessions, omits resultType).
	srv := httptest.NewServer(bad.handler())
	t.Cleanup(srv.Close)
	cross, err := Check(context.Background(), "ctrl-cross", NewHTTPDialer(srv.URL, srv.Client(), nil), StatelessEra)
	if err != nil {
		t.Fatalf("cross-grade: %v", err)
	}
	if cross.Verdict != Nonconformant {
		t.Errorf("cross-grade verdict = %s, want NONCONFORMANT", cross.Verdict)
	}
}

// A dead target must grade UNGRADED and fail an era claim — silence is not
// conformance (the D-418 rule applied to the matrix).
func TestUnreachableTargetIsUngradedNeverConformant(t *testing.T) {
	rep, err := Check(context.Background(), "dead", NewHTTPDialer("http://127.0.0.1:1/mcp", nil, nil), "2025-11-25")
	if err != nil {
		t.Fatalf("Check should capture, not error: %v", err)
	}
	if rep.Verdict != Ungraded {
		t.Fatalf("verdict = %s, want UNGRADED; cells: %+v", rep.Verdict, rep.Cells)
	}
	if err := ValidateEraClaim(rep); err == nil {
		t.Fatal("ValidateEraClaim passed an unreachable target")
	}
}

// ValidateEraClaim's polarity table.
func TestValidateEraClaim(t *testing.T) {
	for _, tc := range []struct {
		verdict Verdict
		wantErr bool
	}{
		{Conformant, false},
		{ConformantStar, false},
		{Nonconformant, true},
		{Ungraded, true},
	} {
		err := ValidateEraClaim(&Report{Target: "t", Era: "2025-11-25", Verdict: tc.verdict,
			Cells: []Cell{{Probe: "T1.tools", Outcome: MustViolation, Evidence: "x"}}})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.verdict, err, tc.wantErr)
		}
	}
}

// The matrix renderers are generated faces of the same reports: the TSV must
// carry one row per report with the verdict, and the MD must never hide an
// unreached cell (no-silent-caps).
func TestMatrixRenderers(t *testing.T) {
	rep := gradeFake(t, &fakeClassic{})
	dead, _ := Check(context.Background(), "dead", NewHTTPDialer("http://127.0.0.1:1/mcp", nil, nil), "2025-11-25")
	tsv := RenderMatrixTSV([]*Report{rep, dead})
	if !strings.Contains(tsv, "ctrl\thttp\t2025-11-25\tCONFORMANT") {
		t.Errorf("TSV lacks the conformant row:\n%s", tsv)
	}
	if !strings.Contains(tsv, "dead\thttp\t2025-11-25\tUNGRADED") {
		t.Errorf("TSV lacks the ungraded row:\n%s", tsv)
	}
	md := RenderMatrixMD([]*Report{rep, dead})
	if !strings.Contains(md, "UNGRADED") || !strings.Contains(md, "unreached") {
		t.Errorf("MD hides the unreached target:\n%s", md)
	}
}

// The capability gate (PREDICATES.md "Capability gating"): a resources-only
// server — bastle's okffacade shape — must get na(no-tools-capability) on the
// tools-probed cells, never violations manufactured from the prober's own
// inapplicable tools/list. The other direction is CTRL-BAD above: a fake that
// DOES advertise tools keeps its T1 defect flagged, so the gate cannot
// swallow a real tools server's violation (the two directions mask each
// other's mutants — each needs its own leg, D-400).
func TestToolslessServerGetsNAToolsCellsNotViolations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if len(in.Params.Meta) < 2 {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"missing _meta envelope"}}`, in.ID)
			return
		}
		switch in.Method {
		case "server/discover":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"serverInfo":{"name":"res-only","version":"1"},"capabilities":{"resources":{}}}}`, in.ID)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unsupported method"}}`, in.ID)
		}
	}))
	t.Cleanup(srv.Close)
	rep, err := Check(context.Background(), "res-only", NewHTTPDialer(srv.URL, srv.Client(), nil), StatelessEra)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, p := range []string{"H3.cold", "T1.tools", "T2.badcursor", "C1.cacheable", "V2.mismatch"} {
		c := cellOf(t, rep, p)
		if c.Outcome != NotApplicable {
			t.Errorf("%s = %s (%s), want na(no-tools-capability)", p, c.Outcome, c.Evidence)
		}
	}
	if rep.Verdict != Conformant {
		t.Errorf("verdict = %s, want CONFORMANT for the conformant resources-only server; cells: %+v", rep.Verdict, rep.Cells)
	}
}

// CheckLockEntry joins a lockfile entry to the era check: the entry's own
// transport/target is probed and its recorded era graded. Era mapping and
// polarity, not a re-test of the graders.
func TestCheckLockEntryValidatesTheRecordedEra(t *testing.T) {
	srv := httptest.NewServer((&fakeClassic{}).handler())
	t.Cleanup(srv.Close)
	good := &surfacelock.ServerLock{Transport: "http", Target: srv.URL,
		Protocol: surfacelock.Protocol{Offered: "2025-11-25", Era: "2025-11-25", Flow: "classic"}}
	rep, err := CheckLockEntry(context.Background(), good)
	if err != nil {
		t.Fatalf("conformant entry failed its era claim: %v (verdict %s)", err, rep.Verdict)
	}
	// A claim against a dead target must FAIL, never pass silently.
	dead := &surfacelock.ServerLock{Transport: "http", Target: "http://127.0.0.1:1/mcp",
		Protocol: surfacelock.Protocol{Offered: "2025-11-25", Era: "2025-11-25", Flow: "classic"}}
	if _, err := CheckLockEntry(context.Background(), dead); err == nil {
		t.Fatal("dead target passed its era claim")
	}
}

// A truncated capture must never grade a violation: the wire exchange may
// have been fine, and a cell may not rest on cut bytes (the tp-notion
// resolution in PREDICATES.md).
func TestTruncatedExchangeGradesUnreachedNeverViolation(t *testing.T) {
	cp := &Capture{Target: "trunc", Kind: "stdio", Era: "2025-11-25", Exchanges: []*Exchange{
		{Probe: "H1.init", Message: `{"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"x","version":"1"},"capabilities":{"tools":{}}}}`},
		{Probe: "T1.page0", Body: `{"result":{"tools":[{"na`, Truncated: true},
	}}
	rep := Grade(cp)
	c := cellOf(t, rep, "T1.tools")
	if c.Outcome != Unreached {
		t.Errorf("T1.tools on a truncated page = %s (%s), want unreached", c.Outcome, c.Evidence)
	}
}

// A dual-era server (classic handshake AND a valid server/discover) is
// spec-permitted: classic-era D1 flags it for cross-grading, never as a
// violation — while a server "answering" discover without the DiscoverResult
// shape still violates (the tp-context7 resolution in PREDICATES.md).
func TestDualEraDiscoverIsObservedNotViolation(t *testing.T) {
	dualEra := func(discover string) *Report {
		inner := (&fakeClassic{}).handler()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := readCappedBody(r)
			var in struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			_ = json.Unmarshal(body, &in)
			if in.Method == "server/discover" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, in.ID, discover)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body)) // hand the fake an unconsumed body
			inner.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		rep, err := Check(context.Background(), "dual", NewHTTPDialer(srv.URL, srv.Client(), nil), "2025-11-25")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return rep
	}
	// This wrapper intercepts discover BEFORE the fake's session gate, which is
	// exactly the dual-era shape: discover answers cold.
	rep := dualEra(`{"supportedVersions":["2026-07-28"],"serverInfo":{"name":"dual","version":"1"},"capabilities":{}}`)
	c := cellOf(t, rep, "D1.discover")
	if c.Outcome != Observed || !strings.Contains(c.Evidence, "cross-grade") {
		t.Errorf("valid dual-era discover = %s (%s), want obs with a cross-grade flag", c.Outcome, c.Evidence)
	}
	rep = dualEra(`{"echo":"server/discover"}`)
	if c := cellOf(t, rep, "D1.discover"); c.Outcome != MustViolation {
		t.Errorf("shapeless discover 'success' = %s (%s), want a MUST violation", c.Outcome, c.Evidence)
	}
}
