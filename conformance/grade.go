package conformance

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Outcome of one predicate cell (PREDICATES.md "Verdict model").
type Outcome string

const (
	Pass            Outcome = "pass"
	MustViolation   Outcome = "MUST-violation"
	ShouldViolation Outcome = "SHOULD-violation"
	Observed        Outcome = "obs"
	NotApplicable   Outcome = "na"
	Unreached       Outcome = "unreached"
)

// Cell is one graded predicate for one (target, era).
type Cell struct {
	Probe    string  `json:"probe"`
	Outcome  Outcome `json:"outcome"`
	Evidence string  `json:"evidence"` // one line: what was observed, why it grades this way
}

// Verdict per PREDICATES.md: CONFORMANT / CONFORMANT* / NONCONFORMANT, or
// UNGRADED when every graded cell is unreached (a dead target must never read
// as conformant — the silence-vs-$0.00 rule applied here).
type Verdict string

const (
	Conformant     Verdict = "CONFORMANT"
	ConformantStar Verdict = "CONFORMANT*"
	Nonconformant  Verdict = "NONCONFORMANT"
	Ungraded       Verdict = "UNGRADED"
)

// Report is the graded result for one capture.
type Report struct {
	Target  string  `json:"target"`
	Kind    string  `json:"kind"`
	Era     string  `json:"era"`
	Cells   []Cell  `json:"cells"`
	Verdict Verdict `json:"verdict"`
}

func (r *Report) cell(probe string, o Outcome, format string, args ...any) {
	r.Cells = append(r.Cells, Cell{Probe: probe, Outcome: o, Evidence: fmt.Sprintf(format, args...)})
}

// rpcView classifies one exchange's response for grading.
type rpcView struct {
	transportErr string
	status       int // HTTP status, 0 on stdio
	result       map[string]json.RawMessage
	errCode      int64
	errMsg       string
	isError      bool
	isBatch      bool // response body is a JSON array
	raw          string
}

func viewOf(ex *Exchange) rpcView {
	v := rpcView{status: ex.Status, raw: ex.Message}
	if ex.Err != "" {
		v.transportErr = ex.Err
	}
	body := ex.Message
	if body == "" {
		body = ex.Body
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "[") {
		v.isBatch = json.Valid([]byte(trimmed))
		return v
	}
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &env) == nil {
		v.result = env.Result
		if env.Error != nil {
			v.isError, v.errCode, v.errMsg = true, env.Error.Code, env.Error.Message
		}
	}
	return v
}

// succeeded: HTTP 2xx (or stdio) AND a JSON-RPC result present.
func (v rpcView) succeeded() bool {
	if v.transportErr != "" || v.isError || v.result == nil {
		return false
	}
	return v.status == 0 || (v.status >= 200 && v.status <= 299)
}

// unreached: the target could not be spoken to at all (dial failure, HTTP
// transport error, a stdio child that died mid-probe). An unreached exchange
// grades UNREACHED, never a verdict — an unreachable server is an honest
// error, not conformance evidence in either direction (the D-414/D-415 rule;
// a dead target must grade UNGRADED, not NONCONFORMANT, and must never "pass"
// a refusal predicate by being down).
func (v rpcView) unreached() bool { return v.transportErr != "" && v.transportErr != errSilence }

// refused: an INTENTIONAL refusal — HTTP 4xx/5xx, a JSON-RPC error, a 2xx
// with no result, or silence from a live stdio child (a server that ignores an
// inapplicable message refuses it by silence).
func (v rpcView) refused() bool { return !v.succeeded() && !v.unreached() }

func (v rpcView) summary() string {
	switch {
	case v.transportErr != "":
		return "transport: " + capString(v.transportErr, 120)
	case v.isError:
		return fmt.Sprintf("rpc error %d: %s", v.errCode, capString(v.errMsg, 120))
	case v.result != nil:
		return fmt.Sprintf("HTTP %d, result", v.status)
	default:
		return fmt.Sprintf("HTTP %d, no JSON-RPC message", v.status)
	}
}

// Grade computes the report for a capture — pure over the capture bytes, so
// the matrix is re-derivable from the retained artifacts alone.
func Grade(cap *Capture) *Report {
	r := &Report{Target: cap.Target, Kind: cap.Kind, Era: cap.Era}
	if cap.Era == StatelessEra {
		gradeStateless(cap, r)
	} else {
		gradeClassic(cap, r)
	}
	r.Verdict = verdictOf(r.Cells)
	return r
}

func verdictOf(cells []Cell) Verdict {
	graded, must, should := 0, 0, 0
	for _, c := range cells {
		switch c.Outcome {
		case MustViolation:
			must++
			graded++
		case ShouldViolation:
			should++
			graded++
		case Pass:
			graded++
		}
	}
	switch {
	case graded == 0:
		return Ungraded
	case must > 0:
		return Nonconformant
	case should > 0:
		return ConformantStar
	default:
		return Conformant
	}
}

func missing(r *Report, cap *Capture, probe string) *Exchange {
	ex := cap.find(probe)
	if ex == nil {
		r.cell(probe, Unreached, "no exchange recorded (%s)", strings.Join(cap.Notes, "; "))
	}
	return ex
}

func gradeClassic(cap *Capture, r *Report) {
	era := cap.Era
	http := cap.Kind == "http"
	hybrid := era == "2024-11-05" && http // Streamable HTTP postdates the era

	var negotiated string
	var sessionMinted bool

	// H1 — handshake, own era.
	if ex := missing(r, cap, "H1.init"); ex != nil {
		v := viewOf(ex)
		sessionMinted = ex.RespHdr["Mcp-Session-Id"] != ""
		switch {
		case v.transportErr != "":
			r.cell("H1.init", Unreached, "%s", v.summary())
		case !v.succeeded():
			r.cell("H1.init", MustViolation, "initialize(%s) refused: %s", era, v.summary())
		default:
			negotiated = resultString(ex.Message, "protocolVersion")
			var probs []string
			if negotiated != era {
				probs = append(probs, fmt.Sprintf("protocolVersion %q != offered era", negotiated))
			}
			if v.result["serverInfo"] == nil {
				probs = append(probs, "serverInfo absent")
			}
			if v.result["capabilities"] == nil {
				probs = append(probs, "capabilities absent")
			}
			if len(probs) > 0 {
				r.cell("H1.init", MustViolation, "%s", strings.Join(probs, "; "))
			} else {
				r.cell("H1.init", Pass, "negotiated %s; serverInfo+capabilities present", negotiated)
			}
		}
	}

	// H2 — offered newer.
	if ex := missing(r, cap, "H2.newer"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.transportErr != "":
			r.cell("H2.newer", Unreached, "%s", v.summary())
		case !v.succeeded():
			r.cell("H2.newer", MustViolation, "handshake errored when offered %s: %s", StatelessEra, v.summary())
		default:
			got := resultString(ex.Message, "protocolVersion")
			switch {
			case got == "":
				r.cell("H2.newer", MustViolation, "no protocolVersion in the response")
			case got == StatelessEra:
				// Conformant only if the server genuinely speaks it — flagged for
				// cross-grading rather than assumed (PREDICATES.md H2).
				r.cell("H2.newer", Observed, "echoed the newer %s — cross-grade this target at that era", got)
			case contains(Eras, got):
				r.cell("H2.newer", Pass, "negotiated down to %s", got)
			default:
				r.cell("H2.newer", MustViolation, "responded with unknown revision %q", got)
			}
		}
	}

	// H3 — lifecycle order: OBS on classic eras. The spec's pre-init constraint
	// binds the CLIENT ("the client SHOULD NOT send requests …"); no revision
	// imposes a server-side refusal duty — the CTRL-SDK control caught the
	// original MUST cell grading a client obligation against servers
	// (PREDICATES.md, resolution recorded 2026-08-13).
	if ex := missing(r, cap, "H3.cold"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("H3.cold", Unreached, "%s", v.summary())
		case v.refused():
			r.cell("H3.cold", Observed, "pre-handshake tools/list refused: %s", v.summary())
		default:
			r.cell("H3.cold", Observed, "pre-handshake tools/list served (no gate; conformant either way)")
		}
	}

	// D1 — discover must not succeed pre-stateless.
	if ex := missing(r, cap, "D1.discover"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("D1.discover", Unreached, "%s", v.summary())
		case v.succeeded():
			r.cell("D1.discover", MustViolation, "server/discover succeeded on a %s-era target", era)
		default:
			r.cell("D1.discover", Pass, "discover not served: %s", v.summary())
		}
	}

	// V1 — protocol-version header (2025-06-18+, HTTP).
	if era == "2025-06-18" || era == "2025-11-25" {
		if !http {
			r.cell("V1.header", NotApplicable, "stdio carries no HTTP headers")
		} else if ex := cap.find("T1.page0"); ex != nil && negotiated != "" {
			v := viewOf(ex)
			switch {
			case v.unreached():
				r.cell("V1.header", Unreached, "%s", v.summary())
			case v.succeeded():
				r.cell("V1.header", Pass, "tools/list with MCP-Protocol-Version %s accepted", negotiated)
			default:
				r.cell("V1.header", MustViolation, "tools/list WITH the negotiated header refused: %s", v.summary())
			}
			if no := cap.find("V1.noheader"); no != nil {
				r.cell("V1.noheader", Observed, "without the header: %s", viewOf(no).summary())
			}
		} else {
			r.cell("V1.header", Unreached, "no negotiated session to test under")
		}
	}

	// S1 — session enforcement (2025-03-26..2025-11-25, HTTP).
	switch {
	case era == "2024-11-05":
		if hybrid {
			r.cell("S1.session", NotApplicable, "na-hybrid: Mcp-Session-Id postdates the era")
		}
	case !http:
		r.cell("S1.session", NotApplicable, "stdio has no session header")
	case !sessionMinted:
		r.cell("S1.session", NotApplicable, "na(stateless-server): no Mcp-Session-Id minted")
	default:
		if ex := missing(r, cap, "S1.nosession"); ex != nil {
			v := viewOf(ex)
			switch {
			case v.unreached():
				r.cell("S1.session", Unreached, "%s", v.summary())
			case v.refused():
				r.cell("S1.session", Pass, "request without the minted session id refused: %s", v.summary())
			default:
				r.cell("S1.session", MustViolation, "minted a session id but served tools/list without it")
			}
		}
	}

	if hasToolsCapability(cap, "H1.init") {
		gradeToolsPages(cap, r, era)
		gradeBadCursor(cap, r)
	} else {
		naToolsCells(r, "T1.tools", "T2.badcursor")
	}

	// B1 — batching: 2025-03-26 MUST accept; 2025-06-18+ MUST refuse; 2024-11-05 OBS.
	// Graded regardless of the tools capability: a batch must be handled AS A
	// BATCH (accepted or refused per era) whatever its inner methods.
	if ex := missing(r, cap, "B1.batch"); ex != nil {
		v := viewOf(ex)
		accepted := v.isBatch && (v.status == 0 || (v.status >= 200 && v.status <= 299))
		switch {
		case v.unreached():
			r.cell("B1.batch", Unreached, "%s", v.summary())
		case era == "2024-11-05":
			r.cell("B1.batch", Observed, "batch accepted=%v (%s)", accepted, v.summary())
		case era == "2025-03-26":
			if accepted {
				r.cell("B1.batch", Pass, "two-element batch answered with a batch response")
			} else {
				r.cell("B1.batch", MustViolation, "batch refused on the era that requires batching: %s", v.summary())
			}
		default: // 2025-06-18, 2025-11-25
			if accepted {
				r.cell("B1.batch", MustViolation, "batch ACCEPTED on an era that removed batching")
			} else {
				r.cell("B1.batch", Pass, "batch refused: %s", v.summary())
			}
		}
	}

	// G1 — GET (OBS for classic eras; na-hybrid for 2024-11-05).
	if http {
		if ex := cap.find("G1.get"); ex != nil {
			if hybrid {
				r.cell("G1.get", NotApplicable, "na-hybrid (HTTP %d, %s)", ex.Status, ex.RespHdr["Content-Type"])
			} else {
				r.cell("G1.get", Observed, "HTTP %d, content-type %q", ex.Status, ex.RespHdr["Content-Type"])
			}
		}
	}

	gradeIdentity(cap, r, "H1.init")
}

func gradeStateless(cap *Capture, r *Report) {
	http := cap.Kind == "http"
	var supported []string

	// D1 — discover MUST succeed with the required members.
	if ex := missing(r, cap, "D1.discover"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.transportErr != "":
			r.cell("D1.discover", Unreached, "%s", v.summary())
		case !v.succeeded():
			r.cell("D1.discover", MustViolation, "server/discover refused: %s", v.summary())
		default:
			supported = resultStrings(ex.Message, "supportedVersions")
			var probs []string
			if len(supported) == 0 {
				probs = append(probs, "supportedVersions absent or empty")
			} else if !contains(supported, StatelessEra) {
				probs = append(probs, fmt.Sprintf("supportedVersions %v lacks %s", supported, StatelessEra))
			}
			if v.result["serverInfo"] == nil {
				probs = append(probs, "serverInfo absent")
			}
			if v.result["capabilities"] == nil {
				probs = append(probs, "capabilities absent")
			}
			if len(probs) > 0 {
				r.cell("D1.discover", MustViolation, "%s", strings.Join(probs, "; "))
			} else {
				r.cell("D1.discover", Pass, "supportedVersions %v; serverInfo+capabilities present", supported)
			}
		}
	}

	// D2 — the mandatory envelope.
	if ex := missing(r, cap, "D2.nometa"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("D2.nometa", Unreached, "%s", v.summary())
		case v.refused():
			r.cell("D2.nometa", Pass, "request without _meta refused: %s", v.summary())
		default:
			r.cell("D2.nometa", MustViolation, "request without the mandatory _meta envelope SERVED")
		}
	}

	// H1 — initialize must be refused.
	if ex := missing(r, cap, "H1.init"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("H1.init", Unreached, "%s", v.summary())
		case v.refused():
			r.cell("H1.init", Pass, "initialize refused: %s", v.summary())
		default:
			r.cell("H1.init", MustViolation, "the removed initialize handshake SUCCEEDED")
		}
	}

	toolsCapable := hasToolsCapability(cap, "D1.discover")

	// H3 — enveloped cold tools/list MUST succeed (tools-capable servers only).
	if !toolsCapable {
		naToolsCells(r, "H3.cold")
	} else if ex := missing(r, cap, "H3.cold"); ex != nil {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("H3.cold", Unreached, "%s", v.summary())
		case v.succeeded():
			r.cell("H3.cold", Pass, "cold enveloped tools/list served")
		default:
			r.cell("H3.cold", MustViolation, "cold enveloped tools/list refused: %s", v.summary())
		}
	}

	// S2 — no protocol sessions (HTTP). Graded only when the target actually
	// answered something: a dead target's "no session header anywhere" is
	// silence, not statelessness.
	if http {
		minted, answered := "", false
		for _, ex := range cap.Exchanges {
			if !viewOf(ex).unreached() {
				answered = true
			}
			if sid := ex.RespHdr["Mcp-Session-Id"]; sid != "" {
				minted = ex.Probe
				break
			}
		}
		switch {
		case minted != "":
			r.cell("S2.nosession", MustViolation, "Mcp-Session-Id minted on %s (sessions were removed)", minted)
		case !answered:
			r.cell("S2.nosession", Unreached, "no exchange reached the target")
		default:
			r.cell("S2.nosession", Pass, "no Mcp-Session-Id on any response")
		}
	} else {
		r.cell("S2.nosession", NotApplicable, "stdio has no session header")
	}

	if toolsCapable {
		gradeToolsPages(cap, r, StatelessEra)
		gradeBadCursor(cap, r)
	} else {
		naToolsCells(r, "T1.tools", "T2.badcursor")
	}

	// B1 — batch MUST be refused.
	if ex := missing(r, cap, "B1.batch"); ex != nil {
		v := viewOf(ex)
		accepted := v.isBatch && (v.status == 0 || (v.status >= 200 && v.status <= 299))
		switch {
		case v.unreached():
			r.cell("B1.batch", Unreached, "%s", v.summary())
		case accepted:
			r.cell("B1.batch", MustViolation, "batch ACCEPTED (removed since 2025-06-18)")
		default:
			r.cell("B1.batch", Pass, "batch refused: %s", v.summary())
		}
	}

	// V2 — version mismatch. The probe rides tools/list, so a tools-less
	// server's -32601 is a method refusal, not version enforcement — na.
	if !toolsCapable {
		naToolsCells(r, "V2.mismatch")
	} else if ex := cap.find("V2.mismatch"); ex == nil {
		r.cell("V2.mismatch", Unreached, "%s", strings.Join(cap.Notes, "; "))
	} else {
		v := viewOf(ex)
		switch {
		case v.unreached():
			r.cell("V2.mismatch", Unreached, "%s", v.summary())
		case !v.refused():
			r.cell("V2.mismatch", MustViolation, "request naming an unsupported protocolVersion was SERVED")
		case v.isError && v.errCode == -32022:
			r.cell("V2.mismatch", Pass, "refused with UnsupportedProtocolVersionError (-32022)")
		default:
			r.cell("V2.mismatch", ShouldViolation, "refused, but not with -32022: %s", v.summary())
		}
	}

	// C1 — CacheableResult on tools/list.
	if !toolsCapable {
		naToolsCells(r, "C1.cacheable")
	} else if ex := cap.find("H3.cold"); ex != nil {
		v := viewOf(ex)
		if v.succeeded() {
			_, hasTTL := v.result["ttlMs"]
			_, hasScope := v.result["cacheScope"]
			if hasTTL && hasScope {
				r.cell("C1.cacheable", Pass, "ttlMs and cacheScope present")
			} else {
				r.cell("C1.cacheable", MustViolation, "tools/list result lacks CacheableResult fields (ttlMs=%v cacheScope=%v)", hasTTL, hasScope)
			}
		} else {
			r.cell("C1.cacheable", Unreached, "tools/list did not succeed")
		}
	}

	// R1 — resultType on every successful result. No successful result at all
	// is unreached, never a pass (a vacuous sweep must be visible).
	succeeded, violated := 0, false
	for _, ex := range cap.Exchanges {
		v := viewOf(ex)
		if !v.succeeded() {
			continue
		}
		succeeded++
		var rt string
		if raw, ok := v.result["resultType"]; !ok || json.Unmarshal(raw, &rt) != nil || rt != "complete" {
			r.cell("R1.resulttype", MustViolation, "%s result lacks resultType:\"complete\"", ex.Probe)
			violated = true
			break
		}
	}
	switch {
	case violated:
	case succeeded == 0:
		r.cell("R1.resulttype", Unreached, "no successful result to inspect")
	default:
		r.cell("R1.resulttype", Pass, "all %d successful results carry resultType complete", succeeded)
	}

	// G1 — SHOULD NOT serve the old GET stream when single-era.
	if http {
		if ex := cap.find("G1.get"); ex != nil {
			ct := ex.RespHdr["Content-Type"]
			sse := strings.HasPrefix(ct, "text/event-stream") && ex.Status >= 200 && ex.Status <= 299
			singleEra := len(supported) == 1 && supported[0] == StatelessEra
			switch {
			case sse && singleEra:
				r.cell("G1.get", ShouldViolation, "single-era %s target still serves the removed GET SSE stream", StatelessEra)
			default:
				r.cell("G1.get", Observed, "HTTP %d, content-type %q", ex.Status, ct)
			}
		}
	}

	gradeIdentity(cap, r, "D1.discover")
}

// gradeToolsPages grades T1 over every T1.page* exchange (plus H3.cold, which
// is page 0 on the stateless flow).
func gradeToolsPages(cap *Capture, r *Report, era string) {
	var pages []*Exchange
	if era == StatelessEra {
		if ex := cap.find("H3.cold"); ex != nil {
			pages = append(pages, ex)
		}
	}
	for i := 0; i < maxPages; i++ {
		if ex := cap.find(fmt.Sprintf("T1.page%d", i)); ex != nil {
			pages = append(pages, ex)
		}
	}
	if len(pages) == 0 {
		r.cell("T1.tools", Unreached, "no tools/list exchange recorded")
		return
	}
	seenNames := map[string]string{}
	seenCursors := map[string]bool{}
	total := 0
	for _, ex := range pages {
		v := viewOf(ex)
		if v.unreached() {
			r.cell("T1.tools", Unreached, "%s: %s", ex.Probe, v.summary())
			return
		}
		if !v.succeeded() {
			r.cell("T1.tools", MustViolation, "%s failed: %s", ex.Probe, v.summary())
			return
		}
		var tools []map[string]json.RawMessage
		if raw, ok := v.result["tools"]; !ok {
			r.cell("T1.tools", MustViolation, "%s result carries no tools array", ex.Probe)
			return
		} else if err := json.Unmarshal(raw, &tools); err != nil {
			r.cell("T1.tools", MustViolation, "%s tools is not an object array: %v", ex.Probe, err)
			return
		}
		for _, t := range tools {
			var name string
			if raw, ok := t["name"]; !ok || json.Unmarshal(raw, &name) != nil || name == "" {
				r.cell("T1.tools", MustViolation, "%s: a tool lacks a string name", ex.Probe)
				return
			}
			if prev, dup := seenNames[name]; dup {
				r.cell("T1.tools", MustViolation, "tool %q duplicated across pages (%s and %s)", name, prev, ex.Probe)
				return
			}
			seenNames[name] = ex.Probe
			total++
		}
		if cur := resultString(ex.Message, "nextCursor"); cur != "" {
			if seenCursors[cur] {
				r.cell("T1.tools", MustViolation, "cursor repeated: %q", cur)
				return
			}
			seenCursors[cur] = true
		}
	}
	if last := pages[len(pages)-1]; resultString(last.Message, "nextCursor") != "" {
		r.cell("T1.tools", Unreached, "page-cap: walk did not terminate within %d pages", maxPages)
		return
	}
	r.cell("T1.tools", Pass, "%d tools over %d page(s), no duplicates, walk terminated", total, len(pages))
}

func gradeBadCursor(cap *Capture, r *Report) {
	ex := cap.find("T2.badcursor")
	if ex == nil {
		r.cell("T2.badcursor", Unreached, "no exchange recorded")
		return
	}
	v := viewOf(ex)
	switch {
	case v.unreached():
		r.cell("T2.badcursor", Unreached, "%s", v.summary())
	case v.isError && v.errCode == -32602:
		r.cell("T2.badcursor", Pass, "invalid cursor refused with -32602")
	case v.refused():
		r.cell("T2.badcursor", Pass, "invalid cursor refused: %s", v.summary())
	default:
		r.cell("T2.badcursor", ShouldViolation, "invalid cursor ACCEPTED (spec SHOULD refuse with -32602)")
	}
}

// hasToolsCapability reads the era-authoritative identity exchange's
// capabilities object. tools/list belongs to the `tools` capability: a server
// not advertising it correctly refuses the method, and grading that refusal
// as a violation would manufacture a finding out of the prober's own
// inapplicable request (PREDICATES.md "Capability gating"). The zero answer
// (no identity exchange, no capabilities member) is TRUE — an over-graded
// tools server is a visible violation someone inspects, while an
// under-graded one silently vanishes from the matrix.
func hasToolsCapability(cap *Capture, probe string) bool {
	ex := cap.find(probe)
	if ex == nil {
		return true
	}
	v := viewOf(ex)
	if v.result == nil || v.result["capabilities"] == nil {
		return true
	}
	var caps map[string]json.RawMessage
	if json.Unmarshal(v.result["capabilities"], &caps) != nil {
		return true
	}
	_, ok := caps["tools"]
	return ok
}

// naToolsCells emits the tools-probed cells as na(no-tools-capability).
func naToolsCells(r *Report, probes ...string) {
	for _, p := range probes {
		r.cell(p, NotApplicable, "na(no-tools-capability): the identity exchange advertises no tools capability")
	}
}

// gradeIdentity grades I1 from the era's identity-bearing exchange.
func gradeIdentity(cap *Capture, r *Report, probe string) {
	ex := cap.find(probe)
	if ex == nil {
		r.cell("I1.identity", Unreached, "no %s exchange", probe)
		return
	}
	v := viewOf(ex)
	if !v.succeeded() || v.result["serverInfo"] == nil {
		r.cell("I1.identity", Unreached, "no serverInfo to read")
		return
	}
	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(v.result["serverInfo"], &info) != nil || info.Name == "" || info.Version == "" {
		r.cell("I1.identity", ShouldViolation, "serverInfo name/version incomplete: %s", capString(string(v.result["serverInfo"]), 120))
		return
	}
	r.cell("I1.identity", Pass, "%s %s", info.Name, info.Version)
}
