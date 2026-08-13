package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// The five protocol revisions the matrix knows (PREDICATES.md "The eras").
var Eras = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

// StatelessEra is the revision that removed the initialize handshake (SEP-2575).
const StatelessEra = "2026-07-28"

const (
	metaProtocolVersionKey    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfoKey         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilitiesKey = "io.modelcontextprotocol/clientCapabilities"
)

// invalidCursor is the pre-registered T2 cursor value.
const invalidCursor = "surfacelock-era-invalid-cursor"

// Capture is the raw material of one (target, era) probe run. Grading is a
// pure function over it; the matrix generator persists it verbatim.
type Capture struct {
	Target    string      `json:"target"`             // display name
	Kind      string      `json:"kind"`               // "http" | "stdio"
	Era       string      `json:"era"`                // the era graded against
	TakenAt   string      `json:"taken_at,omitempty"` // stamped by the caller, never by the prober
	Exchanges []*Exchange `json:"exchanges"`
	Notes     []string    `json:"notes,omitempty"` // prober-level facts (dial failures on fresh sessions, etc.)
}

func (c *Capture) find(probe string) *Exchange {
	for _, ex := range c.Exchanges {
		if ex.Probe == probe {
			return ex
		}
	}
	return nil
}

func (c *Capture) note(format string, args ...any) {
	c.Notes = append(c.Notes, fmt.Sprintf(format, args...))
}

func marshalRPC(id int64, method string, params any) []byte {
	m := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != 0 {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // parameters are prober-built literals; a marshal failure is a bug
	}
	return b
}

func metaEnvelope(version string) map[string]any {
	return map[string]any{
		metaProtocolVersionKey:    version,
		metaClientInfoKey:         map[string]any{"name": "surfacelock-conformance", "version": "0.1"},
		metaClientCapabilitiesKey: map[string]any{},
	}
}

// Probe runs the era's full exchange plan against fresh sessions from dial and
// returns the capture. It never grades; a wire failure is recorded on its
// exchange and grading decides what it means. Read-only by construction: the
// only methods sent are initialize, notifications/initialized, server/discover
// and tools/list.
func Probe(ctx context.Context, target string, dial Dialer, era string) (*Capture, error) {
	first, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	cap := &Capture{Target: target, Kind: first.Kind(), Era: era}
	if era == StatelessEra {
		probeStateless(ctx, cap, first, dial)
	} else {
		probeClassic(ctx, cap, first, dial, era)
	}
	return cap, nil
}

// fresh dials a new session, recording a dial failure as a capture note (the
// grader marks the probes that needed it unreached).
func fresh(ctx context.Context, cap *Capture, dial Dialer, forProbe string) Conn {
	c, err := dial(ctx)
	if err != nil {
		cap.note("fresh session for %s: dial failed: %v", forProbe, err)
		return nil
	}
	return c
}

// classicSession drives initialize+initialized on conn and returns the minted
// session id (HTTP) and negotiated version, threading them for later
// exchanges. Parsing here is prober convenience only — grading re-derives
// everything from the exchanges.
func classicSession(ctx context.Context, cap *Capture, conn Conn, offered, initProbe string) (sessionID, negotiated string) {
	ex := conn.Roundtrip(ctx, initProbe, marshalRPC(1, "initialize", map[string]any{
		"protocolVersion": offered,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "surfacelock-conformance", "version": "0.1"},
	}), nil, 1)
	cap.Exchanges = append(cap.Exchanges, ex)
	sessionID = ex.RespHdr["Mcp-Session-Id"]
	if h, ok := conn.(*HTTPConn); ok && sessionID != "" {
		h.sessionID = sessionID // lets Close() DELETE the session (etiquette)
	}
	negotiated = resultString(ex.Message, "protocolVersion")
	if negotiated == "" {
		return sessionID, ""
	}
	hdr := map[string]string{}
	if sessionID != "" {
		hdr["Mcp-Session-Id"] = sessionID
	}
	ntf := conn.Roundtrip(ctx, initProbe+".initialized", marshalRPC(0, "notifications/initialized", nil), hdr, 0)
	cap.Exchanges = append(cap.Exchanges, ntf)
	return sessionID, negotiated
}

// resultString pulls result.<key> as a string from a JSON-RPC message.
func resultString(message, key string) string {
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if json.Unmarshal([]byte(message), &env) != nil || env.Result == nil {
		return ""
	}
	var s string
	if json.Unmarshal(env.Result[key], &s) != nil {
		return ""
	}
	return s
}

func probeClassic(ctx context.Context, cap *Capture, conn Conn, dial Dialer, era string) {
	defer conn.Close()

	// H1 + the era's own session: initialize(era), initialized, then the T1
	// pagination walk, V1's header variants, T2's bad cursor, B1's batch, and
	// S1's no-session variant — all on this session.
	sessionID, negotiated := classicSession(ctx, cap, conn, era, "H1.init")
	base := map[string]string{}
	if sessionID != "" {
		base["Mcp-Session-Id"] = sessionID
	}
	// The MCP-Protocol-Version header exists from 2025-06-18; sending it to an
	// older era is not part of that era's own flow.
	versionHeader := era == "2025-06-18" || era == "2025-11-25"
	if versionHeader && negotiated != "" {
		base["MCP-Protocol-Version"] = negotiated
	}

	id := int64(10)
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		ex := conn.Roundtrip(ctx, fmt.Sprintf("T1.page%d", page), marshalRPC(id, "tools/list", params), base, id)
		cap.Exchanges = append(cap.Exchanges, ex)
		id++
		cursor = resultString(ex.Message, "nextCursor")
		if cursor == "" {
			break
		}
	}

	if versionHeader && conn.Kind() == "http" {
		// V1's OBS half: the same call with the header explicitly suppressed.
		hdr := map[string]string{"MCP-Protocol-Version": ""}
		for k, v := range base {
			if k != "MCP-Protocol-Version" {
				hdr[k] = v
			}
		}
		ex := conn.Roundtrip(ctx, "V1.noheader", marshalRPC(id, "tools/list", nil), hdr, id)
		cap.Exchanges = append(cap.Exchanges, ex)
		id++
	}

	ex := conn.Roundtrip(ctx, "T2.badcursor", marshalRPC(id, "tools/list", map[string]any{"cursor": invalidCursor}), base, id)
	cap.Exchanges = append(cap.Exchanges, ex)
	id++

	// B1: a two-element batch on the era's own session. The response may be an
	// array (match by transport) or a refusal; id matching is best-effort, so
	// pass id=0 and grade from Body/Status.
	batch := "[" + string(marshalRPC(id, "tools/list", nil)) + "," + string(marshalRPC(id+1, "tools/list", nil)) + "]"
	ex = conn.Roundtrip(ctx, "B1.batch", []byte(batch), base, id)
	cap.Exchanges = append(cap.Exchanges, ex)
	id += 2

	if sessionID != "" && conn.Kind() == "http" {
		hdr := map[string]string{"Mcp-Session-Id": ""}
		if versionHeader && negotiated != "" {
			hdr["MCP-Protocol-Version"] = negotiated
		}
		ex = conn.Roundtrip(ctx, "S1.nosession", marshalRPC(id, "tools/list", nil), hdr, id)
		cap.Exchanges = append(cap.Exchanges, ex)
		id++
	}

	// H2 on a FRESH session: initialize offering a revision newer than the era.
	if h2 := fresh(ctx, cap, dial, "H2.newer"); h2 != nil {
		classicSession(ctx, cap, h2, StatelessEra, "H2.newer")
		h2.Close()
	}

	// H3 on a FRESH session: tools/list before any handshake.
	if h3 := fresh(ctx, cap, dial, "H3.cold"); h3 != nil {
		ex = h3.Roundtrip(ctx, "H3.cold", marshalRPC(1, "tools/list", nil), nil, 1)
		cap.Exchanges = append(cap.Exchanges, ex)
		h3.Close()
	}

	// D1 on a FRESH session: server/discover (must NOT succeed pre-stateless).
	if d1 := fresh(ctx, cap, dial, "D1.discover"); d1 != nil {
		ex = d1.Roundtrip(ctx, "D1.discover", marshalRPC(1, "server/discover", map[string]any{"_meta": metaEnvelope(StatelessEra)}), nil, 1)
		cap.Exchanges = append(cap.Exchanges, ex)
		d1.Close()
	}

	// G1: a bounded GET (HTTP only; the conn records N/A on stdio).
	ex = conn.Get(ctx, "G1.get", map[string]string{"Accept": "text/event-stream"})
	cap.Exchanges = append(cap.Exchanges, ex)
}

func probeStateless(ctx context.Context, cap *Capture, conn Conn, dial Dialer) {
	defer conn.Close()
	era := StatelessEra
	meta := func() map[string]any { return metaEnvelope(era) }

	// D1: server/discover with the full envelope.
	ex := conn.Roundtrip(ctx, "D1.discover", marshalRPC(1, "server/discover", map[string]any{"_meta": meta()}), nil, 1)
	cap.Exchanges = append(cap.Exchanges, ex)
	supported := resultStrings(ex.Message, "supportedVersions")

	// D2: the same request with _meta ABSENT.
	ex = conn.Roundtrip(ctx, "D2.nometa", marshalRPC(2, "server/discover", map[string]any{}), nil, 2)
	cap.Exchanges = append(cap.Exchanges, ex)

	// H1: initialize must be refused post-SEP-2575.
	ex = conn.Roundtrip(ctx, "H1.init", marshalRPC(3, "initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "surfacelock-conformance", "version": "0.1"},
	}), nil, 3)
	cap.Exchanges = append(cap.Exchanges, ex)

	// H3/T1: enveloped tools/list, cold (statelessness is the point), paginated.
	id := int64(10)
	cursor := ""
	for page := 0; page < maxPages; page++ {
		params := map[string]any{"_meta": meta()}
		if cursor != "" {
			params["cursor"] = cursor
		}
		probe := fmt.Sprintf("T1.page%d", page)
		if page == 0 {
			probe = "H3.cold" // the same exchange grades both cells
		}
		ex := conn.Roundtrip(ctx, probe, marshalRPC(id, "tools/list", params), nil, id)
		cap.Exchanges = append(cap.Exchanges, ex)
		id++
		cursor = resultString(ex.Message, "nextCursor")
		if cursor == "" {
			break
		}
	}

	ex = conn.Roundtrip(ctx, "T2.badcursor", marshalRPC(id, "tools/list", map[string]any{"_meta": meta(), "cursor": invalidCursor}), nil, id)
	cap.Exchanges = append(cap.Exchanges, ex)
	id++

	batch := "[" + string(marshalRPC(id, "tools/list", map[string]any{"_meta": meta()})) + "," + string(marshalRPC(id+1, "tools/list", map[string]any{"_meta": meta()})) + "]"
	ex = conn.Roundtrip(ctx, "B1.batch", []byte(batch), nil, id)
	cap.Exchanges = append(cap.Exchanges, ex)
	id += 2

	// V2: a version the server did not list. Prefer the oldest era not in
	// supportedVersions; if it lists all five, the cell is unreached.
	mismatch := ""
	for _, e := range Eras {
		if !contains(supported, e) {
			mismatch = e
			break
		}
	}
	if mismatch != "" {
		ex = conn.Roundtrip(ctx, "V2.mismatch", marshalRPC(id, "tools/list", map[string]any{"_meta": metaEnvelope(mismatch)}), nil, id)
		cap.Exchanges = append(cap.Exchanges, ex)
		id++
	} else {
		cap.note("V2.mismatch unreached: supportedVersions lists every known era")
	}

	ex = conn.Get(ctx, "G1.get", map[string]string{"Accept": "text/event-stream"})
	cap.Exchanges = append(cap.Exchanges, ex)
}

func resultStrings(message, key string) []string {
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if json.Unmarshal([]byte(message), &env) != nil || env.Result == nil {
		return nil
	}
	var out []string
	if json.Unmarshal(env.Result[key], &out) != nil {
		return nil
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ProbeWithTimeout bounds a whole run (a hostile target must not park the
// matrix generator).
func ProbeWithTimeout(target string, dial Dialer, era string, budget time.Duration) (*Capture, error) {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	return Probe(ctx, target, dial, era)
}
