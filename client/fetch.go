package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/JsizzleR/surfacelock"
)

// DefaultOfferedVersion is the protocol revision offered when the caller does
// not choose one. Verifiers always re-offer the lockfile's recorded value
// instead, so negotiation is reproducible (SPEC.md §3.1).
const DefaultOfferedVersion = ModernRevision

// ModernRevision is the first stateless protocol revision (SEP-2575): the
// initialize/initialized handshake is removed, every request carries the
// reserved `_meta` envelope keys, and capabilities come from `server/discover`.
// Offering it makes Fetch try the stateless flow first and fall back to the
// classic handshake (measured: SDK servers up to 2025-11-25 answer classic
// only, while a stateless-only endpoint refuses classic outright — the two
// populations are disjoint, so one flow cannot serve both).
const ModernRevision = "2026-07-28"

// Fetch flows (SPEC.md §3.4), aliased from the root package (the format
// authority), kept here so existing callers keep compiling.
const (
	FlowStateless = surfacelock.FlowStateless
	FlowClassic   = surfacelock.FlowClassic
)

const closeTimeout = 5 * time.Second

// Reserved _meta envelope keys every stateless-revision request must carry.
const (
	metaProtocolVersionKey    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfoKey         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilitiesKey = "io.modelcontextprotocol/clientCapabilities"
)

// Ref addresses a server the way a lockfile entry does.
type Ref struct {
	Transport string // "http" | "stdio"
	Target    string
	Args      []string
	Env       []string // extra KEY=VAL pairs for stdio; never recorded in a lockfile
	Offered   string   // protocolVersion to offer; DefaultOfferedVersion if empty

	// Flow pins the fetch flow: FlowStateless, FlowClassic, or "" for
	// offer-driven selection with fallback (SPEC.md §3.4). Verifiers pass the
	// lockfile's recorded flow so a lock is re-verified over the flow it was
	// taken with, never over whichever one the current server prefers.
	Flow string

	// Headers are static HTTP request headers attached to every request this
	// fetch makes. HTTP ONLY — setting them with any other transport is an
	// ERROR, never a silent drop, because a credential quietly not sent looks
	// exactly like one that was. stdio carries credentials in Env instead. They exist for a token-gated upstream: an MCP endpoint
	// behind an edge authenticator answers an unauthenticated fetch with a
	// transport failure, which is an honest error and never a drift verdict.
	// This package never copies one into a lockfile; a server that ECHOES one
	// into its own surface is a separate matter the CLI guards and this type
	// cannot — see surfacelock.Headers, property 1.
	Headers surfacelock.Headers

	// HTTPClient, when non-nil, carries the http transport's requests ("http"
	// only; ignored for stdio). It exists for callers whose target is not
	// directly dialable by a default client — a unix-socket upstream behind a
	// pinned DialContext, a client with redirects refused — and is used as
	// given: Fetch adds no timeouts of its own beyond ctx.
	HTTPClient *http.Client
}

type toolsListPage struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor json.RawMessage   `json:"nextCursor"`
}

// errPreCommit marks a modern-flow failure that happened BEFORE a
// version-confirmed server/discover — the flow-selection commit point. Only
// these failures may fall back to classic: once discover has confirmed the
// offered revision the server IS a stateless server, and a later tools/list
// failure (cap, cursor loop, inadmissible page) must be terminal — a second
// classic enumeration would let a hostile hybrid serve different bytes over
// the other flow and re-classify a deliberate inadmissibility as a transport
// failure (a review finding on the phase-2 gate). INVARIANT: nothing at or after
// the commit point may construct or wrap an errPreCommit — errors.As is
// ancestry-based, not phase-aware, so a post-commit error carrying this marker
// anywhere in its chain would re-open the fallback it exists to close.
type errPreCommit struct{ err error }

func (e errPreCommit) Error() string { return e.err.Error() }
func (e errPreCommit) Unwrap() error { return e.err }

// discoverVerdict is what a failed server/discover says about the classic
// fallback (classifyDiscoverFailure).
type discoverVerdict int

const (
	discoverFallback discoverVerdict = iota // no modern evidence: one classic attempt follows
	discoverRetry                           // refused a revision it lists: ask once more
	discoverTerminal                        // the reference client ends its probe here: no fallback
)

// offerHint names the way to the classic flow when the fallback is withheld.
const offerHint = " (an offer before " + ModernRevision + " takes the classic flow)"

// classifyDiscoverFailure follows the reference client's probe classifier
// (@modelcontextprotocol/client 2.0.0, probeClassifier.ts, measured from its
// published dist) on a server/discover that did not answer with a result.
//
// On every transport a message that cannot be read as one answer the way an
// exact-key reader would (answerError: a case-variant envelope key, or an
// answer with neither result nor error) ends the probe. Over HTTP it ends,
// with no classic fallback, on 401, 403, any status from 500 and any status
// below 200, whatever the body holds (the reference decides before reading
// it; this client has read it, to the page cap, and ignores it); on a refusal
// body past the page cap (or one that broke off), which cannot be classified;
// and on any failure that leaves no answer to read (a transport error, the
// deadline, a 2xx that is not a JSON-RPC message). Any other non-2xx body, and
// every JSON-RPC error answer, is classified by modernRefusal. Over stdio
// every other failure (a closed or silent child, a line past the cap) is no
// modern evidence and falls back, as the reference's stdio probe does.
//
// Deliberate differences, each failing toward today's fallback or toward a
// refusal, never toward a modern lock the reference would not reach: a
// redirect is not followed (refuseRedirect) and its body is classified like
// any other status's; a 2xx message Go's struct decoder refuses (for example a
// duplicate member of a mismatched type, a non-string message, a non-numeric
// code, nesting past Go's decoder depth) has no answer to read; a body or a
// stdio line that does not parse as JSON for Go is no modern evidence.
func classifyDiscoverFailure(sess session, err error, offered string) (discoverVerdict, string) {
	var ae *answerError
	if errors.As(err, &ae) {
		return discoverTerminal, "its answer cannot be read as one JSON-RPC answer"
	}
	var rc *rpcCallError
	if errors.As(err, &rc) {
		return modernRefusal(rc.raw, offered)
	}
	var hs *httpStatusError
	if errors.As(err, &hs) {
		switch {
		case hs.status < 200 || hs.status == http.StatusUnauthorized || hs.status == http.StatusForbidden || hs.status >= 500:
			return discoverTerminal, fmt.Sprintf("the reference client ends its probe on HTTP %d", hs.status)
		case hs.cut:
			return discoverTerminal, "a refusal body that runs past the page cap or breaks off cannot be classified"
		}
		return modernRefusal(hs.body, offered)
	}
	if _, isHTTP := sess.(*httpSession); isHTTP {
		return discoverTerminal, "it left no discover answer to read"
	}
	return discoverFallback, ""
}

// modernRefusal classifies a JSON-RPC error message as the reference's
// classifyRpcError does: only -32022 UnsupportedProtocolVersion whose
// data.supported is a non-empty array of strings is era evidence. A list naming
// the offered revision earns one corrective retry; one naming any other
// revision from ModernRevision on (compared as strings, as the reference does)
// is a modern server with no revision in common, which gets no classic
// fallback; a legacy-only list falls back. -32020, -32021, -32001 and every
// other code are not era evidence and fall back. Keys are read exactly and
// last-wins, as JSON.parse reads them, and the code as a number of any
// spelling.
func modernRefusal(msg []byte, offered string) (discoverVerdict, string) {
	var top, e, data map[string]json.RawMessage
	var code float64
	var list []any
	if json.Unmarshal(msg, &top) != nil || json.Unmarshal(top["error"], &e) != nil ||
		json.Unmarshal(e["code"], &code) != nil || code != -32022 ||
		json.Unmarshal(e["data"], &data) != nil || json.Unmarshal(data["supported"], &list) != nil || len(list) == 0 {
		return discoverFallback, ""
	}
	supported := make([]string, len(list))
	for i, v := range list {
		s, ok := v.(string)
		if !ok {
			return discoverFallback, "" // a null or non-string element: not era evidence
		}
		supported[i] = s
	}
	switch {
	case slices.Contains(supported, offered):
		return discoverRetry, ""
	case slices.ContainsFunc(supported, func(v string) bool { return v >= ModernRevision }):
		return discoverTerminal, fmt.Sprintf("its -32022 lists modern revisions %s but not the offered %q", boundedList(supported), offered)
	}
	return discoverFallback, ""
}

// boundedList quotes a server-supplied list for an error, ASCII-escaped (so
// the cut never splits a rune) and cut at 200 bytes.
func boundedList(v []string) string {
	q := fmt.Sprintf("%+q", v)
	if len(q) > 200 {
		q = q[:200] + "..."
	}
	return q
}

// isNull reports whether a raw JSON value is the literal null.
func isNull(raw json.RawMessage) bool { return string(raw) == "null" }

// Fetch runs one fresh session against the server and returns the verbatim
// tools/list surface for admission by surfacelock.Admit, applying the
// fetch-side hostile-input rules (SPEC.md §6): page byte caps, page count cap,
// cursor size cap, and cursor-loop refusal.
//
// Flow selection (SPEC.md §3.4): ref.Flow when set; otherwise offer-driven —
// offering ModernRevision tries the stateless flow and falls back to ONE
// classic attempt on a FRESH session iff the stateless attempt failed before
// its commit point (a fresh session because a hostile stdio child could
// pre-queue responses for the fallback's predictable ids on a reused one);
// earlier offers speak classic only.
func Fetch(ctx context.Context, ref Ref, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	offered := ref.Offered
	if offered == "" {
		offered = DefaultOfferedVersion
	}
	// The offered string is caller input that becomes an HTTP header value and
	// the recorded era — refuse a control-char offer before the first request.
	if err := surfacelock.CheckEra(offered); err != nil {
		return nil, err
	}
	// Static headers are caller input that becomes header bytes on every
	// request — refuse an invalid name or an injected CR/LF here, before the
	// first one is written, rather than at net/http's write barrier, whose
	// error names a write and not the caller's input.
	if err := ref.Headers.Validate(); err != nil {
		return nil, err
	}
	// REFUSED, not ignored, and here rather than only in the CLI: a Go caller
	// that sets both has the same wrong mental model a CLI caller does, and the
	// consequence is worse — a `lock` taken with a credential the transport
	// never sent produces an artifact that looks fine.
	if len(ref.Headers) > 0 && ref.Transport != "http" {
		return nil, fmt.Errorf("Headers apply to the http transport; transport %q carries credentials in Env", ref.Transport)
	}

	switch ref.Flow {
	case FlowStateless:
		return fetchOnce(ctx, ref, lim, offered, true)
	case FlowClassic:
		return fetchOnce(ctx, ref, lim, offered, false)
	case "":
		if offered != ModernRevision {
			return fetchOnce(ctx, ref, lim, offered, false)
		}
		raw, merr := fetchOnce(ctx, ref, lim, offered, true)
		if merr == nil {
			return raw, nil
		}
		var pre errPreCommit
		if !errors.As(merr, &pre) {
			return nil, merr // post-commit: the server is stateless; its failure is terminal
		}
		raw, cerr := fetchOnce(ctx, ref, lim, offered, false)
		if cerr == nil {
			return raw, nil
		}
		// Both %w so a machine-readable class (ErrInadmissible) from EITHER
		// attempt survives errors.Is on the joined failure.
		return nil, fmt.Errorf("server/discover: %w; initialize fallback: %w", merr, cerr)
	default:
		return nil, fmt.Errorf("unknown flow %q", ref.Flow)
	}
}

// fetchOnce opens ONE fresh session and runs a single flow over it.
func fetchOnce(ctx context.Context, ref Ref, lim surfacelock.Limits, offered string, stateless bool) (*surfacelock.RawSurface, error) {
	var sess session
	var err error
	switch ref.Transport {
	case "http":
		sess = newHTTPSession(ref.Target, lim.MaxPageBytes, ref.HTTPClient, ref.Headers)
	case "stdio":
		sess, err = newStdioSession(append([]string{ref.Target}, ref.Args...), ref.Env, lim.MaxPageBytes)
	default:
		return nil, fmt.Errorf("unknown transport %q", ref.Transport)
	}
	if err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	defer sess.close(ctx)
	var raw *surfacelock.RawSurface
	if stateless {
		raw, err = fetchModern(ctx, sess, offered, lim)
	} else {
		raw, err = fetchClassic(ctx, sess, offered, lim)
	}
	return raw, dropBodies(err)
}

// dropBodies releases the response bytes an rpcCallError or httpStatusError
// keeps for classification (up to the page cap each), so no failed fetch
// returns them; the error's text and its chain are unchanged. A fetchOnce
// error carries at most one of each: a session fails at its first failed call.
func dropBodies(err error) error {
	var rc *rpcCallError
	if errors.As(err, &rc) {
		rc.raw = nil
	}
	var hs *httpStatusError
	if errors.As(err, &hs) {
		hs.body = nil
	}
	return err
}

// metaEnvelope is the reserved `_meta` object every stateless-revision request
// carries; a server refuses the request without all three keys (measured).
func metaEnvelope(offered string) map[string]any {
	return map[string]any{
		metaProtocolVersionKey:    offered,
		metaClientInfoKey:         map[string]any{"name": "surfacelock", "version": "0.1"},
		metaClientCapabilitiesKey: map[string]any{},
	}
}

// resultFields decodes a JSON-RPC result object with EXACT keys — the shared
// surfacelock.DecodeExact discipline (duplicate keys refused via canonicalization,
// case-variant aliases of consumed keys refused; the case-variance shape).
func resultFields(raw json.RawMessage, what string, keys ...string) (map[string]json.RawMessage, error) {
	return surfacelock.DecodeExact(raw, what, keys...)
}

// fetchModern is the stateless flow: server/discover for the surface's
// instructions/serverInfo, then `_meta`-enveloped tools/list pages. The era is
// the offered revision itself — each request names the dialect it speaks — and
// discover's supportedVersions must confirm it, or the dialect the bytes were
// served under is unknown and there is no surface to era-tag. A failure up to
// that confirmation is wrapped errPreCommit unless it ends the fetch outright (a
// terminal discover refusal, classifyDiscoverFailure; a result with no exact
// form); nothing after it is.
func fetchModern(ctx context.Context, sess session, offered string, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	// Every stateless request names its dialect in an HTTP header as well as in
	// _meta, and the two MUST agree — server/discover included, which is the
	// request that decides the flow. Setting this only after the commit point
	// (as before) sent discover header-less, and a spec-conformant server
	// refused it (measured, SDK 2.3.1 legacy:'reject': exit 3; its default
	// posture fell back to classic and the surface was era-tagged 2025-11-25).
	if h, ok := sess.(*httpSession); ok {
		h.proto, h.stateless = offered, true
	}
	var discRaw json.RawMessage
	for attempt := 0; ; attempt++ {
		res, err := sess.call(ctx, "server/discover", map[string]any{"_meta": metaEnvelope(offered)})
		if err == nil {
			discRaw = res
			break
		}
		verdict, why := classifyDiscoverFailure(sess, err, offered)
		var rc *rpcCallError
		var hs *httpStatusError
		if errors.As(err, &rc) || errors.As(err, &hs) {
			// Keep the text only: no response body outlives its classification
			// in the error a failed fetch returns.
			err = errors.New(err.Error())
		}
		switch {
		case verdict == discoverRetry && attempt == 0:
			continue // the reference client's one corrective retry
		case verdict == discoverRetry:
			return nil, fmt.Errorf("server/discover: %w: it refused the offered %q again after one corrective retry, though its -32022 lists it, so no classic fallback%s",
				err, offered, offerHint)
		case verdict == discoverTerminal:
			return nil, fmt.Errorf("server/discover: %w: %s, so no classic fallback%s", err, why, offerHint)
		}
		return nil, errPreCommit{err}
	}
	// The whole result exactly, before any of it is read (R-2608): a
	// supportedVersions element Go would decode to U+FFFD is not "not this
	// era", and reading it so would lock the classic flow over a modern answer;
	// the canonicalizer refuses some such forms and passes others, so the check
	// is on the raw bytes, and the refusal is terminal.
	if !utf8.Valid(discRaw) || !surfacelock.PairedSurrogates(discRaw) {
		return nil, fmt.Errorf("server/discover: %w: the result has no exact form (invalid UTF-8 or an unpaired surrogate escape)", surfacelock.ErrInadmissible)
	}
	obj, err := resultFields(discRaw, "server/discover", "supportedVersions", "serverInfo", "instructions")
	if err != nil {
		return nil, errPreCommit{err}
	}
	var supported []string
	if raw, ok := obj["supportedVersions"]; ok {
		if err := json.Unmarshal(raw, &supported); err != nil {
			return nil, errPreCommit{fmt.Errorf("server/discover: supportedVersions is not a string array")}
		}
	}
	if !slices.Contains(supported, offered) {
		return nil, errPreCommit{fmt.Errorf("server/discover: supportedVersions %q does not include the offered %q", supported, offered)}
	}
	// The commit point: the server has confirmed it serves the offered
	// stateless revision. From here every failure is terminal for the fetch.
	raw := &surfacelock.RawSurface{
		Offered:      offered,
		Era:          offered,
		Flow:         FlowStateless,
		Instructions: obj["instructions"],
		ServerInfo:   obj["serverInfo"],
	}
	if err := fetchPages(ctx, sess, raw, lim, func(cursor string) any {
		params := map[string]any{"_meta": metaEnvelope(offered)}
		if cursor != "" {
			params["cursor"] = cursor
		}
		return params
	}); err != nil {
		return nil, err
	}
	return raw, nil
}

// fetchClassic is the pre-stateless flow: initialize (offering `offered`),
// notifications/initialized, then plain tools/list pages. The era is whatever
// protocolVersion the server negotiated in its initialize result.
func fetchClassic(ctx context.Context, sess session, offered string, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	initParams := map[string]any{
		"protocolVersion": offered,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "surfacelock", "version": "0.1"},
	}
	initRaw, err := sess.call(ctx, "initialize", initParams)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	obj, err := resultFields(initRaw, "initialize", "protocolVersion", "serverInfo", "instructions")
	if err != nil {
		return nil, err
	}
	era, err := surfacelock.ExactString(obj["protocolVersion"])
	if errors.Is(err, surfacelock.ErrInadmissible) {
		// Read exactly: the era is recorded and hashed, so a token Go would
		// decode to U+FFFD would record a value the server never sent (R-2608).
		return nil, fmt.Errorf("initialize: protocolVersion %w", err)
	}
	if err != nil || era == "" {
		// No string protocolVersion means the surface cannot be era-tagged: there
		// is no surface (SPEC.md §6), and that is a protocol failure, not drift.
		return nil, fmt.Errorf("initialize: result carries no protocolVersion string")
	}
	// Validate the era BEFORE it is used as the MCP-Protocol-Version HTTP header
	// value: a control-char era is an inadmissible surface (exit 5), and refusing it
	// here keeps it from surfacing later as an opaque transport error when net/http
	// rejects the header.
	if err := surfacelock.CheckEra(era); err != nil {
		return nil, err
	}
	if h, ok := sess.(*httpSession); ok {
		h.proto = era
	}
	if err := sess.notify(ctx, "notifications/initialized", nil); err != nil {
		return nil, fmt.Errorf("initialized notification: %w", err)
	}

	raw := &surfacelock.RawSurface{
		Offered:      offered,
		Era:          era,
		Flow:         FlowClassic,
		Instructions: obj["instructions"],
		ServerInfo:   obj["serverInfo"],
	}
	if err := fetchPages(ctx, sess, raw, lim, func(cursor string) any {
		var params any = map[string]any{}
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		return params
	}); err != nil {
		return nil, err
	}
	return raw, nil
}

// fetchPages paginates tools/list into raw.Pages under the fetch-side caps,
// with the per-request params built by the flow-specific paramsFor.
func fetchPages(ctx context.Context, sess session, raw *surfacelock.RawSurface, lim surfacelock.Limits, paramsFor func(cursor string) any) error {
	cursor := ""
	seenCursors := map[string]bool{}
	for {
		// Refuse BEFORE fetching page MaxPages+1: don't spend a round-trip and hold
		// another MaxPageBytes just to reject a server that paginates without end.
		if len(raw.Pages) >= lim.MaxPages {
			return fmt.Errorf("tools/list: %w: more than %d pages", surfacelock.ErrInadmissible, lim.MaxPages)
		}
		page, err := sess.call(ctx, "tools/list", paramsFor(cursor))
		if err != nil {
			return fmt.Errorf("tools/list: %w", err)
		}
		raw.Pages = append(raw.Pages, page)
		var p toolsListPage
		if err := json.Unmarshal(page, &p); err != nil {
			return fmt.Errorf("tools/list: %w: page does not parse: %v", surfacelock.ErrInadmissible, err)
		}
		if p.NextCursor == nil || isNull(p.NextCursor) {
			return nil
		}
		// Exactly: the cursor keys the loop check and is sent back to the
		// server, which must get the cursor it issued, not U+FFFD for a lone
		// surrogate half (R-2608).
		next, err := surfacelock.ExactString(p.NextCursor)
		if err != nil {
			return fmt.Errorf("tools/list: %w: nextCursor %v", surfacelock.ErrInadmissible, err)
		}
		if next == "" {
			return nil
		}
		if len(next) > lim.MaxCursorBytes {
			return fmt.Errorf("tools/list: %w: cursor exceeds %d bytes", surfacelock.ErrInadmissible, lim.MaxCursorBytes)
		}
		if seenCursors[next] {
			return fmt.Errorf("tools/list: %w: cursor loop (cursor repeated)", surfacelock.ErrInadmissible)
		}
		seenCursors[next] = true
		cursor = next
	}
}
