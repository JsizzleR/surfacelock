package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

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

// Fetch flows (SPEC.md §3.4), recorded in the lockfile entry so a verifier
// reproduces the flow the lock was taken over — an unrecorded flow would let a
// replacement server that speaks only the OTHER flow serve the locked bytes
// and pass verification while the negotiation path silently changed.
const (
	FlowStateless = "stateless"
	FlowClassic   = "classic"
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
// failure (Codex@max finding, phase-2 gate). INVARIANT: nothing at or after
// the commit point may construct or wrap an errPreCommit — errors.As is
// ancestry-based, not phase-aware, so a post-commit error carrying this marker
// anywhere in its chain would re-open the fallback it exists to close.
type errPreCommit struct{ err error }

func (e errPreCommit) Error() string { return e.err.Error() }
func (e errPreCommit) Unwrap() error { return e.err }

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
		sess = newHTTPSession(ref.Target, lim.MaxPageBytes, ref.HTTPClient)
	case "stdio":
		sess, err = newStdioSession(append([]string{ref.Target}, ref.Args...), ref.Env, lim.MaxPageBytes)
	default:
		return nil, fmt.Errorf("unknown transport %q", ref.Transport)
	}
	if err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	defer sess.close(ctx)
	if stateless {
		return fetchModern(ctx, sess, offered, lim)
	}
	return fetchClassic(ctx, sess, offered, lim)
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

// resultFields decodes a JSON-RPC result object with EXACT keys. It refuses a
// result that (a) is not canonicalizable — which catches duplicate keys at any
// depth — or (b) carries a case-variant alias of any consumed key: encoding/json
// struct decoding matches case-insensitively last-wins, so
// {"instructions":"I","INSTRUCTIONS":"K"} would hash K while an exact-case
// consumer reads I — a parser-differential that lets one (era, hash) pair cover
// two different prompt-bearing surfaces (the D-346 shape, found by Codex@max on
// this diff; the same guard already exists for the "tools" page key in Admit).
func resultFields(raw json.RawMessage, what string, keys ...string) (map[string]json.RawMessage, error) {
	if _, err := surfacelock.Canonicalize(raw); err != nil {
		return nil, fmt.Errorf("%s: result is not canonicalizable: %v", what, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s: bad result: %w", what, err)
	}
	for k := range obj {
		for _, want := range keys {
			if k != want && strings.EqualFold(k, want) {
				return nil, fmt.Errorf("%s: result carries a case-variant of %q: %q", what, want, k)
			}
		}
	}
	return obj, nil
}

// fetchModern is the stateless flow: server/discover for the surface's
// instructions/serverInfo, then `_meta`-enveloped tools/list pages. The era is
// the offered revision itself — each request names the dialect it speaks — and
// discover's supportedVersions must confirm it, or the dialect the bytes were
// served under is unknown and there is no surface to era-tag. Every failure up
// to and including that confirmation is wrapped errPreCommit; nothing after it
// is.
func fetchModern(ctx context.Context, sess session, offered string, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	discRaw, err := sess.call(ctx, "server/discover", map[string]any{"_meta": metaEnvelope(offered)})
	if err != nil {
		return nil, errPreCommit{err}
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
	if h, ok := sess.(*httpSession); ok {
		h.proto = offered
	}
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
	var era string
	if err := json.Unmarshal(obj["protocolVersion"], &era); err != nil || era == "" {
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
		if p.NextCursor == nil {
			return nil
		}
		var next string
		if err := json.Unmarshal(p.NextCursor, &next); err != nil {
			return fmt.Errorf("tools/list: %w: nextCursor is not a string", surfacelock.ErrInadmissible)
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
