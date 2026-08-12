package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
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

	// HTTPClient, when non-nil, carries the http transport's requests ("http"
	// only; ignored for stdio). It exists for callers whose target is not
	// directly dialable by a default client — a unix-socket upstream behind a
	// pinned DialContext, a client with redirects refused — and is used as
	// given: Fetch adds no timeouts of its own beyond ctx.
	HTTPClient *http.Client
}

type initializeResult struct {
	ProtocolVersion json.RawMessage `json:"protocolVersion"`
	ServerInfo      json.RawMessage `json:"serverInfo"`
	Instructions    json.RawMessage `json:"instructions"`
}

// discoverResult is the server/discover result's read surface. Like
// initializeResult it is a struct decode: the fields feed era validation,
// ServerInfo sanitization and instructions hashing — all of which treat the
// values as hostile downstream.
type discoverResult struct {
	SupportedVersions []string        `json:"supportedVersions"`
	ServerInfo        json.RawMessage `json:"serverInfo"`
	Instructions      json.RawMessage `json:"instructions"`
}

type toolsListPage struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor json.RawMessage   `json:"nextCursor"`
}

// Fetch runs one fresh session against the server and returns the verbatim
// tools/list surface for admission by surfacelock.Admit, applying the
// fetch-side hostile-input rules (SPEC.md §6): page byte caps, page count cap,
// cursor size cap, and cursor-loop refusal.
//
// Flow selection is offer-driven (SPEC.md §3.1): offering ModernRevision
// tries the stateless flow (server/discover, `_meta`-enveloped tools/list, no
// handshake) and falls back to the classic initialize handshake when the
// server refuses discover; offering any earlier revision speaks classic only,
// so a verifier re-offering a recorded era reproduces the recorded flow.
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
	defer sess.close()

	if offered == ModernRevision {
		raw, merr := fetchModern(ctx, sess, offered, lim)
		if merr == nil {
			return raw, nil
		}
		// A server refusing discover may still negotiate the classic handshake
		// (every pre-stateless SDK does). Reset any transport state the failed
		// attempt left behind so the fallback starts a genuinely fresh session.
		if h, ok := sess.(*httpSession); ok {
			h.sessionID, h.proto = "", ""
		}
		raw, cerr := fetchClassic(ctx, sess, offered, lim)
		if cerr == nil {
			return raw, nil
		}
		return nil, fmt.Errorf("server/discover: %v; initialize fallback: %w", merr, cerr)
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

// fetchModern is the stateless flow: server/discover for the surface's
// instructions/serverInfo, then `_meta`-enveloped tools/list pages. The era is
// the offered revision itself — each request names the dialect it speaks — and
// discover's supportedVersions must confirm it, or the dialect the bytes were
// served under is unknown and there is no surface to era-tag.
func fetchModern(ctx context.Context, sess session, offered string, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	discRaw, err := sess.call(ctx, "server/discover", map[string]any{"_meta": metaEnvelope(offered)})
	if err != nil {
		return nil, err
	}
	var dr discoverResult
	if err := json.Unmarshal(discRaw, &dr); err != nil {
		return nil, fmt.Errorf("server/discover: bad result: %w", err)
	}
	if !slices.Contains(dr.SupportedVersions, offered) {
		return nil, fmt.Errorf("server/discover: supportedVersions %q does not include the offered %q", dr.SupportedVersions, offered)
	}
	if h, ok := sess.(*httpSession); ok {
		h.proto = offered
	}
	raw := &surfacelock.RawSurface{
		Offered:      offered,
		Era:          offered,
		Instructions: dr.Instructions,
		ServerInfo:   dr.ServerInfo,
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
	var ir initializeResult
	if err := json.Unmarshal(initRaw, &ir); err != nil {
		return nil, fmt.Errorf("initialize: bad result: %w", err)
	}
	var era string
	if err := json.Unmarshal(ir.ProtocolVersion, &era); err != nil || era == "" {
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
		Instructions: ir.Instructions,
		ServerInfo:   ir.ServerInfo,
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
