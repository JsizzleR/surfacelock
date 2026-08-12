package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/JsizzleR/surfacelock"
)

// DefaultOfferedVersion is the protocol revision offered at initialize when the
// caller does not choose one. Verifiers always re-offer the lockfile's recorded
// value instead, so negotiation is reproducible (SPEC.md §3.1).
const DefaultOfferedVersion = "2026-07-28"

const closeTimeout = 5 * time.Second

// Ref addresses a server the way a lockfile entry does.
type Ref struct {
	Transport string // "http" | "stdio"
	Target    string
	Args      []string
	Env       []string // extra KEY=VAL pairs for stdio; never recorded in a lockfile
	Offered   string   // protocolVersion to offer; DefaultOfferedVersion if empty
}

type initializeResult struct {
	ProtocolVersion json.RawMessage `json:"protocolVersion"`
	ServerInfo      json.RawMessage `json:"serverInfo"`
	Instructions    json.RawMessage `json:"instructions"`
}

type toolsListPage struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor json.RawMessage   `json:"nextCursor"`
}

// Fetch runs one fresh session against the server — initialize (offering
// ref.Offered), notifications/initialized, then a fully-paginated tools/list —
// and returns the verbatim result for admission by surfacelock.Admit. Fetch-side
// hostile-input rules (SPEC.md §6): page byte caps, page count cap, cursor size
// cap, and cursor-loop refusal.
func Fetch(ctx context.Context, ref Ref, lim surfacelock.Limits) (*surfacelock.RawSurface, error) {
	offered := ref.Offered
	if offered == "" {
		offered = DefaultOfferedVersion
	}

	var sess session
	var err error
	switch ref.Transport {
	case "http":
		sess = newHTTPSession(ref.Target, lim.MaxPageBytes)
	case "stdio":
		sess, err = newStdioSession(append([]string{ref.Target}, ref.Args...), ref.Env, lim.MaxPageBytes)
	default:
		return nil, fmt.Errorf("unknown transport %q", ref.Transport)
	}
	if err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	defer sess.close()

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

	cursor := ""
	seenCursors := map[string]bool{}
	for {
		var params any = map[string]any{}
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		page, err := sess.call(ctx, "tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		raw.Pages = append(raw.Pages, page)
		if len(raw.Pages) > lim.MaxPages {
			return nil, fmt.Errorf("tools/list: %w: more than %d pages", surfacelock.ErrInadmissible, lim.MaxPages)
		}
		var p toolsListPage
		if err := json.Unmarshal(page, &p); err != nil {
			return nil, fmt.Errorf("tools/list: %w: page does not parse: %v", surfacelock.ErrInadmissible, err)
		}
		if p.NextCursor == nil {
			break
		}
		var next string
		if err := json.Unmarshal(p.NextCursor, &next); err != nil {
			return nil, fmt.Errorf("tools/list: %w: nextCursor is not a string", surfacelock.ErrInadmissible)
		}
		if next == "" {
			break
		}
		if len(next) > lim.MaxCursorBytes {
			return nil, fmt.Errorf("tools/list: %w: cursor exceeds %d bytes", surfacelock.ErrInadmissible, lim.MaxCursorBytes)
		}
		if seenCursors[next] {
			return nil, fmt.Errorf("tools/list: %w: cursor loop (cursor repeated)", surfacelock.ErrInadmissible)
		}
		seenCursors[next] = true
		cursor = next
	}
	return raw, nil
}
