package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// httpBackend bridges the stdio front to a Streamable HTTP upstream: each
// client frame is POSTed; JSON responses come back as one frame; SSE responses
// are relayed event-by-event AS THEY ARRIVE (a buffered relay would break
// long-lived streams — subscriptions/listen, progress notifications — and
// delay the tools/list_changed signal mid-session verification exists for).
type httpBackend struct {
	name        string
	url         string
	client      *http.Client
	frames      chan []byte
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	notifOnce   sync.Once
	closeOnce   sync.Once
	finding     func(format string, args ...any)
	onTransport func()

	mu        sync.Mutex
	sessionID string
	proto     string // negotiated era; the MCP-Protocol-Version header post-handshake
	closed    bool   // no wg.Add after Close has begun wg.Wait
}

const httpCloseTimeout = 5 * time.Second

func newHTTPBackend(target string, finding func(string, ...any), onTransport func()) (*httpBackend, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("target %q is not an http(s) URL", target)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &httpBackend{
		url: target, client: &http.Client{}, frames: make(chan []byte, 64),
		ctx: ctx, cancel: cancel, finding: finding, onTransport: onTransport,
	}, nil
}

// Send POSTs one client frame. It returns immediately; the response (or a
// synthetic, clearly-transport-labeled error frame) arrives on Frames. The
// frame has already passed the core's envelope discipline.
func (b *httpBackend) Send(_ context.Context, frame []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(frame, &obj); err != nil {
		return fmt.Errorf("frame does not parse: %w", err)
	}
	idRaw := obj["id"]
	if idRaw != nil && isJSONNull(idRaw) {
		idRaw = nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return context.Canceled
	}
	b.wg.Add(1)
	b.mu.Unlock()
	go b.roundTrip(frame, idRaw, cheapMetaEra(obj["params"]))
	return nil
}

// cheapMetaEra extracts the reserved _meta protocolVersion for the
// MCP-Protocol-Version header, without canonicalizing (tools/call params are
// arbitrarily large). This is a transport hint only — the VERIFIED era reading
// is the core's exact-key metaEra; a frame the core consumed fields from has
// already had its aliases refused.
func cheapMetaEra(params json.RawMessage) string {
	if params == nil {
		return ""
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	metaRaw, ok := p["_meta"]
	if !ok {
		return ""
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return ""
	}
	var era string
	if raw, ok := meta[metaProtocolVersionKey]; ok {
		json.Unmarshal(raw, &era)
	}
	return era
}

func (b *httpBackend) roundTrip(frame []byte, idRaw json.RawMessage, reqEra string) {
	defer b.wg.Done()
	req, err := http.NewRequestWithContext(b.ctx, http.MethodPost, b.url, bytes.NewReader(frame))
	if err != nil {
		b.transportFailure(idRaw, fmt.Sprintf("bad upstream request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "surfacelock-proxy/0.1")
	b.mu.Lock()
	if b.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", b.sessionID)
	}
	proto := b.proto
	b.mu.Unlock()
	if reqEra != "" {
		proto = reqEra // stateless: each request names the dialect it speaks
	}
	if proto != "" {
		req.Header.Set("MCP-Protocol-Version", proto)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		if b.ctx.Err() != nil {
			return
		}
		b.transportFailure(idRaw, fmt.Sprintf("upstream request failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		b.mu.Lock()
		b.sessionID = sid
		b.mu.Unlock()
	}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		b.transportFailure(idRaw, fmt.Sprintf("upstream HTTP %d: %s", resp.StatusCode, snippet))
		return
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		body, err := readAllCapped(resp.Body, relayFrameCap)
		if err != nil {
			b.transportFailure(idRaw, fmt.Sprintf("upstream response read: %v", err))
			return
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return // empty 200 on a notification
		}
		b.emit(body)
	case strings.HasPrefix(ct, "text/event-stream"):
		b.relaySSE(resp.Body, idRaw)
	default:
		b.transportFailure(idRaw, fmt.Sprintf("unexpected upstream content-type %.60q", ct))
	}
}

// relaySSE relays each SSE event as one frame the moment it completes. When the
// stream was answering a request (idRaw non-nil) and ends without a matching
// response, a transport error frame is synthesized so the client is not left
// waiting on nothing.
func (b *httpBackend) relaySSE(body io.Reader, idRaw json.RawMessage) {
	wantKeys := map[string]bool{}
	if idRaw != nil {
		for _, k := range responseIDKeys(idRaw) {
			wantKeys[k] = true
		}
	}
	sawResponse := false
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), relayFrameCap)
	var data bytes.Buffer
	flush := func() {
		if data.Len() == 0 {
			return
		}
		frame := append([]byte(nil), data.Bytes()...)
		data.Reset()
		if idRaw != nil && !sawResponse {
			var env map[string]json.RawMessage
			if err := json.Unmarshal(frame, &env); err == nil {
				if got, ok := env["id"]; ok {
					if key, err := idKeyFor(got); err == nil && wantKeys[key] {
						sawResponse = true
					}
				}
			}
		}
		b.emit(frame)
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len()+len(v) > relayFrameCap {
				b.transportFailure(idRaw, fmt.Sprintf("sse event exceeds %d bytes", relayFrameCap))
				return
			}
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	flush()
	if err := sc.Err(); err != nil && b.ctx.Err() == nil {
		b.finding("upstream sse stream broke: %s", boundText(err.Error(), 200))
	}
	if idRaw != nil && !sawResponse && b.ctx.Err() == nil {
		b.transportFailure(idRaw, "upstream stream ended without a response")
	}
}

// StartNotificationStream opens (and keeps re-opening) the standalone GET
// stream that carries server-initiated messages on the classic Streamable HTTP
// flow. Without it, notifications/tools/list_changed would never cross the
// bridge and the client's mid-session re-list — the event the proxy most wants
// to verify — would be silently suppressed.
func (b *httpBackend) StartNotificationStream() {
	b.notifOnce.Do(func() {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return
		}
		b.wg.Add(1)
		b.mu.Unlock()
		go b.notifLoop()
	})
}

func (b *httpBackend) notifLoop() {
	defer b.wg.Done()
	for b.ctx.Err() == nil {
		req, err := http.NewRequestWithContext(b.ctx, http.MethodGet, b.url, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("User-Agent", "surfacelock-proxy/0.1")
		b.mu.Lock()
		if b.sessionID != "" {
			req.Header.Set("Mcp-Session-Id", b.sessionID)
		}
		if b.proto != "" {
			req.Header.Set("MCP-Protocol-Version", b.proto)
		}
		b.mu.Unlock()
		resp, err := b.client.Do(req)
		if err == nil {
			switch {
			case resp.StatusCode >= 200 && resp.StatusCode <= 299 &&
				strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"):
				b.relaySSE(resp.Body, nil)
			case resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound ||
				resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
				resp.Body.Close()
				return // this server has no notification stream; that is allowed
			}
			resp.Body.Close()
		}
		select {
		case <-time.After(2 * time.Second):
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *httpBackend) SetProto(era string) {
	b.mu.Lock()
	b.proto = era
	b.mu.Unlock()
}

// transportFailure reports an upstream transport problem: an honest error,
// NEVER a drift verdict — the wording, the JSON-RPC error code, and the exit
// outcome all keep the two apart (an unreachable server needs "bring the server
// back", not "re-pin the lock").
func (b *httpBackend) transportFailure(idRaw json.RawMessage, detail string) {
	detail = boundText(detail, 300)
	b.finding("upstream transport: %s", detail)
	b.onTransport()
	if idRaw == nil {
		return
	}
	b.emit(errorFrame(idRaw, codeTransportFailed,
		"surfacelock proxy: upstream transport failure (not drift): "+detail))
}

func (b *httpBackend) emit(frame []byte) {
	select {
	case b.frames <- frame:
	case <-b.ctx.Done():
	}
}

func (b *httpBackend) Frames() <-chan []byte { return b.frames }

// Err is nil: per-request failures are reported in-band as transport-labeled
// error frames, and the backend itself only stops when closed.
func (b *httpBackend) Err() error { return nil }

func (b *httpBackend) Close() {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		sid := b.sessionID
		b.mu.Unlock()
		b.cancel()
		b.wg.Wait()
		if sid != "" {
			// Best-effort session teardown, bounded: a hostile server that hands
			// out a session id and then stalls the DELETE must not extend teardown.
			ctx, cancel := context.WithTimeout(context.Background(), httpCloseTimeout)
			defer cancel()
			if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.url, nil); err == nil {
				req.Header.Set("Mcp-Session-Id", sid)
				if resp, err := b.client.Do(req); err == nil {
					resp.Body.Close()
				}
			}
		}
		close(b.frames)
	})
}

// readAllCapped reads at most cap bytes and fails closed if the source has
// more: a truncated hostile payload must be a refusal, never a shortened parse.
func readAllCapped(r io.Reader, capBytes int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(capBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > capBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", capBytes)
	}
	return b, nil
}
