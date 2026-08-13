// Package conformance measures a live MCP server against the pre-registered
// era predicates in PREDICATES.md and grades a (target, era) pair. The design
// splits PROBING (wire I/O producing a Capture of raw exchanges) from GRADING
// (a pure function Capture → Report), so every verdict is re-derivable from the
// retained capture bytes alone — the matrix artifact is generated, never
// hand-written.
//
// Both wire directions are hostile: every read is byte-capped and fail-closed,
// SSE relays are bounded, and captured bodies are truncated at a recorded cap
// (truncation is stamped on the exchange, so a graded cell can never silently
// rest on cut bytes).
package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Wire bounds. Deliberately generous for real servers (the toolslock-p0 corpus
// maxed at ~100 KiB per tools/list) and small enough that a hostile target
// cannot run the prober out of memory.
const (
	maxBodyBytes    = 1 << 20  // per-response capture cap
	maxSSEBytes     = 4 << 20  // whole-stream read cap while hunting the response event
	maxCaptureBytes = 64 << 10 // per-exchange retained body (grading + artifact)
	exchangeTimeout = 15 * time.Second
	maxPages        = 8 // T1's stated page bound
)

// Exchange is one probe round-trip, retained verbatim (capped) in the capture.
type Exchange struct {
	Probe     string            `json:"probe"`             // predicate id + step, e.g. "T1.page0"
	Request   string            `json:"request,omitempty"` // body sent ("" for GET)
	HTTPVerb  string            `json:"http_verb,omitempty"`
	ReqHdr    map[string]string `json:"req_hdr,omitempty"`  // interesting request headers
	Status    int               `json:"status,omitempty"`   // HTTP status; 0 on stdio or transport failure
	RespHdr   map[string]string `json:"resp_hdr,omitempty"` // Mcp-Session-Id / Content-Type only
	Body      string            `json:"body,omitempty"`     // raw response body, capped
	Message   string            `json:"message,omitempty"`  // the matched JSON-RPC message (extracted from SSE when needed)
	Truncated bool              `json:"truncated,omitempty"`
	Err       string            `json:"err,omitempty"` // transport-level failure (dial, timeout, oversize)
}

// Conn is one session-scoped connection to a target. HTTP conns are cheap and
// carry no state beyond the URL and static headers; a stdio conn is a live
// child process. Fresh sessions come from the Dialer, never from reuse.
type Conn interface {
	// Kind is "http" or "stdio".
	Kind() string
	// Roundtrip sends body and returns the exchange for it. hdr is merged over
	// the conn's static headers (HTTP only; ignored on stdio). id is the JSON-RPC
	// id the response is matched by; id == 0 means fire-and-forget (a
	// notification, or a probe whose response is graded by transport status
	// alone) — the exchange then records whatever immediate response arrived.
	Roundtrip(ctx context.Context, probe string, body []byte, hdr map[string]string, id int64) *Exchange
	// Get performs a bounded GET with the given headers (HTTP only; a stdio conn
	// records a not-applicable exchange).
	Get(ctx context.Context, probe string, hdr map[string]string) *Exchange
	// Close tears the session down (DELETE for a session-carrying HTTP conn,
	// SIGKILL+wait for stdio). Best-effort, bounded.
	Close()
}

// Dialer mints a fresh session/connection per call.
type Dialer func(ctx context.Context) (Conn, error)

// ---- HTTP ----

// HTTPConn probes one Streamable-HTTP endpoint. Session state (Mcp-Session-Id)
// is NOT tracked implicitly: the prober decides per-exchange which headers to
// send, because session behavior is itself under test.
type HTTPConn struct {
	URL    string
	Client *http.Client
	// Static headers sent on every request (e.g. Authorization for a
	// token-gated target). Per-exchange headers override them.
	Static map[string]string

	// sessionID, when set by the prober after a handshake, is available for it
	// to thread into later exchanges explicitly. The conn itself never sends it.
	sessionID string
}

// NewHTTPDialer returns a Dialer minting fresh HTTPConns (a fresh conn is a
// fresh session by construction — no session header is carried over).
func NewHTTPDialer(url string, client *http.Client, static map[string]string) Dialer {
	if client == nil {
		client = &http.Client{Timeout: exchangeTimeout}
	}
	return func(ctx context.Context) (Conn, error) {
		return &HTTPConn{URL: url, Client: client, Static: static}, nil
	}
}

func (h *HTTPConn) Kind() string { return "http" }

func (h *HTTPConn) headers(extra map[string]string) map[string]string {
	m := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
		"User-Agent":   "surfacelock-conformance/0.1",
	}
	for k, v := range h.Static {
		m[k] = v
	}
	for k, v := range extra {
		if v == "" {
			delete(m, k) // explicit suppression: "send WITHOUT this header"
			continue
		}
		m[k] = v
	}
	return m
}

func (h *HTTPConn) Roundtrip(ctx context.Context, probe string, body []byte, hdr map[string]string, id int64) *Exchange {
	ex := &Exchange{Probe: probe, Request: capString(string(body), maxCaptureBytes), HTTPVerb: "POST"}
	cctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		ex.Err = err.Error()
		return ex
	}
	merged := h.headers(hdr)
	for k, v := range merged {
		req.Header.Set(k, v)
	}
	ex.ReqHdr = requestHeaderSubset(merged)
	resp, err := h.Client.Do(req)
	if err != nil {
		ex.Err = capString(err.Error(), 300)
		return ex
	}
	defer resp.Body.Close()
	ex.Status = resp.StatusCode
	ex.RespHdr = respHeaderSubset(resp.Header)
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") && id != 0 {
		msg, raw, truncated, err := readSSEMessage(resp.Body, id)
		ex.Body, ex.Truncated = capString(raw, maxCaptureBytes), truncated
		if err != nil {
			ex.Err = capString(err.Error(), 300)
			return ex
		}
		ex.Message = capString(msg, maxCaptureBytes)
		return ex
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		ex.Err = capString(err.Error(), 300)
		return ex
	}
	if len(raw) > maxBodyBytes {
		raw, ex.Truncated = raw[:maxBodyBytes], true
	}
	ex.Body = capString(string(raw), maxCaptureBytes)
	if json.Valid(raw) {
		ex.Message = ex.Body
	}
	return ex
}

func (h *HTTPConn) Get(ctx context.Context, probe string, hdr map[string]string) *Exchange {
	ex := &Exchange{Probe: probe, HTTPVerb: "GET"}
	// A conforming GET may be an endless SSE stream: bound the whole exchange
	// tightly and read only enough to classify it.
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, h.URL, nil)
	if err != nil {
		ex.Err = err.Error()
		return ex
	}
	merged := h.headers(hdr)
	delete(merged, "Content-Type")
	for k, v := range merged {
		req.Header.Set(k, v)
	}
	ex.ReqHdr = requestHeaderSubset(merged)
	resp, err := h.Client.Do(req)
	if err != nil {
		ex.Err = capString(err.Error(), 300)
		return ex
	}
	defer resp.Body.Close()
	ex.Status = resp.StatusCode
	ex.RespHdr = respHeaderSubset(resp.Header)
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) // classification bytes only
	ex.Body = capString(string(raw), 4096)
	return ex
}

func (h *HTTPConn) Close() {
	if h.sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.URL, nil)
	if err != nil {
		return
	}
	for k, v := range h.Static {
		req.Header.Set(k, v)
	}
	req.Header.Set("Mcp-Session-Id", h.sessionID)
	if resp, err := h.Client.Do(req); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
}

// readSSEMessage scans a bounded SSE stream for the JSON-RPC message with id.
func readSSEMessage(r io.Reader, id int64) (msg, raw string, truncated bool, err error) {
	var kept strings.Builder
	sc := bufio.NewScanner(io.LimitReader(r, maxSSEBytes))
	sc.Buffer(make([]byte, 64*1024), maxBodyBytes)
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if kept.Len() < maxCaptureBytes {
			kept.WriteString(line)
			kept.WriteString("\n")
		} else {
			truncated = true
		}
		if line == "" {
			if payload := data.String(); payload != "" && sseIDMatches(payload, id) {
				return payload, kept.String(), truncated, nil
			}
			data.Reset()
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len()+len(v) > maxBodyBytes {
				return "", kept.String(), true, fmt.Errorf("sse event exceeds %d bytes", maxBodyBytes)
			}
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	if payload := data.String(); payload != "" && sseIDMatches(payload, id) {
		return payload, kept.String(), truncated, nil
	}
	if err := sc.Err(); err != nil {
		return "", kept.String(), truncated, fmt.Errorf("sse read: %w", err)
	}
	return "", kept.String(), truncated, fmt.Errorf("sse stream ended without a response for id %d", id)
}

func sseIDMatches(payload string, id int64) bool {
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal([]byte(payload), &env) != nil {
		return false
	}
	return rpcIDMatches(env.ID, id)
}

// rpcIDMatches accepts the measured echo tolerances: numeric ids may come back
// as strings (the toolslock-p0 corpus fact).
func rpcIDMatches(raw json.RawMessage, id int64) bool {
	if len(raw) == 0 {
		return false
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n == id
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == fmt.Sprintf("%d", id)
	}
	return false
}

func requestHeaderSubset(m map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"Mcp-Session-Id", "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func respHeaderSubset(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"Mcp-Session-Id", "Content-Type"} {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---- stdio ----

// StdioConn probes one child process over ndjson stdio. A fresh session is a
// fresh process; headers, sessions and GET are not-applicable by transport.
type StdioConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	rdDone chan struct{}
	closed sync.Once
}

// NewStdioDialer mints a Dialer that launches argv per session.
func NewStdioDialer(argv []string, extraEnv []string) Dialer {
	return func(ctx context.Context) (Conn, error) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Env = append(cmd.Environ(), extraEnv...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		c := &StdioConn{cmd: cmd, stdin: stdin, lines: make(chan string, 16), rdDone: make(chan struct{})}
		go func() {
			defer close(c.rdDone)
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 64*1024), maxBodyBytes)
			for sc.Scan() {
				select {
				case c.lines <- sc.Text():
				case <-time.After(exchangeTimeout):
					return // prober gone; stop draining
				}
			}
		}()
		return c, nil
	}
}

func (s *StdioConn) Kind() string { return "stdio" }

func (s *StdioConn) Roundtrip(ctx context.Context, probe string, body []byte, hdr map[string]string, id int64) *Exchange {
	ex := &Exchange{Probe: probe, Request: capString(string(body), maxCaptureBytes)}
	if _, err := s.stdin.Write(append(append([]byte{}, body...), '\n')); err != nil {
		ex.Err = capString(err.Error(), 300)
		return ex
	}
	if id == 0 {
		return ex // notification: nothing to match
	}
	deadline := time.After(exchangeTimeout)
	for {
		select {
		case line := <-s.lines:
			if ex.Body == "" {
				ex.Body = capString(line, maxCaptureBytes)
			}
			// A batch request is answered by a batch array; match it as a whole.
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
				ex.Message = capString(line, maxCaptureBytes)
				return ex
			}
			var env struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal([]byte(line), &env) == nil && rpcIDMatches(env.ID, id) {
				ex.Message = capString(line, maxCaptureBytes)
				ex.Body = ex.Message
				return ex
			}
		case <-s.rdDone:
			ex.Err = errChildClosed
			return ex
		case <-deadline:
			ex.Err = errSilence
			return ex
		case <-ctx.Done():
			ex.Err = ctx.Err().Error()
			return ex
		}
	}
}

func (s *StdioConn) Get(_ context.Context, probe string, _ map[string]string) *Exchange {
	return &Exchange{Probe: probe, Err: "not applicable on stdio"}
}

func (s *StdioConn) Close() {
	s.closed.Do(func() {
		_ = s.stdin.Close()
		if s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = s.cmd.Wait()
	})
}

// Stdio non-answers, distinguished for grading: a live child that stays silent
// REFUSES by silence (an inapplicable message ignored on purpose); a child that
// died mid-probe is unreachable, which grades unreached, never a verdict.
const (
	errSilence     = "no response before the exchange timeout"
	errChildClosed = "child closed stdout without a matching response"
)
