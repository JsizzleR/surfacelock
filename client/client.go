// Package client fetches an MCP server's tool surface over Streamable HTTP or
// stdio, applying the SPEC.md §6 fetch-side admissibility rules (page caps, cursor
// loops, size caps). Both transports are ports of the measured spike client that
// probed the 44-server viability corpus.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/JsizzleR/surfacelock"
)

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}

type session interface {
	call(ctx context.Context, method string, params any) (json.RawMessage, error)
	notify(ctx context.Context, method string, params any) error
	close()
}

func marshalReq(id int64, method string, params any) ([]byte, error) {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return json.Marshal(m)
}

func marshalNotify(method string, params any) ([]byte, error) {
	m := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		m["params"] = params
	}
	return json.Marshal(m)
}

func resultFromMessage(raw []byte, id int64, method string) (json.RawMessage, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: bad json response: %w", method, err)
	}
	if !idMatches(env.ID, id) {
		return nil, fmt.Errorf("%s: response id mismatch", method)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("%s: rpc error %d: %q", method, env.Error.Code, env.Error.Message)
	}
	return env.Result, nil
}

func idMatches(raw json.RawMessage, id int64) bool {
	if len(raw) == 0 {
		return false
	}
	var got int64
	if err := json.Unmarshal(raw, &got); err == nil {
		return got == id
	}
	var s string // some servers echo numeric ids back as strings
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == fmt.Sprint(id)
	}
	return false
}

// readCapped reads at most limit bytes and fails closed if the source has more:
// a truncated hostile payload must be a refusal, never a silently shortened parse.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", surfacelock.ErrInadmissible, limit)
	}
	return b, nil
}

// ---- Streamable HTTP transport ----

type httpSession struct {
	url       string
	client    *http.Client
	sessionID string
	proto     string // negotiated; sent as MCP-Protocol-Version after initialize
	nextID    int64
	pageCap   int
}

func newHTTPSession(url string, pageCap int) *httpSession {
	return &httpSession{url: url, client: &http.Client{}, nextID: 1, pageCap: pageCap}
}

func (h *httpSession) post(ctx context.Context, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "surfacelock/0.1")
	if h.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", h.sessionID)
	}
	if h.proto != "" {
		req.Header.Set("MCP-Protocol-Version", h.proto)
	}
	return h.client.Do(req)
}

func (h *httpSession) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := h.nextID
	h.nextID++
	body, err := marshalReq(id, method, params)
	if err != nil {
		return nil, err
	}
	resp, err := h.post(ctx, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("%s: HTTP %d: %q", method, resp.StatusCode, snippet)
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		raw, err := readCapped(resp.Body, h.pageCap)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		return resultFromMessage(raw, id, method)
	case strings.HasPrefix(ct, "text/event-stream"):
		return h.readSSE(resp.Body, id, method)
	default:
		return nil, fmt.Errorf("%s: unexpected content-type %q", method, ct)
	}
}

// readSSE scans events until it finds the JSON-RPC response whose id matches.
func (h *httpSession) readSSE(r io.Reader, id int64, method string) (json.RawMessage, error) {
	// The stream cap is a small multiple of the page cap: a response can arrive
	// after unrelated notification events, but an unbounded stream is a refusal.
	sc := bufio.NewScanner(io.LimitReader(r, int64(h.pageCap)*4))
	sc.Buffer(make([]byte, 64*1024), h.pageCap)
	var data strings.Builder
	flush := func() (json.RawMessage, bool, error) {
		if data.Len() == 0 {
			return nil, false, nil
		}
		payload := data.String()
		data.Reset()
		var env envelope
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			return nil, false, nil // non-JSON event; skip
		}
		if !idMatches(env.ID, id) {
			return nil, false, nil // notification or other id; skip
		}
		if env.Error != nil {
			return nil, true, fmt.Errorf("%s: rpc error %d: %q", method, env.Error.Code, env.Error.Message)
		}
		return env.Result, true, nil
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			res, done, err := flush()
			if done || err != nil {
				return res, err
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len()+len(v) > h.pageCap {
				return nil, fmt.Errorf("%s: %w: sse event exceeds %d bytes", method, surfacelock.ErrInadmissible, h.pageCap)
			}
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	if res, done, err := flush(); done || err != nil {
		return res, err
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("%s: %w: sse line exceeds %d bytes", method, surfacelock.ErrInadmissible, h.pageCap)
		}
		return nil, fmt.Errorf("%s: sse read: %w", method, err)
	}
	return nil, fmt.Errorf("%s: sse stream ended without a response for id %d", method, id)
}

func (h *httpSession) notify(ctx context.Context, method string, params any) error {
	body, err := marshalNotify(method, params)
	if err != nil {
		return err
	}
	resp, err := h.post(ctx, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return nil
}

func (h *httpSession) close() {
	if h.sessionID == "" {
		return
	}
	// Best-effort session teardown; bounded so close never hangs on a dead server.
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", h.sessionID)
	if resp, err := h.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// ---- stdio transport ----

type stdioSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	msgs   chan envelope
	rdErr  chan error
	done   chan struct{} // closed by close(); frees a reader parked on a full msgs
	closed sync.Once
	nextID int64
}

func newStdioSession(argv, extraEnv []string, lineCap int) (*stdioSession, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stderr = io.Discard // must drain or a chatty server blocks on a full pipe
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s := &stdioSession{cmd: cmd, stdin: stdin, msgs: make(chan envelope, 64),
		rdErr: make(chan error, 1), done: make(chan struct{}), nextID: 1}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), lineCap)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 || line[0] != '{' {
				continue // tolerate log lines from misbehaving servers
			}
			var env envelope
			if err := json.Unmarshal(line, &env); err != nil {
				continue
			}
			// Select on done so a reader parked here (consumer stopped draining
			// after ctx cancellation or after the final page) is freed by close()
			// instead of leaking — SIGKILL unblocks a pipe read, never a channel
			// send. Matters for a long-lived importer, not the short-lived CLI.
			select {
			case s.msgs <- env:
			case <-s.done:
				return
			}
		}
		err := sc.Err()
		if err == nil {
			err = errors.New("server closed stdout")
		} else if errors.Is(err, bufio.ErrTooLong) {
			err = fmt.Errorf("%w: stdout line exceeds %d bytes", surfacelock.ErrInadmissible, lineCap)
		}
		s.rdErr <- err
		close(s.msgs)
	}()
	return s, nil
}

func (s *stdioSession) send(ctx context.Context, body []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := s.stdin.Write(append(body, '\n'))
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *stdioSession) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := s.nextID
	s.nextID++
	body, err := marshalReq(id, method, params)
	if err != nil {
		return nil, err
	}
	if err := s.send(ctx, body); err != nil {
		return nil, fmt.Errorf("%s: write: %w", method, err)
	}
	for {
		select {
		case env, ok := <-s.msgs:
			if !ok {
				return nil, fmt.Errorf("%s: %w", method, <-s.rdErr)
			}
			if !idMatches(env.ID, id) {
				continue // notification or unrelated message
			}
			if env.Error != nil {
				return nil, fmt.Errorf("%s: rpc error %d: %q", method, env.Error.Code, env.Error.Message)
			}
			return env.Result, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", method, ctx.Err())
		}
	}
}

func (s *stdioSession) notify(ctx context.Context, method string, params any) error {
	body, err := marshalNotify(method, params)
	if err != nil {
		return err
	}
	return s.send(ctx, body)
}

func (s *stdioSession) close() {
	// Idempotent: a second close() must not signal a REUSED process group after Wait
	// has reaped the pid.
	s.closed.Do(func() {
		close(s.done) // free a reader parked on a full msgs channel
		s.stdin.Close()
		if s.cmd.Process != nil {
			// Kill the whole group: npx/uvx wrap the real server in child processes.
			syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		}
		s.cmd.Wait()
	})
}
