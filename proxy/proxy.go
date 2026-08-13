// Package proxy is the in-band verifying proxy: it sits ON the client path
// between an MCP client and one server, forwards the session, and verifies
// every surface-bearing response the session is served — the handshake
// (initialize / server/discover: era, flow, instructions) and every tools/list
// page, including re-lists after notifications/tools/list_changed — against a
// tools.lock entry.
//
// It FAILS CLOSED ON DRIFT: a drifted surface is answered with a JSON-RPC error
// naming the remedy (review, then `surfacelock pin`) and is never forwarded.
// Drift, inadmissible bytes, and transport failure are DIFFERENT refusals with
// different remedies and different error codes: an unreachable server is an
// honest error, never a drift verdict, and vice versa.
//
// The threat this closes: an out-of-band audit (`surfacelock verify`, a
// deploy-gate attestation) can be cloaked — a hostile server can serve the
// auditor clean bytes and the victim's session poisoned ones, because it can
// distinguish the sessions. The proxy hashes what THIS session is served, so
// there is no other session to cloak against.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/JsizzleR/surfacelock"
)

// relayFrameCap bounds one relayed frame in memory, in either direction. It is
// deliberately far above Limits.MaxPageBytes: the proxy relays whole sessions,
// and a tools/call result (a file read, a query result) is legitimately much
// larger than a tools/list page. Surface-bearing responses are still bounded by
// the Limits caps at verification time.
const relayFrameCap = 64 << 20

// maxPending bounds the in-flight request map; a client that streams requests
// without reading responses is refused, not accumulated.
const maxPending = 256

// maxTrackedCursors bounds the issued-cursor map across all enumerations. On
// overflow new cursors are not tracked and their continuations verify as
// orphan enumerations (per-tool verdicts, no completeness claim) — degraded
// honestly, never silently.
const maxTrackedCursors = 1024

// Config configures one proxied session.
type Config struct {
	// Name is the lockfile entry name, used in findings and refusal messages.
	Name string
	// Entry is the locked server entry. It MUST come from a lockfile that
	// passed Validate: the proxy trusts the stored hashes as self-consistent.
	Entry *surfacelock.ServerLock
	// Env is extra KEY=VAL environment for a stdio upstream (never recorded in
	// a lockfile; secrets ride the environment, not the artifact).
	Env []string
	// Warn forwards non-prompt-text drift (schema, metadata, era, flow,
	// removed) with a warning instead of refusing. Drift that introduces
	// unreviewed prompt text — description or instructions changes, added
	// tools — refuses even under Warn.
	Warn bool
	// Limits are the SPEC.md §6 admissibility caps for surface-bearing
	// responses. Zero value means surfacelock.DefaultLimits().
	Limits surfacelock.Limits
	// Findings receives one sanitized line per verification event. nil = discard.
	Findings io.Writer
	// ChildStderr receives a stdio upstream's stderr. nil = discard.
	ChildStderr io.Writer
	// Backend overrides the upstream transport (test seam). nil = built from
	// Entry.Transport/Target/Args.
	Backend Backend
}

// Outcome summarizes a finished session for the CLI exit-code contract.
type Outcome struct {
	Drift        bool // drift was observed (refused, or forwarded under Warn)
	Inadmissible bool // the wire carried bytes no verdict can be built on
	Transport    bool // the session ended on (or saw) an upstream transport failure
}

// Backend is the upstream half of the proxy: Send carries one client frame
// upstream; Frames yields upstream frames (responses, notifications,
// server-initiated requests) until the backend terminates.
type Backend interface {
	Send(ctx context.Context, frame []byte) error
	Frames() <-chan []byte
	// Err reports why Frames closed; nil after a caller-initiated Close.
	Err() error
	Close()
}

// protoAware is implemented by backends that carry a negotiated protocol
// version out-of-band (the Streamable HTTP MCP-Protocol-Version header).
type protoAware interface{ SetProto(era string) }

// notifStreamer is implemented by backends with a server-initiated notification
// channel that must be opened explicitly (the Streamable HTTP standalone GET
// stream). The proxy opens it after a verified classic handshake — without it,
// notifications/tools/list_changed would never reach the client, silently
// suppressing the very re-list that mid-session verification exists to check
// (measured: the real client re-lists within milliseconds of the notification).
type notifStreamer interface{ StartNotificationStream() }

type pendingReq struct {
	method string
	era    string // stateless request dialect (reserved _meta protocolVersion); "" for classic
	enum   *enumeration
}

type core struct {
	cfg     Config
	v       *verifier
	backend Backend

	mu      sync.Mutex // verification and routing state
	pending map[string]*pendingReq
	cursors map[string]*enumeration

	outMu sync.Mutex
	out   io.Writer

	findMu  sync.Mutex
	outcome Outcome
}

// Run proxies one session: client frames arrive on clientIn (newline-delimited
// JSON-RPC, the MCP stdio transport) and are forwarded upstream; upstream
// frames are verified and forwarded to clientOut. Run returns when the client
// closes clientIn, the upstream terminates, or ctx is cancelled.
//
// If the upstream dies first, the goroutine reading clientIn may remain blocked
// in Read until the caller closes clientIn; a CLI process exits and reaps it,
// a long-lived importer must close clientIn itself.
func Run(ctx context.Context, cfg Config, clientIn io.Reader, clientOut io.Writer) (Outcome, error) {
	if cfg.Entry == nil {
		return Outcome{}, errors.New("proxy: Config.Entry is required")
	}
	if cfg.Findings == nil {
		cfg.Findings = io.Discard
	}
	if cfg.ChildStderr == nil {
		cfg.ChildStderr = io.Discard
	}
	if cfg.Limits == (surfacelock.Limits{}) {
		cfg.Limits = surfacelock.DefaultLimits()
	}

	c := &core{
		cfg:     cfg,
		v:       newVerifier(cfg.Entry, cfg.Name, cfg.Warn, cfg.Limits),
		pending: map[string]*pendingReq{},
		cursors: map[string]*enumeration{},
		out:     clientOut,
	}

	backend := cfg.Backend
	if backend == nil {
		var err error
		switch cfg.Entry.Transport {
		case "stdio":
			backend, err = newStdioBackend(cfg.Entry.Target, cfg.Entry.Args, cfg.Env, cfg.ChildStderr)
		case "http":
			backend, err = newHTTPBackend(cfg.Entry.Target, c.finding, c.setTransport)
		default:
			err = fmt.Errorf("unknown transport %q", cfg.Entry.Transport)
		}
		if err != nil {
			return Outcome{Transport: true}, fmt.Errorf("proxy: start upstream: %w", err)
		}
	}
	c.backend = backend

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	inboundDone := make(chan struct{})
	go func() {
		defer close(inboundDone)
		for frame := range backend.Frames() {
			c.handleServerFrame(frame)
		}
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		c.serveClient(ctx, clientIn)
	}()

	select {
	case <-clientDone:
	case <-inboundDone:
	case <-ctx.Done():
	}
	cancel()
	backend.Close()
	<-inboundDone

	if err := backend.Err(); err != nil {
		c.finding("upstream transport failed: %s", boundText(err.Error(), 300))
		c.setTransport()
	}
	c.mu.Lock()
	out := c.outcome
	c.mu.Unlock()
	c.finding("session end: drift=%v inadmissible=%v transport=%v",
		out.Drift, out.Inadmissible, out.Transport)
	return out, nil
}

func (c *core) setDrift()        { c.mu.Lock(); c.outcome.Drift = true; c.mu.Unlock() }
func (c *core) setInadmissible() { c.mu.Lock(); c.outcome.Inadmissible = true; c.mu.Unlock() }
func (c *core) setTransport()    { c.mu.Lock(); c.outcome.Transport = true; c.mu.Unlock() }

func (c *core) finding(format string, args ...any) {
	line := "surfacelock[" + c.cfg.Name + "]: " + surfacelock.Sanitize(fmt.Sprintf(format, args...)) + "\n"
	c.findMu.Lock()
	io.WriteString(c.cfg.Findings, line)
	c.findMu.Unlock()
}

func (c *core) writeFrame(b []byte) {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	c.out.Write(append(b, '\n'))
}

func (c *core) applyVerdict(vd verdict) {
	for _, f := range vd.findings {
		c.finding("%s", f)
	}
	if vd.drift {
		c.setDrift()
	}
	if vd.inadmissible {
		c.setInadmissible()
	}
}

// serveClient reads client frames until EOF or ctx cancellation.
func (c *core) serveClient(ctx context.Context, clientIn io.Reader) {
	sc := bufio.NewScanner(clientIn)
	sc.Buffer(make([]byte, 64<<10), relayFrameCap)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		c.handleClientFrame(ctx, append([]byte(nil), line...))
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			c.finding("client frame exceeds %d bytes — session terminated (framing cannot be recovered)", relayFrameCap)
		} else if ctx.Err() == nil {
			c.finding("client read: %s", boundText(err.Error(), 200))
		}
		c.setTransport()
	}
}

// handleClientFrame routes one client frame: requests are tracked (so their
// responses can be verified), then forwarded; notifications and responses to
// server-initiated requests are forwarded untouched. A frame whose envelope has
// no trustworthy identity (duplicate members, case-variant aliases of consumed
// keys, batching) is refused, never forwarded: the proxy would otherwise vouch
// for a response to a request it could not read the way the server does.
func (c *core) handleClientFrame(ctx context.Context, line []byte) {
	f, err := parseFrame(line)
	if err != nil {
		if errors.Is(err, errNotObject) {
			c.finding("refused client frame: not a single JSON-RPC object (batching is unsupported)")
		} else {
			c.finding("refused client frame: %s", boundText(err.Error(), 200))
		}
		return
	}

	if !f.isRequest() {
		// A notification, or the client's response to a server-initiated request.
		c.forwardUpstream(ctx, f.raw)
		return
	}

	c.mu.Lock()
	if len(c.pending) >= maxPending {
		c.mu.Unlock()
		c.finding("refused client request %s: too many in-flight requests", f.method)
		c.writeFrame(errorFrame(f.idRaw, codeProxyRefused,
			fmt.Sprintf("surfacelock[%s]: too many in-flight requests", c.cfg.Name)))
		return
	}
	if _, dup := c.pending[f.idKey]; dup {
		c.mu.Unlock()
		c.finding("refused client request %s: request id already in flight", f.method)
		c.writeFrame(errorFrame(f.idRaw, codeProxyRefused,
			fmt.Sprintf("surfacelock[%s]: request id already in flight", c.cfg.Name)))
		return
	}

	p := &pendingReq{method: f.method}
	switch f.method {
	case "server/discover":
		era, err := discoverParamsEra(f.obj["params"])
		if err != nil {
			c.mu.Unlock()
			c.finding("refused client request server/discover: %s", boundText(err.Error(), 200))
			c.writeFrame(errorFrame(f.idRaw, codeProxyRefused,
				fmt.Sprintf("surfacelock[%s]: unverifiable server/discover params: %s", c.cfg.Name, boundText(err.Error(), 200))))
			return
		}
		// The discover probe is normal client behavior even against a classic
		// lock (measured: the real client probes and falls back on refusal), so
		// nothing is refused here; the verdict lands on a SUCCESSFUL result.
		p.era = era
	case "tools/list":
		vd, pend := c.prepareToolsList(f)
		if vd != nil {
			c.mu.Unlock()
			c.applyVerdict(*vd)
			c.writeFrame(errorFrame(f.idRaw, vd.code, vd.msg))
			return
		}
		p = pend
	}
	c.pending[f.idKey] = p
	c.mu.Unlock()
	c.forwardUpstream(ctx, f.raw)
}

// prepareToolsList resolves a tools/list request's era, flow and enumeration.
// Called with mu held. A non-nil verdict refuses the request before it is
// forwarded: the refusals here (flow mismatch, era mismatch, no verified
// handshake) are decidable from the request alone, and taking the verdict
// before the upstream sees the request means a doomed exchange never starts.
func (c *core) prepareToolsList(f *frame) (*verdict, *pendingReq) {
	cursor, era, stateless, err := listParams(f.obj["params"])
	if err != nil {
		vd := c.v.inadmissibleVerdict("tools/list request", err)
		return &vd, nil
	}
	if stateless {
		if err := surfacelock.CheckEra(era); err != nil {
			vd := c.v.inadmissibleVerdict("tools/list request", err)
			return &vd, nil
		}
		if c.cfg.Entry.Protocol.Flow == surfacelock.FlowClassic {
			vd := c.v.resolveDrift("tools/list request", nil, false, true, "")
			if vd.refuse {
				return &vd, nil
			}
			c.applyVerdictLocked(vd) // warn mode: forwarded with a warning
		}
		if era != c.cfg.Entry.Protocol.Era {
			vd := c.v.resolveDrift("tools/list request", nil, false, false,
				fmt.Sprintf("session era %q, locked era %q (lock with --offer matching this client, or re-pin)", era, c.cfg.Entry.Protocol.Era))
			if vd.refuse {
				return &vd, nil
			}
			c.applyVerdictLocked(vd)
		}
	} else {
		if c.v.handshakeEra == "" {
			vd := c.v.inadmissibleVerdict("tools/list request",
				errors.New("no verified handshake on a classic session — there is no era to verify the response against"))
			return &vd, nil
		}
		era = c.v.handshakeEra
	}

	var en *enumeration
	if cursor != "" {
		if known, ok := c.cursors[cursor]; ok {
			delete(c.cursors, cursor) // cursors are single-use
			en = known
		} else {
			en = c.v.newEnumeration(era, true) // unknown cursor: orphan, no completeness claim
		}
	} else {
		en = c.v.newEnumeration(era, false)
	}
	return nil, &pendingReq{method: "tools/list", era: era, enum: en}
}

// applyVerdictLocked is applyVerdict for call sites already holding mu.
func (c *core) applyVerdictLocked(vd verdict) {
	for _, f := range vd.findings {
		c.finding("%s", f)
	}
	if vd.drift {
		c.outcome.Drift = true
	}
	if vd.inadmissible {
		c.outcome.Inadmissible = true
	}
}

func (c *core) forwardUpstream(ctx context.Context, raw []byte) {
	if err := c.backend.Send(ctx, raw); err != nil {
		if ctx.Err() != nil {
			return
		}
		c.finding("upstream send failed: %s", boundText(err.Error(), 200))
		c.setTransport()
	}
}

// handleServerFrame routes one upstream frame. Responses to tracked
// surface-bearing requests are verified before forwarding; a response whose id
// matches nothing in flight is DROPPED — surface bytes must never reach the
// client through correlation confusion — and everything else (notifications,
// server-initiated requests, responses to other tracked requests) passes
// through verbatim.
func (c *core) handleServerFrame(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	f, err := parseFrame(line)
	if err != nil {
		if errors.Is(err, errNotObject) {
			return // non-JSON noise on a stdio server's stdout is endemic; skip
		}
		c.finding("dropped upstream frame with unverifiable envelope: %s", boundText(err.Error(), 200))
		c.setInadmissible()
		return
	}

	if f.method != "" {
		// Server-initiated request or notification (tools/list_changed rides
		// here). Forward: suppressing a notification would hide the re-list
		// trigger mid-session verification exists to observe.
		c.writeFrame(f.raw)
		return
	}
	if f.idKey == "" {
		return // no id, no method: not a JSON-RPC message
	}

	c.mu.Lock()
	var p *pendingReq
	var key string
	for _, k := range responseIDKeys(f.idRaw) {
		if got, ok := c.pending[k]; ok {
			p, key = got, k
			break
		}
	}
	if p == nil {
		c.mu.Unlock()
		c.finding("dropped unsolicited response (id not in flight)")
		return
	}
	delete(c.pending, key)

	_, hasResult := f.obj["result"]
	_, hasError := f.obj["error"]
	surfaceBearing := p.method == "initialize" || p.method == "server/discover" || p.method == "tools/list"

	if hasError && !hasResult {
		c.mu.Unlock()
		// The upstream's own refusal (e.g. the discover probe refused by a
		// classic server). Its error object is hostile bytes, but it is the
		// server speaking for itself, not the proxy vouching for a surface.
		c.writeFrame(f.raw)
		return
	}
	if !hasResult || hasError {
		if surfaceBearing {
			vd := c.v.inadmissibleVerdict(p.method+" response",
				errors.New("response carries neither a lone result nor a lone error"))
			c.applyVerdictLocked(vd)
			c.mu.Unlock()
			c.writeFrame(errorFrame(f.idRaw, vd.code, vd.msg))
			return
		}
		c.mu.Unlock()
		c.writeFrame(f.raw)
		return
	}

	if !surfaceBearing {
		c.mu.Unlock()
		c.writeFrame(f.raw)
		return
	}

	result := f.obj["result"]
	var vd verdict
	switch p.method {
	case "initialize":
		vd = c.v.verifyHandshake(surfacelock.FlowClassic, result, "")
	case "server/discover":
		if p.era == "" {
			vd = c.v.inadmissibleVerdict("server/discover result",
				errors.New("request carried no protocolVersion _meta — the result cannot be era-tagged"))
		} else {
			vd = c.v.verifyHandshake(surfacelock.FlowStateless, result, p.era)
		}
	case "tools/list":
		var next string
		vd, next = c.v.verifyToolsPage(p.enum, result)
		if !vd.refuse && next != "" {
			if len(c.cursors) < maxTrackedCursors {
				c.cursors[next] = p.enum
			} else {
				vd.findings = append(vd.findings,
					"cursor tracking is full; the continuation will verify as a partial enumeration")
			}
		}
	}
	handshakeVerified := (p.method == "initialize") && !vd.refuse
	c.applyVerdictLocked(vd)
	c.mu.Unlock()

	if vd.refuse {
		c.writeFrame(errorFrame(f.idRaw, vd.code, vd.msg))
		return
	}
	if handshakeVerified {
		if pa, ok := c.backend.(protoAware); ok {
			pa.SetProto(c.v.handshakeEra)
		}
		if ns, ok := c.backend.(notifStreamer); ok {
			ns.StartNotificationStream()
		}
	}
	c.writeFrame(f.raw)
}

// listParams reads a tools/list request's cursor and stateless era with
// exact-key discipline. Client params here are consumed input: a case-variant
// alias of a consumed key, or duplicate members, would let the proxy track a
// different request than the server answers.
func listParams(params json.RawMessage) (cursor, era string, stateless bool, err error) {
	if params == nil || isJSONNull(params) {
		return "", "", false, nil
	}
	obj, err := surfacelock.DecodeExact(params, "tools/list params", "cursor", "_meta")
	if err != nil {
		return "", "", false, err
	}
	if raw, ok := obj["cursor"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &cursor); err != nil {
			return "", "", false, errors.New("cursor is not a string")
		}
	}
	era, stateless, err = metaEra(obj["_meta"])
	if err != nil {
		return "", "", false, err
	}
	return cursor, era, stateless, nil
}

// discoverParamsEra reads a server/discover request's reserved _meta
// protocolVersion (the dialect its result will be served under).
func discoverParamsEra(params json.RawMessage) (string, error) {
	if params == nil || isJSONNull(params) {
		return "", nil
	}
	obj, err := surfacelock.DecodeExact(params, "server/discover params", "_meta")
	if err != nil {
		return "", err
	}
	era, _, err := metaEra(obj["_meta"])
	return era, err
}

// metaProtocolVersionKey is the reserved stateless-revision envelope key; its
// presence is what marks a request as speaking the stateless dialect (measured:
// classic-flow requests also carry _meta, with client-private keys, so _meta
// presence alone is not the marker).
const metaProtocolVersionKey = "io.modelcontextprotocol/protocolVersion"

func metaEra(metaRaw json.RawMessage) (era string, stateless bool, err error) {
	if metaRaw == nil || isJSONNull(metaRaw) {
		return "", false, nil
	}
	meta, err := surfacelock.DecodeExact(metaRaw, "request _meta", metaProtocolVersionKey)
	if err != nil {
		return "", false, err
	}
	raw, ok := meta[metaProtocolVersionKey]
	if !ok || isJSONNull(raw) {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &era); err != nil {
		return "", false, errors.New("_meta protocolVersion is not a string")
	}
	return era, true, nil
}
