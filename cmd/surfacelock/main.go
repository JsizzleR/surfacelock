// Command surfacelock is the CI face of the tools.lock format: lock, verify, diff,
// and pin an MCP server's tool surface. Exit codes are the SPEC.md §9 contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/JsizzleR/surfacelock"
	"github.com/JsizzleR/surfacelock/client"
	"github.com/JsizzleR/surfacelock/proxy"
)

// SPEC.md §9 exit codes. "The surface changed" and "there is no surface to judge"
// must never be confused by a pipeline, in either direction.
const (
	exitOK           = 0
	exitDrift        = 1
	exitUsage        = 2
	exitTransport    = 3
	exitLockfile     = 4
	exitInadmissible = 5
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = `usage: surfacelock <command> [flags] [target]

commands:
  lock    capture a server's tool surface into the lockfile (new entry only)
  verify  re-fetch every entry (or --name one) and fail on drift   [CI verb]
  diff    like verify, but report per-tool, severity-classified
  pin     re-fetch and rewrite an existing entry (explicit re-lock)
  proxy   sit on the client path (stdio) and verify what THIS session is served

target (lock only):
  --url URL            Streamable HTTP endpoint
  -- CMD [ARGS...]     stdio server command

flags:
  --file PATH    lockfile path (default tools.lock)
  --name NAME    entry name (default: URL host / command basename; lock, or one entry)
  --timeout D    per-server fetch budget (default 60s; lock/verify/diff/pin)
  --offer V      protocolVersion to offer at initialize (lock only; default ` + client.DefaultOfferedVersion + `)
  --env K=V      extra environment for stdio servers (repeatable; never recorded)
  --json         lock/verify/diff: machine-readable report on stdout (CLI-JSON.md;
                 exit codes unchanged)
  --warn         proxy only: forward non-prompt-text drift with a warning;
                 description/instructions changes and added tools still refuse

proxy: point the MCP client at this command instead of the server —
  {"command":"surfacelock","args":["proxy","--file","/abs/tools.lock","--name","NAME"]}
The upstream (stdio command or Streamable HTTP URL) comes from the lockfile entry.

exit codes: 0 ok · 1 drift · 2 usage · 3 transport/protocol · 4 lockfile · 5 inadmissible surface`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cmd := args[0]
	switch cmd {
	case "lock", "verify", "diff", "pin", "proxy":
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "surfacelock: unknown command %q\n%s\n", cmd, usage)
		return exitUsage
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "tools.lock", "lockfile path")
	name := fs.String("name", "", "entry name")
	timeout := fs.Duration("timeout", 60*time.Second, "per-server fetch budget")
	offer := fs.String("offer", client.DefaultOfferedVersion, "protocolVersion to offer (lock only)")
	urlFlag := fs.String("url", "", "Streamable HTTP endpoint (lock only)")
	warn := fs.Bool("warn", false, "proxy only: forward non-prompt-text drift with a warning")
	jsonOut := fs.Bool("json", false, "machine-readable report on stdout (lock/verify/diff)")
	var env multiFlag
	fs.Var(&env, "env", "extra KEY=VAL for stdio servers (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}

	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr, file: *file, name: *name,
		timeout: *timeout, offer: *offer, url: *urlFlag, warn: *warn, jsonOut: *jsonOut,
		env: env, argv: fs.Args()}
	if c.jsonOut && (cmd == "pin" || cmd == "proxy") {
		// Fail closed: a caller asking for the machine contract on a verb that
		// does not emit it must not silently get the human output instead.
		c.errorf("--json is not supported for %s", cmd)
		return exitUsage
	}

	switch cmd {
	case "lock":
		return c.lock()
	case "verify":
		return c.compare(false)
	case "diff":
		return c.compare(true)
	case "pin":
		return c.pin()
	case "proxy":
		return c.proxy()
	}
	return exitUsage
}

type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	file, name     string
	timeout        time.Duration
	offer          string
	url            string
	warn           bool
	jsonOut        bool
	env            []string
	argv           []string
}

// errorf writes a diagnostic to stderr with all control characters neutralized.
// Error strings carry server-controlled bytes (rpc error messages, HTTP body
// snippets, era strings), and this output lands in terminals and CI logs — a hostile
// server must not be able to smuggle ANSI escapes or cursor control through them. This
// is the blanket boundary defense; call sites also use %q on individual untrusted
// values, but neither alone is sufficient for every future error path.
func (c *cli) errorf(format string, args ...any) {
	fmt.Fprintln(c.stderr, "surfacelock: "+safe(fmt.Sprintf(format, args...)))
}

// safe renders a string with control characters (C0, DEL, and other Unicode control
// runes) escaped, so untrusted content cannot rewrite the terminal.
func safe(s string) string { return surfacelock.Sanitize(s) }

// exitFor maps an error to the SPEC.md §9 exit code contract.
func exitFor(err error) int {
	switch {
	case errors.Is(err, surfacelock.ErrInadmissible):
		return exitInadmissible
	case errors.Is(err, surfacelock.ErrLockfile):
		return exitLockfile
	default:
		return exitTransport
	}
}

// targetRef resolves the lock target from --url or the post-flag argv.
func (c *cli) targetRef() (client.Ref, string, error) {
	if c.url != "" && len(c.argv) > 0 {
		return client.Ref{}, "", errors.New("give either --url or a stdio command, not both")
	}
	switch {
	case c.url != "":
		u, err := url.Parse(c.url)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return client.Ref{}, "", fmt.Errorf("--url %q is not an http(s) URL", c.url)
		}
		return client.Ref{Transport: "http", Target: c.url, Offered: c.offer}, u.Host, nil
	case len(c.argv) > 0:
		ref := client.Ref{Transport: "stdio", Target: c.argv[0], Args: c.argv[1:], Env: c.env, Offered: c.offer}
		return ref, filepath.Base(c.argv[0]), nil
	default:
		return client.Ref{}, "", errors.New("no target: give --url URL or -- CMD [ARGS...]")
	}
}

func refFromEntry(e *surfacelock.ServerLock, env []string) client.Ref {
	return client.Ref{Transport: e.Transport, Target: e.Target, Args: e.Args,
		Env: env, Offered: e.Protocol.Offered, Flow: e.Protocol.Flow}
}

func (c *cli) fetchSurface(ref client.Ref) (*surfacelock.Surface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	lim := surfacelock.DefaultLimits()
	raw, err := client.Fetch(ctx, ref, lim)
	if err != nil {
		return nil, err
	}
	return surfacelock.Admit(*raw, lim)
}

func (c *cli) readLockfile() (*surfacelock.Lockfile, error) {
	b, err := os.ReadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", surfacelock.ErrLockfile, err)
	}
	lf, err := surfacelock.Parse(b)
	if err != nil {
		return nil, err
	}
	// SPEC.md §7: a reader MUST reject a self-inconsistent lockfile. Validate the
	// whole file at read time so every verb refuses a corrupt/tampered entry — not
	// only the one it happens to touch — and lock/pin never re-render corruption.
	if err := lf.Validate(); err != nil {
		return nil, err
	}
	return lf, nil
}

func (c *cli) writeLockfile(lf *surfacelock.Lockfile) error {
	b, err := lf.Render()
	if err != nil {
		return err
	}
	return os.WriteFile(c.file, b, 0o644)
}

func (c *cli) lock() int {
	rep := c.newReport("lock")
	ref, defaultName, err := c.targetRef()
	if err != nil {
		c.errorf("%v", err)
		return c.fail(rep, exitUsage, err)
	}
	name := c.name
	if name == "" {
		name = defaultName
	}

	lf, err := c.readLockfile()
	if errors.Is(err, os.ErrNotExist) {
		lf = surfacelock.NewLockfile()
	} else if err != nil {
		c.errorf("%v", err)
		return c.fail(rep, exitLockfile, err)
	}
	if _, exists := lf.Servers[name]; exists {
		err := fmt.Errorf("entry %q already exists in %s; accepting a changed surface is pin's job", name, c.file)
		c.errorf("%v", err)
		return c.fail(rep, exitUsage, err)
	}

	surface, err := c.fetchSurface(ref)
	if err != nil {
		c.errorf("%v", err)
		return c.fail(rep, exitFor(err), err)
	}
	entry, err := surfacelock.EntryFromSurface(ref.Transport, ref.Target, ref.Args, surface)
	if err != nil {
		c.errorf("%v", err)
		return c.fail(rep, exitTransport, err)
	}
	lf.Servers[name] = entry
	if err := c.writeLockfile(lf); err != nil {
		// Wrap before fail so the report says WHICH half failed (read vs
		// write) — a consumer must not need stderr to learn that.
		err = fmt.Errorf("write %s: %w", c.file, err)
		c.errorf("%v", err)
		return c.fail(rep, exitLockfile, err)
	}
	n := len(entry.Tools)
	rep.Name, rep.Tools, rep.Era, rep.SurfaceHash = name, &n, entry.Protocol.Era, entry.SurfaceHash
	if !c.jsonOut {
		fmt.Fprintf(c.stdout, "locked %s: %d tools, era %s, %s\n",
			safe(name), len(entry.Tools), safe(entry.Protocol.Era), entry.SurfaceHash)
	}
	return c.finish(rep, exitOK)
}

func (c *cli) pin() int {
	lf, err := c.readLockfile()
	if err != nil {
		c.errorf("%v", err)
		return exitLockfile
	}
	names, code, _ := c.selectEntries(lf)
	if code != exitOK {
		return code
	}
	for _, name := range names {
		old := lf.Servers[name]
		surface, err := c.fetchSurface(refFromEntry(old, c.env))
		if err != nil {
			c.errorf("%s: %v", name, err)
			return exitFor(err)
		}
		entry, err := surfacelock.EntryFromSurface(old.Transport, old.Target, old.Args, surface)
		if err != nil {
			c.errorf("%s: %v", name, err)
			return exitTransport
		}
		changed := entry.SurfaceHash != old.SurfaceHash
		lf.Servers[name] = entry
		state := "unchanged"
		if changed {
			state = "repinned"
		}
		fmt.Fprintf(c.stdout, "%s %s: %d tools, era %s, %s\n",
			state, safe(name), len(entry.Tools), safe(entry.Protocol.Era), entry.SurfaceHash)
	}
	if err := c.writeLockfile(lf); err != nil {
		c.errorf("write %s: %v", c.file, err)
		return exitLockfile
	}
	return exitOK
}

// proxy runs the in-band verifying proxy: stdin/stdout are the client-facing
// MCP stdio transport, stderr carries findings, and the upstream (stdio command
// or Streamable HTTP URL) comes from the lockfile entry — the lock is the
// single source of truth for what is being proxied and what it must serve.
func (c *cli) proxy() int {
	lf, err := c.readLockfile()
	if err != nil {
		c.errorf("%v", err)
		return exitLockfile
	}
	name := c.name
	if name == "" {
		if len(lf.Servers) != 1 {
			c.errorf("proxy needs --name when %s has %d entries", c.file, len(lf.Servers))
			return exitUsage
		}
		for n := range lf.Servers {
			name = n
		}
	}
	entry, ok := lf.Servers[name]
	if !ok {
		c.errorf("no entry %q in %s", name, c.file)
		return exitUsage
	}

	// The client owns the session lifecycle (it closes stdin), but it may also
	// just signal us — teardown must still reach the upstream process group.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	out, err := proxy.Run(ctx, proxy.Config{
		Name:        name,
		Entry:       entry,
		Env:         c.env,
		Warn:        c.warn,
		Limits:      surfacelock.DefaultLimits(),
		Findings:    c.stderr,
		ChildStderr: c.stderr,
	}, c.stdin, c.stdout)
	if err != nil {
		c.errorf("%v", err)
		return exitTransport
	}
	// Same precedence as worse(): a session that saw bytes no verdict can be
	// built on outranks a transport failure, which outranks a completed drift
	// verdict — "the surface changed" and "there is no surface to judge" must
	// never be confused by whatever wraps this process.
	code := exitOK
	if out.Drift {
		code = exitDrift
	}
	if out.Transport {
		code = exitTransport
	}
	if out.Inadmissible {
		code = exitInadmissible
	}
	return code
}

// selectEntries resolves --name (or all entries, sorted) against the lockfile.
// On failure the error carries what errorf already reported, for --json callers.
func (c *cli) selectEntries(lf *surfacelock.Lockfile) ([]string, int, error) {
	if c.name != "" {
		if _, ok := lf.Servers[c.name]; !ok {
			err := fmt.Errorf("no entry %q in %s; new servers are lock's job", c.name, c.file)
			c.errorf("%v", err)
			return nil, exitUsage, err
		}
		return []string{c.name}, exitOK, nil
	}
	if len(lf.Servers) == 0 {
		err := fmt.Errorf("%s has no entries", c.file)
		c.errorf("%v", err)
		return nil, exitLockfile, err
	}
	names := make([]string, 0, len(lf.Servers))
	for n := range lf.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, exitOK, nil
}

// compare is verify and diff: fetch live, classify drift, report. verbose=false is
// the CI verb (quiet on success); verbose=true reports per-tool detail either way.
func (c *cli) compare(verbose bool) int {
	verb := "verify"
	if verbose {
		verb = "diff"
	}
	rep := c.newReport(verb)
	lf, err := c.readLockfile()
	if err != nil {
		c.errorf("%v", err)
		return c.fail(rep, exitLockfile, err)
	}
	names, code, selErr := c.selectEntries(lf)
	if code != exitOK {
		return c.fail(rep, code, selErr)
	}
	rep.Servers = make(map[string]*jsonServer, len(names))
	// (Entries were already self-consistency-checked by readLockfile → Validate.)
	// Process every entry; a per-entry failure must NOT early-return, or an entry
	// that already drifted would have its verdict masked by a later entry's transport
	// error. worst tracks the most serious outcome by the precedence in worse().
	worst := exitOK
	drifted := false
	for _, name := range names {
		entry := lf.Servers[name]
		surface, err := c.fetchSurface(refFromEntry(entry, c.env))
		if err != nil {
			c.errorf("%s: %v", name, err)
			code := exitFor(err)
			worst = worse(worst, code)
			rep.Servers[name] = &jsonServer{Outcome: outcomeFor(code), Error: safe(err.Error())}
			continue
		}
		d, err := surfacelock.Diff(entry, surface)
		if err != nil {
			c.errorf("%s: %v", name, err)
			worst = worse(worst, exitTransport)
			rep.Servers[name] = &jsonServer{Outcome: outcomeFor(exitTransport), Error: safe(err.Error())}
			continue
		}
		if d.Empty() {
			n := len(entry.Tools)
			rep.Servers[name] = &jsonServer{Outcome: "ok", Tools: &n, Era: entry.Protocol.Era}
			if verbose && !c.jsonOut {
				fmt.Fprintf(c.stdout, "%s: no drift (%d tools, era %s)\n", safe(name), len(entry.Tools), safe(entry.Protocol.Era))
			}
			continue
		}
		drifted = true
		worst = worse(worst, exitDrift)
		rep.Servers[name] = &jsonServer{Outcome: "drift", Diff: diffToJSON(d)}
		if !c.jsonOut {
			c.reportDrift(name, d, verbose)
		}
	}
	if !c.jsonOut {
		if worst == exitOK && !verbose {
			fmt.Fprintf(c.stdout, "ok: %d server(s), no drift\n", len(names))
		}
		// A hard failure (3/4/5) means the run could not complete, so it must not report
		// "just drift" (exit 1) — but the drift that WAS found is still on stdout.
		if drifted && worst != exitDrift {
			fmt.Fprintf(c.stdout, "note: drift was found, but exit %d reflects a more serious failure above\n", worst)
		}
	}
	return c.finish(rep, worst)
}

// worse returns the more serious of two exit codes for a multi-entry run. A run that
// could not complete (transport/lockfile/inadmissible) outranks a completed drift
// verdict, which outranks success; among hard failures, lockfile corruption and
// inadmissible surfaces (definite, actionable) outrank a transient transport error.
func worse(a, b int) int {
	rank := func(code int) int {
		switch code {
		case exitOK:
			return 0
		case exitDrift:
			return 1
		case exitTransport:
			return 2
		case exitInadmissible:
			return 3
		case exitLockfile:
			return 4
		default:
			return 5
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func (c *cli) reportDrift(name string, d *surfacelock.SurfaceDiff, verbose bool) {
	fmt.Fprintf(c.stdout, "DRIFT %s (severity: %s)\n", safe(name), d.Severity())
	if d.InstructionsChanged {
		fmt.Fprintf(c.stdout, "  [description] server instructions changed\n")
	}
	if d.EraChanged {
		fmt.Fprintf(c.stdout, "  [era] negotiated protocol revision %q -> %q\n", d.OldEra, d.NewEra)
	}
	for _, t := range d.Tools {
		classes := make([]string, 0, len(t.Classes))
		for _, cl := range t.Classes {
			classes = append(classes, cl.String())
		}
		// %q: tool names are hostile input and this line goes to a terminal.
		fmt.Fprintf(c.stdout, "  [%s] tool %q\n", strings.Join(classes, "+"), t.Name)
	}
	if verbose {
		fmt.Fprintf(c.stdout, "  review the change, then accept it explicitly: surfacelock pin --name %q\n", name)
	}
}
