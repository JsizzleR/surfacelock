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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/JsizzleR/surfacelock"
	"github.com/JsizzleR/surfacelock/client"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage: surfacelock <command> [flags] [target]

commands:
  lock    capture a server's tool surface into the lockfile (new entry only)
  verify  re-fetch every entry (or --name one) and fail on drift   [CI verb]
  diff    like verify, but report per-tool, severity-classified
  pin     re-fetch and rewrite an existing entry (explicit re-lock)

target (lock only):
  --url URL            Streamable HTTP endpoint
  -- CMD [ARGS...]     stdio server command

flags:
  --file PATH    lockfile path (default tools.lock)
  --name NAME    entry name (default: URL host / command basename; lock, or one entry)
  --timeout D    per-server fetch budget (default 60s)
  --offer V      protocolVersion to offer at initialize (lock only; default ` + client.DefaultOfferedVersion + `)
  --env K=V      extra environment for stdio servers (repeatable; never recorded)

exit codes: 0 ok · 1 drift · 2 usage · 3 transport/protocol · 4 lockfile · 5 inadmissible surface`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cmd := args[0]
	switch cmd {
	case "lock", "verify", "diff", "pin":
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
	var env multiFlag
	fs.Var(&env, "env", "extra KEY=VAL for stdio servers (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}

	c := &cli{stdout: stdout, stderr: stderr, file: *file, name: *name,
		timeout: *timeout, offer: *offer, url: *urlFlag, env: env, argv: fs.Args()}

	switch cmd {
	case "lock":
		return c.lock()
	case "verify":
		return c.compare(false)
	case "diff":
		return c.compare(true)
	case "pin":
		return c.pin()
	}
	return exitUsage
}

type cli struct {
	stdout, stderr io.Writer
	file, name     string
	timeout        time.Duration
	offer          string
	url            string
	env            []string
	argv           []string
}

func (c *cli) errorf(format string, args ...any) {
	fmt.Fprintf(c.stderr, "surfacelock: "+format+"\n", args...)
}

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
		Env: env, Offered: e.Protocol.Offered}
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
	return surfacelock.Parse(b)
}

func (c *cli) writeLockfile(lf *surfacelock.Lockfile) error {
	b, err := lf.Render()
	if err != nil {
		return err
	}
	return os.WriteFile(c.file, b, 0o644)
}

func (c *cli) lock() int {
	ref, defaultName, err := c.targetRef()
	if err != nil {
		c.errorf("%v", err)
		return exitUsage
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
		return exitLockfile
	}
	if _, exists := lf.Servers[name]; exists {
		c.errorf("entry %q already exists in %s; accepting a changed surface is pin's job", name, c.file)
		return exitUsage
	}

	surface, err := c.fetchSurface(ref)
	if err != nil {
		c.errorf("%v", err)
		return exitFor(err)
	}
	entry, err := surfacelock.EntryFromSurface(ref.Transport, ref.Target, ref.Args, surface)
	if err != nil {
		c.errorf("%v", err)
		return exitTransport
	}
	lf.Servers[name] = entry
	if err := c.writeLockfile(lf); err != nil {
		c.errorf("write %s: %v", c.file, err)
		return exitLockfile
	}
	fmt.Fprintf(c.stdout, "locked %s: %d tools, era %s, %s\n",
		name, len(entry.Tools), entry.Protocol.Era, entry.SurfaceHash)
	return exitOK
}

func (c *cli) pin() int {
	lf, err := c.readLockfile()
	if err != nil {
		c.errorf("%v", err)
		return exitLockfile
	}
	names, code := c.selectEntries(lf)
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
			state, name, len(entry.Tools), entry.Protocol.Era, entry.SurfaceHash)
	}
	if err := c.writeLockfile(lf); err != nil {
		c.errorf("write %s: %v", c.file, err)
		return exitLockfile
	}
	return exitOK
}

// selectEntries resolves --name (or all entries, sorted) against the lockfile.
func (c *cli) selectEntries(lf *surfacelock.Lockfile) ([]string, int) {
	if c.name != "" {
		if _, ok := lf.Servers[c.name]; !ok {
			c.errorf("no entry %q in %s; new servers are lock's job", c.name, c.file)
			return nil, exitUsage
		}
		return []string{c.name}, exitOK
	}
	if len(lf.Servers) == 0 {
		c.errorf("%s has no entries", c.file)
		return nil, exitLockfile
	}
	names := make([]string, 0, len(lf.Servers))
	for n := range lf.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, exitOK
}

// compare is verify and diff: fetch live, classify drift, report. verbose=false is
// the CI verb (quiet on success); verbose=true reports per-tool detail either way.
func (c *cli) compare(verbose bool) int {
	lf, err := c.readLockfile()
	if err != nil {
		c.errorf("%v", err)
		return exitLockfile
	}
	names, code := c.selectEntries(lf)
	if code != exitOK {
		return code
	}
	worst := exitOK
	for _, name := range names {
		entry := lf.Servers[name]
		// A lockfile whose hashes disagree with its own content must not produce a
		// drift verdict: that is corruption, not change (SPEC.md §7).
		if err := entry.Validate(); err != nil {
			c.errorf("%s: %v", name, err)
			return exitLockfile
		}
		surface, err := c.fetchSurface(refFromEntry(entry, c.env))
		if err != nil {
			c.errorf("%s: %v", name, err)
			return exitFor(err)
		}
		d, err := surfacelock.Diff(entry, surface)
		if err != nil {
			c.errorf("%s: %v", name, err)
			return exitTransport
		}
		if d.Empty() {
			if verbose {
				fmt.Fprintf(c.stdout, "%s: no drift (%d tools, era %s)\n", name, len(entry.Tools), entry.Protocol.Era)
			}
			continue
		}
		worst = exitDrift
		c.reportDrift(name, d, verbose)
	}
	if worst == exitOK && !verbose {
		fmt.Fprintf(c.stdout, "ok: %d server(s), no drift\n", len(names))
	}
	return worst
}

func (c *cli) reportDrift(name string, d *surfacelock.SurfaceDiff, verbose bool) {
	fmt.Fprintf(c.stdout, "DRIFT %s (severity: %s)\n", name, d.Severity())
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
