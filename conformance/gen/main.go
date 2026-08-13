// Command gen produces the era-conformance matrix: it probes the targets in a
// targets.tsv, retains every capture verbatim under -captures, and renders
// matrix.tsv + matrix.md from the captures. With -regrade it skips probing and
// re-grades the retained captures alone — the artifact is re-derivable from
// the data, never hand-written.
//
// targets.tsv columns (tab-separated, # comments, "-" = empty):
//
//	name  kind(http|stdio)  era  address  [env]  [auth_env]
//
// address is a URL for http, a space-split argv for stdio. env is a ||-split
// list of K=V pairs for a stdio child (the corpus's dummy-credential idiom: a
// value that lets a server START; no call that would use it is ever made).
// auth_env names an environment variable holding a bearer token (the token
// itself never enters the repo); empty means unauthenticated.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/JsizzleR/surfacelock/conformance"
)

func main() {
	targets := flag.String("targets", "conformance/targets.tsv", "targets file")
	captures := flag.String("captures", "conformance/captures", "capture directory")
	out := flag.String("out", "conformance", "output directory for matrix.tsv/matrix.md")
	regrade := flag.Bool("regrade", false, "re-grade retained captures without probing")
	only := flag.String("only", "", "probe only the target with this name")
	budget := flag.Duration("budget", 2*time.Minute, "per-target probe budget")
	flag.Parse()

	if err := run(*targets, *captures, *out, *only, *regrade, *budget); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

type target struct {
	name, kind, era, address, authEnv string
	env                               []string
}

func run(targetsPath, capturesDir, outDir, only string, regrade bool, budget time.Duration) error {
	if !regrade {
		rows, err := readTargets(targetsPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(capturesDir, 0o755); err != nil {
			return err
		}
		for _, t := range rows {
			if only != "" && t.name != only {
				continue
			}
			if err := probeOne(t, capturesDir, budget); err != nil {
				// A probe failure is recorded, never silently skipped: the
				// capture file carries the error and grades UNGRADED.
				fmt.Fprintf(os.Stderr, "gen: %s@%s: %v (recorded)\n", t.name, t.era, err)
			}
		}
	}
	return render(capturesDir, outDir)
}

func readTargets(path string) ([]target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []target
	for ln, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			return nil, fmt.Errorf("%s:%d: want >=4 tab-separated fields, got %d", path, ln+1, len(f))
		}
		t := target{name: f[0], kind: f[1], era: f[2], address: f[3]}
		if len(f) > 4 && f[4] != "-" && f[4] != "" {
			t.env = strings.Split(f[4], "||")
		}
		if len(f) > 5 && f[5] != "-" {
			t.authEnv = strings.TrimSpace(f[5])
		}
		if t.kind != "http" && t.kind != "stdio" {
			return nil, fmt.Errorf("%s:%d: kind %q", path, ln+1, t.kind)
		}
		out = append(out, t)
	}
	return out, nil
}

func probeOne(t target, capturesDir string, budget time.Duration) error {
	var dial conformance.Dialer
	switch t.kind {
	case "http":
		var static map[string]string
		if t.authEnv != "" {
			tok := os.Getenv(t.authEnv)
			if tok == "" {
				return fmt.Errorf("auth env %s is empty", t.authEnv)
			}
			static = map[string]string{"Authorization": "Bearer " + tok}
		}
		dial = conformance.NewHTTPDialer(t.address, nil, static)
	case "stdio":
		dial = conformance.NewStdioDialer(strings.Fields(t.address), t.env)
	}
	fmt.Printf("probing %s (%s, era %s)...\n", t.name, t.kind, t.era)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cap, err := conformance.Probe(ctx, t.name, dial, t.era)
	if err != nil {
		// Even a dial-failed run leaves a capture, so the matrix shows the
		// target as UNGRADED with its reason instead of omitting it.
		cap = &conformance.Capture{Target: t.name, Kind: t.kind, Era: t.era,
			Notes: []string{"probe failed: " + err.Error()}}
	}
	cap.TakenAt = time.Now().UTC().Format(time.RFC3339)
	return writeCapture(capturesDir, cap)
}

func captureFile(dir, targetName, era string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, targetName)
	return filepath.Join(dir, fmt.Sprintf("%s@%s.json", safe, era))
}

func writeCapture(dir string, cap *conformance.Capture) error {
	b, err := json.MarshalIndent(cap, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(captureFile(dir, cap.Target, cap.Era), append(b, '\n'), 0o644)
}

func render(capturesDir, outDir string) error {
	entries, err := os.ReadDir(capturesDir)
	if err != nil {
		return err
	}
	var reports []*conformance.Report
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(capturesDir, e.Name()))
		if err != nil {
			return err
		}
		var cap conformance.Capture
		if err := json.Unmarshal(raw, &cap); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		reports = append(reports, conformance.Grade(&cap))
		names = append(names, e.Name())
	}
	if len(reports) == 0 {
		return fmt.Errorf("no captures under %s", capturesDir)
	}
	sort.Strings(names)
	if err := os.WriteFile(filepath.Join(outDir, "matrix.tsv"), []byte(conformance.RenderMatrixTSV(reports)), 0o644); err != nil {
		return err
	}
	md := conformance.RenderMatrixMD(reports) +
		fmt.Sprintf("\n---\nGraded from %d capture(s): %s\n", len(names), strings.Join(names, ", "))
	if err := os.WriteFile(filepath.Join(outDir, "matrix.md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Printf("matrix rendered from %d captures -> %s\n", len(reports), outDir)
	return nil
}
