package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeJSONReport asserts stdout is EXACTLY one JSON document (the CLI-JSON.md
// guarantee: no human output interleaved) and returns it decoded into a map so
// tests see the wire shape, not the Go structs that produced it.
func decodeJSONReport(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout carries more than one JSON document:\n%s", stdout)
	}
	if rest := strings.TrimSpace(stdout[int(dec.InputOffset()):]); rest != "" {
		t.Fatalf("trailing non-JSON bytes on stdout: %q", rest)
	}
	return doc
}

func reportServer(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	servers, ok := doc["servers"].(map[string]any)
	if !ok {
		t.Fatalf("no servers object in report: %v", doc)
	}
	s, ok := servers[name].(map[string]any)
	if !ok {
		t.Fatalf("no server %q in report: %v", name, doc)
	}
	return s
}

// TestJSONLifecycle drives lock → verify(ok) → drift(verify+diff) through --json
// and checks the CLI-JSON.md shape at each step, including that exit inside the
// document always equals the process exit code.
func TestJSONLifecycle(t *testing.T) {
	m := &mutableMCP{}
	m.set(toolV1, "be nice")
	srv := httptest.NewServer(http.HandlerFunc(m.handler))
	defer srv.Close()
	lockPath := filepath.Join(t.TempDir(), "tools.lock")

	code, stdout, _ := runCLI(t, "lock", "--json", "--file", lockPath, "--name", "mut", "--url", srv.URL)
	if code != exitOK {
		t.Fatalf("lock --json: exit %d", code)
	}
	doc := decodeJSONReport(t, stdout)
	if doc["surfacelock_json"] != float64(1) || doc["verb"] != "lock" || doc["exit"] != float64(exitOK) {
		t.Fatalf("lock report header wrong: %v", doc)
	}
	if doc["name"] != "mut" || doc["tools"] != float64(1) || doc["era"] != "2025-11-25" {
		t.Fatalf("lock report body wrong: %v", doc)
	}
	hash, _ := doc["surface_hash"].(string)
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("lock report surface_hash %q", hash)
	}

	code, stdout, _ = runCLI(t, "verify", "--json", "--file", lockPath)
	if code != exitOK {
		t.Fatalf("verify --json clean: exit %d", code)
	}
	doc = decodeJSONReport(t, stdout)
	if doc["verb"] != "verify" || doc["exit"] != float64(exitOK) {
		t.Fatalf("verify report header wrong: %v", doc)
	}
	s := reportServer(t, doc, "mut")
	if s["outcome"] != "ok" || s["tools"] != float64(1) || s["era"] != "2025-11-25" {
		t.Fatalf("clean server object wrong: %v", s)
	}
	if _, hasDiff := s["diff"]; hasDiff {
		t.Fatalf("clean server object carries a diff: %v", s)
	}

	m.set(toolV2, "be nice") // description drift: the injection vector
	for _, verb := range []string{"verify", "diff"} {
		code, stdout, _ = runCLI(t, verb, "--json", "--file", lockPath)
		if code != exitDrift {
			t.Fatalf("%s --json drift: exit %d", verb, code)
		}
		doc = decodeJSONReport(t, stdout)
		if doc["exit"] != float64(exitDrift) {
			t.Fatalf("%s report exit field %v != process exit", verb, doc["exit"])
		}
		s = reportServer(t, doc, "mut")
		if s["outcome"] != "drift" {
			t.Fatalf("%s drift outcome wrong: %v", verb, s)
		}
		d, _ := s["diff"].(map[string]any)
		if d == nil || d["severity"] != "description" || d["instructions_changed"] != false {
			t.Fatalf("%s diff object wrong: %v", verb, s)
		}
		if d["old_era"] != "2025-11-25" || d["new_era"] != "2025-11-25" || d["era_changed"] != false {
			t.Fatalf("%s diff eras wrong: %v", verb, d)
		}
		tools, _ := d["tools"].([]any)
		if len(tools) != 1 {
			t.Fatalf("%s diff tools wrong: %v", verb, d)
		}
		td, _ := tools[0].(map[string]any)
		classes, _ := td["classes"].([]any)
		if td["name"] != "greet" || len(classes) == 0 || classes[0] != "description" {
			t.Fatalf("%s tool diff wrong: %v", verb, td)
		}
	}
}

// TestJSONDriftBesideTransportFailure is the D-414/D-418 property on the wire:
// the exit code carries the worst outcome (transport), but the drift that WAS
// found is still fully present in its own server object.
func TestJSONDriftBesideTransportFailure(t *testing.T) {
	m := &mutableMCP{}
	m.set(toolV1, "")
	srv := httptest.NewServer(http.HandlerFunc(m.handler))
	defer srv.Close()
	m2 := &mutableMCP{}
	m2.set(toolV1, "")
	dead := httptest.NewServer(http.HandlerFunc(m2.handler))
	lockPath := filepath.Join(t.TempDir(), "tools.lock")

	if code, _, _ := runCLI(t, "lock", "--file", lockPath, "--name", "drifter", "--url", srv.URL); code != exitOK {
		t.Fatal("lock drifter failed")
	}
	if code, _, _ := runCLI(t, "lock", "--file", lockPath, "--name", "gone", "--url", dead.URL); code != exitOK {
		t.Fatal("lock gone failed")
	}
	m.set(toolV2, "")
	dead.Close() // now unreachable

	code, stdout, _ := runCLI(t, "verify", "--json", "--file", lockPath)
	if code != exitTransport {
		t.Fatalf("exit %d, want %d (transport outranks drift)", code, exitTransport)
	}
	doc := decodeJSONReport(t, stdout)
	if doc["exit"] != float64(exitTransport) {
		t.Fatalf("report exit %v != process exit", doc["exit"])
	}
	drifter := reportServer(t, doc, "drifter")
	if drifter["outcome"] != "drift" || drifter["diff"] == nil {
		t.Fatalf("drift lost beside the transport failure: %v", drifter)
	}
	gone := reportServer(t, doc, "gone")
	errText, _ := gone["error"].(string)
	if gone["outcome"] != "transport" || errText == "" {
		t.Fatalf("transport server object wrong: %v", gone)
	}
}

// TestJSONFailurePathsStillEmitOneDocument: every post-flag-parse exit path in a
// --json run must put exactly one JSON document on stdout, with exit and error set.
func TestJSONFailurePathsStillEmitOneDocument(t *testing.T) {
	m := &mutableMCP{dup: true} // inadmissible surface
	srv := httptest.NewServer(http.HandlerFunc(m.handler))
	defer srv.Close()
	dir := t.TempDir()
	goodLock := filepath.Join(dir, "good.lock")
	m2 := &mutableMCP{}
	m2.set(toolV1, "")
	srv2 := httptest.NewServer(http.HandlerFunc(m2.handler))
	defer srv2.Close()
	if code, _, _ := runCLI(t, "lock", "--file", goodLock, "--name", "mut", "--url", srv2.URL); code != exitOK {
		t.Fatal("setup lock failed")
	}
	corrupt := filepath.Join(dir, "corrupt.lock")
	if err := os.WriteFile(corrupt, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		exit int
	}{
		{"lock inadmissible", []string{"lock", "--json", "--file", filepath.Join(dir, "x.lock"), "--url", srv.URL}, exitInadmissible},
		{"lock no target", []string{"lock", "--json", "--file", goodLock}, exitUsage},
		{"lock existing entry", []string{"lock", "--json", "--file", goodLock, "--name", "mut", "--url", srv2.URL}, exitUsage},
		{"verify corrupt lockfile", []string{"verify", "--json", "--file", corrupt}, exitLockfile},
		{"verify missing lockfile", []string{"verify", "--json", "--file", filepath.Join(dir, "absent.lock")}, exitLockfile},
		{"verify bad --name", []string{"verify", "--json", "--file", goodLock, "--name", "nope"}, exitUsage},
	}
	for _, tc := range cases {
		code, stdout, _ := runCLI(t, tc.args...)
		if code != tc.exit {
			t.Fatalf("%s: exit %d, want %d", tc.name, code, tc.exit)
		}
		doc := decodeJSONReport(t, stdout)
		if doc["exit"] != float64(tc.exit) {
			t.Fatalf("%s: report exit %v != process exit %d", tc.name, doc["exit"], tc.exit)
		}
		errText, _ := doc["error"].(string)
		if errText == "" {
			t.Fatalf("%s: run-level report has no error: %v", tc.name, doc)
		}
	}
}

// TestJSONRefusedOnPinAndProxy: --json on a verb outside the contract fails
// closed (exit 2) rather than silently producing human output.
func TestJSONRefusedOnPinAndProxy(t *testing.T) {
	for _, verb := range []string{"pin", "proxy"} {
		code, stdout, stderr := runCLI(t, verb, "--json", "--file", "does-not-matter.lock")
		if code != exitUsage {
			t.Fatalf("%s --json: exit %d, want %d", verb, code, exitUsage)
		}
		if stdout != "" {
			t.Fatalf("%s --json wrote to stdout: %q", verb, stdout)
		}
		if !strings.Contains(stderr, "not supported") {
			t.Fatalf("%s --json stderr: %q", verb, stderr)
		}
	}
}

// TestJSONNeutralizesHostileErrorText: server-controlled bytes reaching the
// report's error strings must arrive as valid JSON with control characters
// neutralized — a consumer that prints them must not have its terminal rewritten.
func TestJSONNeutralizesHostileErrorText(t *testing.T) {
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-1,"message":"boom \\u001b[2J\\u0007 wiped"}}`, req.ID)
	}))
	defer hostile.Close()

	code, stdout, _ := runCLI(t, "lock", "--json", "--file", filepath.Join(t.TempDir(), "x.lock"), "--url", hostile.URL)
	if code != exitTransport {
		t.Fatalf("exit %d, want %d", code, exitTransport)
	}
	doc := decodeJSONReport(t, stdout)
	errText, _ := doc["error"].(string)
	if errText == "" {
		t.Fatalf("no error in report: %v", doc)
	}
	for _, r := range errText {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("raw control rune %q survived into the report error: %q", r, errText)
		}
	}
}

// failWriter fails after n bytes — a closed pipe mid-report.
type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, fmt.Errorf("broken pipe")
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, fmt.Errorf("broken pipe")
	}
	w.n -= len(p)
	return len(p), nil
}

// TestJSONWriteFailureEscalatesExit: a report that could not be delivered must
// not exit with a consumable verdict — exit 0 plus empty stdout would read as
// "clean". Verified for the clean case (0 → 3) and the drift case (1 → 3):
// worse() precedence, not a blanket overwrite.
func TestJSONWriteFailureEscalatesExit(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{exitOK, exitTransport},
		{exitDrift, exitTransport},
		{exitLockfile, exitLockfile}, // already worse than transport: unchanged
	} {
		var stderr strings.Builder
		c := &cli{jsonOut: true, stdout: &failWriter{}, stderr: &stderr}
		got := c.finish(c.newReport("verify"), tc.in)
		if got != tc.want {
			t.Fatalf("finish(%d) with failing stdout = %d, want %d", tc.in, got, tc.want)
		}
		if !strings.Contains(stderr.String(), "write --json report") {
			t.Fatalf("no diagnostic on stderr: %q", stderr.String())
		}
	}
	// Control (D-431 lesson: a leg asserting a guard did NOT fire needs proof it
	// WAS armed): the same call with a working writer keeps its exit code.
	var out, stderr strings.Builder
	c := &cli{jsonOut: true, stdout: &out, stderr: &stderr}
	if got := c.finish(c.newReport("verify"), exitOK); got != exitOK {
		t.Fatalf("finish with working stdout = %d, want 0", got)
	}
	if out.Len() == 0 {
		t.Fatal("working writer received no report")
	}
}
