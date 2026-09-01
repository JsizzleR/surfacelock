package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JsizzleR/surfacelock"
)

func TestParseHeadersLiteral(t *testing.T) {
	h, warn, err := parseHeaders([]string{"X-A: v", "X-B:v2"}, nil)
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if h["X-A"] != "v" || h["X-B"] != "v2" {
		t.Fatalf("parsed %v", h)
	}
	if len(warn) != 0 {
		t.Fatalf("non-credential names warned: %v", warn)
	}
}

func TestParseHeadersSplitsOnTheFirstColonOnly(t *testing.T) {
	// A header value may contain colons — `Bearer a:b` and any URL do.
	h, _, err := parseHeaders([]string{"Authorization: Bearer a:b:c"}, nil)
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if got := h["Authorization"]; got != "Bearer a:b:c" {
		t.Fatalf("Authorization = %q, want the whole value past the first colon", got)
	}
}

func TestParseHeadersEnvKeepsTheValueOutOfArgv(t *testing.T) {
	t.Setenv("DEMO_TOKEN", "tok-123")
	h, warn, err := parseHeaders(nil, []string{"Authorization: DEMO_TOKEN"})
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if h["Authorization"] != "tok-123" {
		t.Fatalf("Authorization = %q, want the environment's value", h["Authorization"])
	}
	// The whole point of the flag: no warning, because nothing secret is in argv.
	if len(warn) != 0 {
		t.Fatalf("--header-env warned about argv exposure: %v", warn)
	}
}

func TestParseHeadersEnvRefusesUnsetAndEmpty(t *testing.T) {
	// An empty credential is refused UPSTREAM as a 401, which the proxy reports
	// as a transport failure — a true sentence about the wrong cause. Refusing
	// here is what makes the operator's error name their own input.
	if _, _, err := parseHeaders(nil, []string{"Authorization: DEFINITELY_NOT_SET_12345"}); err == nil {
		t.Fatal("an unset variable was admitted")
	} else if !strings.Contains(err.Error(), "not set") {
		t.Fatalf("error = %v, want one naming the unset variable", err)
	}
	t.Setenv("EMPTY_TOKEN", "")
	if _, _, err := parseHeaders(nil, []string{"Authorization: EMPTY_TOKEN"}); err == nil {
		t.Fatal("an empty variable was admitted")
	} else if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v, want one naming the empty variable", err)
	}
}

func TestParseHeadersNeverEchoesTheSecret(t *testing.T) {
	// Every error this function can return reaches a terminal and often a CI
	// log. None of them may carry the value.
	t.Setenv("DEMO_TOKEN", "tok-123")
	for _, args := range [][2][]string{
		{{"Authorization: tok-123"}, {"Authorization: DEMO_TOKEN"}}, // duplicate across the two flags
		{{"Authorization: tok-123", "authorization: tok-123"}, nil}, // duplicate within one
		{{"Bad Name: tok-123"}, nil},                                // invalid name
		{{"Authorization: tok-\r\n123"}, nil},                       // injection
	} {
		_, _, err := parseHeaders(args[0], args[1])
		if err == nil {
			t.Fatalf("parseHeaders(%v, %v) was admitted", args[0], args[1])
		}
		if strings.Contains(err.Error(), "tok-123") {
			t.Fatalf("the error echoed the secret: %v", err)
		}
	}
}

func TestParseHeadersRefusesDuplicatesCaseInsensitively(t *testing.T) {
	// HTTP field names are case-insensitive, so these are ONE header and
	// last-wins would silently pick a credential the operator did not choose.
	if _, _, err := parseHeaders([]string{"Authorization: a", "AUTHORIZATION: b"}, nil); err == nil {
		t.Fatal("a case-variant duplicate was admitted")
	}
	t.Setenv("T", "x")
	if _, _, err := parseHeaders([]string{"Authorization: a"}, []string{"authorization: T"}); err == nil {
		t.Fatal("a duplicate across --header and --header-env was admitted")
	}
}

func TestParseHeadersWarnsWhenACredentialGoesIntoArgv(t *testing.T) {
	for _, name := range []string{"Authorization", "authorization", "Cookie", "X-Api-Key", "Proxy-Authorization", "X-Auth-Token"} {
		_, warn, err := parseHeaders([]string{name + ": v"}, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(warn) != 1 {
			t.Errorf("%s produced %d warnings, want 1", name, len(warn))
		} else if !strings.Contains(warn[0], "--header-env") {
			t.Errorf("%s warning does not name the remedy: %s", name, warn[0])
		}
		if strings.Contains(strings.Join(warn, " "), ": v") {
			t.Errorf("%s warning echoed the value: %s", name, warn[0])
		}
	}
}

func TestParseHeadersRefusesMalformedSpellings(t *testing.T) {
	for _, tc := range []struct{ name, arg string }{
		{"no colon", "Authorization Bearer x"},
		{"empty name", ": v"},
	} {
		if _, _, err := parseHeaders([]string{tc.arg}, nil); err == nil {
			t.Errorf("%s: %q was admitted", tc.name, tc.arg)
		}
	}
	if _, _, err := parseHeaders(nil, []string{"Authorization:"}); err == nil {
		t.Error("--header-env with no variable named was admitted")
	}
	if _, _, err := parseHeaders(nil, []string{"no colon"}); err == nil {
		t.Error("--header-env with no colon was admitted")
	}
}

func TestParseHeadersValidatesThroughTheLibrary(t *testing.T) {
	// The CLI must not have a second, weaker opinion about what is admissible:
	// the same Validate the transports call is what refuses here.
	var h surfacelock.Headers = surfacelock.Headers{"X-A": "a\x1bb"}
	if h.Validate() == nil {
		t.Fatal("precondition: the library admits an ESC value")
	}
	if _, _, err := parseHeaders([]string{"X-A: a\x1bb"}, nil); err == nil {
		t.Fatal("the CLI admitted what the library refuses")
	}
}

// --- the refusals that keep a credential from being silently dropped ---

func TestCLIRefusesHeadersOnAStdioTarget(t *testing.T) {
	// Ignoring them would send nothing and say nothing; on `lock` the artifact
	// would be taken without the credential and look fine.
	code, _, stderr := runCLI(t, "lock", "--header", "Authorization: Bearer t",
		"--file", t.TempDir()+"/tools.lock", "--name", "s", "--", "/bin/echo")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(stderr, "--env") {
		t.Fatalf("stderr does not name the stdio spelling: %s", stderr)
	}
	if strings.Contains(stderr, "Bearer t") {
		t.Fatalf("the refusal echoed the credential: %s", stderr)
	}
}

func TestCLIRefusesHeadersAgainstAStdioLockEntry(t *testing.T) {
	// The proxy verb takes its transport from the ENTRY, so this is the only
	// place the mismatch can be caught for it. The entry is produced by `lock`
	// and then RETARGETED to stdio, so it is a genuinely valid lockfile: a
	// hand-written one is refused by lockfile validation first, which would
	// make this leg green for the wrong reason.
	srv := &mutableMCP{}
	srv.set(toolV1, "be helpful")
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	lock := dir + "/tools.lock"
	if code, _, stderr := runCLI(t, "lock", "--url", ts.URL, "--name", "s", "--file", lock); code != exitOK {
		t.Fatalf("fixture lock: exit %d: %s", code, stderr)
	}
	b, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	entry := doc["servers"].(map[string]any)["s"].(map[string]any)
	entry["transport"] = "stdio"
	entry["target"] = "/bin/echo"
	entry["args"] = []any{}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, out, 0o600); err != nil {
		t.Fatal(err)
	}
	// Precondition: the retargeted file is still a VALID lockfile, so a usage
	// refusal below is about the transport and not about the artifact.
	if code, _, stderr := runCLI(t, "verify", "--file", lock, "--name", "s"); code == exitLockfile {
		t.Fatalf("the retargeted fixture is not a valid lockfile: %s", stderr)
	}

	for _, verb := range []string{"proxy", "verify", "pin"} {
		code, _, stderr := runCLI(t, verb, "--header", "X-Api-Key: secret-v", "--file", lock, "--name", "s")
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d (usage)", verb, code, exitUsage)
		}
		if !strings.Contains(stderr, "stdio") {
			t.Errorf("%s: stderr does not name the entry's transport: %s", verb, stderr)
		}
		if strings.Contains(stderr, "secret-v") {
			t.Errorf("%s: the refusal echoed the credential: %s", verb, stderr)
		}
	}
}

func TestCLIUnsetHeaderEnvIsAUsageErrorNotATransportFailure(t *testing.T) {
	// The failure mode this prevents: an unset variable sends an absent
	// credential, the upstream answers 401, and the operator is told their
	// SERVER is unreachable.
	code, _, stderr := runCLI(t, "lock", "--header-env", "Authorization: NOT_SET_98765",
		"--url", "http://127.0.0.1:1/mcp", "--name", "s", "--file", t.TempDir()+"/tools.lock")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (usage, not a transport failure)", code, exitUsage)
	}
	if !strings.Contains(stderr, "NOT_SET_98765") {
		t.Fatalf("stderr does not name the variable: %s", stderr)
	}
}

// TestCLILockOverATokenGatedServer is the end-to-end positive control: with the
// credential the lock succeeds, and WITHOUT it the same server refuses. Without
// the second half the first proves nothing — a server that admitted everything
// would pass it.
func TestCLILockOverATokenGatedServer(t *testing.T) {
	srv := &mutableMCP{}
	srv.set(toolV1, "be helpful")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		srv.handler(w, r)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()

	t.Setenv("DEMO_TOKEN", "Bearer tok")
	code, _, stderr := runCLI(t, "lock", "--header-env", "Authorization: DEMO_TOKEN",
		"--url", ts.URL, "--name", "gated", "--file", dir+"/ok.lock")
	if code != exitOK {
		t.Fatalf("lock with the credential: exit %d: %s", code, stderr)
	}
	b, err := os.ReadFile(dir + "/ok.lock")
	if err != nil {
		t.Fatal(err)
	}
	// The artifact must not carry the credential that fetched it.
	for _, needle := range []string{"Bearer tok", "DEMO_TOKEN", "Authorization"} {
		if strings.Contains(string(b), needle) {
			t.Fatalf("the written lockfile carries %q:\n%s", needle, b)
		}
	}

	code, _, stderr = runCLI(t, "lock", "--url", ts.URL, "--name", "gated", "--file", dir+"/no.lock")
	if code == exitOK {
		t.Fatal("lock WITHOUT the credential succeeded — the fixture is not gating anything")
	}
	if !strings.Contains(stderr, "401") {
		t.Fatalf("the uncredentialed refusal does not name the 401: %s", stderr)
	}
}

// runProxyCLI drives the proxy verb the way an MCP client does: stdin stays
// OPEN while the response is read. A driver that pipes one frame and closes
// stdin gets exit 0 and an EMPTY stdout — the proxy shuts down with the client
// — so such a fixture is green over every defect this file tests.
func runProxyCLI(t *testing.T, frame string, args ...string) (int, string, string) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var stderr bytes.Buffer
	codeCh := make(chan int, 1)
	go func() { codeCh <- run(args, inR, outW, &stderr); outW.Close() }()

	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	io.WriteString(inW, frame+"\n")
	var first string
	select {
	case l, ok := <-lines:
		if ok {
			first = l
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the proxy to answer the client")
	}
	inW.Close() // only now: the client is done
	select {
	case code := <-codeCh:
		return code, first, stderr.String()
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the proxy to exit")
		return 0, "", ""
	}
}

// TestCLIProxyOverATokenGatedServer is the leg Act 5 actually runs: the
// standalone proxy on the client path, in front of a route that requires a
// credential. Both halves are needed — without the negative half a proxy that
// forwarded everything unconditionally would pass, and without the positive
// half a proxy that refused everything would.
func TestCLIProxyOverATokenGatedServer(t *testing.T) {
	srv := &mutableMCP{}
	srv.set(toolV1, "be helpful")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		srv.handler(w, r)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	lock := dir + "/tools.lock"

	t.Setenv("DEMO_TOKEN", "Bearer tok")
	if code, _, stderr := runCLI(t, "lock", "--header-env", "Authorization: DEMO_TOKEN",
		"--url", ts.URL, "--name", "gated", "--file", lock); code != exitOK {
		t.Fatalf("fixture lock: exit %d: %s", code, stderr)
	}

	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`

	// WITH the credential: the handshake reaches the client as a result.
	code, line, stderr := runProxyCLI(t, init, "proxy", "--file", lock, "--name", "gated",
		"--header-env", "Authorization: DEMO_TOKEN")
	if code != exitOK {
		t.Fatalf("credentialed proxy: exit %d\n%s", code, stderr)
	}
	if !strings.Contains(line, `"result"`) || strings.Contains(line, `"error"`) {
		t.Fatalf("credentialed proxy did not forward the handshake: %s\n%s", line, stderr)
	}
	if strings.Contains(stderr, "Bearer tok") {
		t.Fatalf("the proxy's own diagnostics echoed the credential:\n%s", stderr)
	}

	// WITHOUT it: an honest TRANSPORT failure, never a drift verdict — the
	// distinction the whole refusal contract rests on.
	code, line, stderr = runProxyCLI(t, init, "proxy", "--file", lock, "--name", "gated")
	if code == exitOK {
		t.Fatal("uncredentialed proxy succeeded — the fixture is not gating anything")
	}
	if !strings.Contains(line, "401") {
		t.Fatalf("the client was not told about the 401: %s", line)
	}
	// Asserted on the session's own verdict, not on the word "drift" appearing:
	// the refusal message says "not drift" and a substring test on the word is
	// satisfied by the very sentence that makes the distinction.
	if !strings.Contains(line, "transport failure") {
		t.Fatalf("the refusal does not name itself a transport failure: %s", line)
	}
	if !strings.Contains(stderr, "drift=false") || !strings.Contains(stderr, "transport=true") {
		t.Fatalf("the session outcome does not read transport-only:\n%s", stderr)
	}
}
