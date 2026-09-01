package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/JsizzleR/surfacelock"
)

// credentialish are the header names whose value is a secret in the shapes
// people actually send. A LITERAL --header puts its value in argv, where every
// process on the box can read it for as long as the proxy runs — and a proxy
// spawned from an MCP client config runs for the whole session. Naming one of
// these on --header is not refused (a CI runner with a private argv is a
// legitimate caller and an escape hatch that does not exist gets worked around),
// but it says so once, on stderr, and names the flag that does not have the
// problem.
// KEYED THE WAY canonicalName FOLDS, and gated by a test that checks the
// lookup fires: a set whose keys are spelled in a different case than the
// lookup produces matches nothing at all, and an advisory that never prints
// looks exactly like an advisory nobody needed (the searches-that-match-nothing
// class — the first draft of this map was spelled "Authorization" and warned on
// nothing).
var credentialish = map[string]bool{
	"AUTHORIZATION":       true,
	"PROXY-AUTHORIZATION": true,
	"COOKIE":              true,
	"X-API-KEY":           true,
	"X-AUTH-TOKEN":        true,
}

// parseHeaders builds the static header set from the two flag spellings.
//
// --header      NAME:VALUE   the value literally, from argv
// --header-env  NAME:ENVVAR  the value from the environment, so it is never in argv
//
// Both split on the FIRST colon, because a header value may contain colons
// (`Authorization: Bearer x:y` is well-formed) and an ENVVAR name may not.
// Duplicate names across either flag are refused rather than last-wins: two
// spellings of one credential is a mistake whose quiet resolution is a request
// the operator did not write.
func parseHeaders(literal, fromEnv []string) (surfacelock.Headers, []string, error) {
	h := surfacelock.Headers{}
	var warnings []string
	seen := map[string]string{} // canonical name -> the flag that set it

	add := func(flag, name, value string) error {
		name = strings.TrimSpace(name)
		canon := canonicalName(name)
		if prev, dup := seen[canon]; dup {
			return fmt.Errorf("%s: header %q is set twice (already set by %s)", flag, name, prev)
		}
		seen[canon] = flag
		h[name] = value
		return nil
	}

	for _, s := range literal {
		name, value, ok := strings.Cut(s, ":")
		if !ok {
			// THE OPERAND IS NOT ECHOED. The commonest way to get here is
			// `--header 'Authorization Bearer sk-live-…'` — the colon left out
			// — so the malformed argument IS the credential, and stderr is a
			// different audience from argv: CI logs are archived and shared.
			// Print the SHAPE.
			return nil, nil, fmt.Errorf("--header: want NAME:VALUE (one colon; the value may contain colons)")
		}
		value = strings.TrimSpace(value)
		if err := add("--header", name, value); err != nil {
			return nil, nil, err
		}
		if credentialish[canonicalName(strings.TrimSpace(name))] {
			warnings = append(warnings, fmt.Sprintf(
				"--header %s puts its value in this process's argv, where any local process can read it; --header-env %s:VAR reads it from the environment instead",
				strings.TrimSpace(name), strings.TrimSpace(name)))
		}
	}

	for _, s := range fromEnv {
		name, varName, ok := strings.Cut(s, ":")
		if !ok {
			return nil, nil, fmt.Errorf("--header-env: want NAME:ENVVAR (one colon)")
		}
		varName = strings.TrimSpace(varName)
		if varName == "" {
			return nil, nil, fmt.Errorf("--header-env %s: no environment variable named", strings.TrimSpace(name))
		}
		// Refuse an unset or empty variable rather than sending an empty header.
		// An empty credential is refused upstream as a 401, which is reported as
		// a transport failure — a true statement about the wrong cause. The
		// VALUE is never echoed, here or anywhere: only the variable's name.
		value, present := os.LookupEnv(varName)
		if !present {
			return nil, nil, fmt.Errorf("--header-env %s: $%s is not set", strings.TrimSpace(name), varName)
		}
		if value == "" {
			return nil, nil, fmt.Errorf("--header-env %s: $%s is empty", strings.TrimSpace(name), varName)
		}
		if err := add("--header-env", name, value); err != nil {
			return nil, nil, err
		}
	}

	if err := h.Validate(); err != nil {
		return nil, nil, err
	}
	return h, warnings, nil
}

// canonicalName folds a field name for the duplicate check the way HTTP does:
// field names are case-insensitive, so "authorization" and "Authorization" are
// one header and setting both is the duplicate this refuses.
func canonicalName(s string) string { return strings.ToUpper(s) }

// reflectionMinLen is the shortest header value this guard will look for. It is
// a THRESHOLD, not a proof: below it, false positives dominate — `X-Env: prod`
// would refuse any surface whose description happens to contain "prod" — and a
// value that short is not a credential worth this refusal. Stated rather than
// tuned silently, because it is the guard's stated bound.
const reflectionMinLen = 8

// refuseReflectedCredential refuses to WRITE a lockfile whose bytes contain a
// value this process was given as a request header.
//
// MEASURED, not predicted: a server that echoes what it was sent — into
// `instructions`, or into a tool's description — gets those bytes recorded
// verbatim, because a lockfile's whole job is to record the surface it was
// served. With `Authorization: Bearer SECRET-abc`, `instructions` came back
// "you are authenticated as Bearer SECRET-abc" and the rendered artifact
// carried it. That is a credential in a file people commit.
//
// It is a REFUSAL rather than a redaction: redacting would write an artifact
// whose surface_hash no longer describes what the server served, which is the
// one thing the format may never do. The remedy an operator needs is to stop
// trusting that server, and this says so.
//
// A benign echo is possible and this refuses it too. That is the safe
// direction: the cost of a false refusal is one message, and the cost of a
// false pass is a secret in version control forever.
func (c *cli) refuseReflectedCredential(rendered []byte) error {
	doc := string(rendered)
	for _, name := range sortedKeys(c.headers) {
		v := c.headers[name]
		if len(v) < reflectionMinLen {
			continue
		}
		if strings.Contains(doc, v) {
			// The value is NOT echoed — naming the header is enough to act on,
			// and this message goes to the same stderr and CI logs everything
			// else in this file refuses to leak into.
			return fmt.Errorf("refusing to write %s: the server's own surface contains the value of the %s header this run sent it — "+
				"a server that reflects your credential into its tool surface would put it in a file you commit", c.file, name)
		}
	}
	return nil
}

func sortedKeys(h surfacelock.Headers) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
