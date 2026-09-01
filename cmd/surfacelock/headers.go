package main

import (
	"fmt"
	"os"
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
			return nil, nil, fmt.Errorf("--header %q: want NAME:VALUE", s)
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
			return nil, nil, fmt.Errorf("--header-env %q: want NAME:ENVVAR", s)
		}
		varName = strings.TrimSpace(varName)
		if varName == "" {
			return nil, nil, fmt.Errorf("--header-env %q: no environment variable named", s)
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
