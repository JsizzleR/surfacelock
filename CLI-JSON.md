# surfacelock `--json` — machine-readable CLI output, version 1

**Status: pre-release, like everything here — but this document is the contract the
Python bindings (and any other machine consumer) parse. The human output is not a
contract and may change freely; this shape may not.**

This is a CLI output contract, not part of the `tools.lock` format: SPEC.md owns the
artifact and the exit codes; this document owns what `--json` writes to stdout.

## Scope

`--json` is accepted by `lock`, `verify`, and `diff`. It is refused (exit 2) by `pin`
and `proxy`: `pin`'s review artifact is the lockfile's VCS diff, and `proxy`'s stdout
is an MCP transport. Exit codes are unchanged by `--json` — they remain the SPEC.md §9
contract:

| code | meaning |
|---|---|
| 0 | success; `verify`/`diff`: no drift |
| 1 | drift |
| 2 | usage error |
| 3 | transport or protocol failure |
| 4 | lockfile error |
| 5 | inadmissible surface |

## Guarantees

- When the flag set parsed successfully and `--json` was given, stdout carries
  **exactly one JSON document** (two-space indented, one trailing newline) and nothing
  else, on **every** exit path. Human diagnostics still go to stderr.
  The one exception is a flag-parse failure itself (exit 2, nothing on stdout): the
  process could not have known `--json` was intended.
- `"exit"` inside the document always equals the process exit code.
- **Versioning**: `"surfacelock_json"` is an integer, bumped on any breaking change to
  this shape. Adding fields is not breaking — consumers MUST ignore fields they do not
  know. (This is deliberately the opposite of the lockfile's SPEC.md §7 strictness: a
  report is advice, an artifact is an authority.)
- All string values are valid UTF-8 JSON strings. Error text and names can carry
  server-controlled bytes; control characters are escaped/neutralized, but consumers
  MUST still treat these strings as untrusted data, not terminal-safe text.
- Severity classification and class ordering come from the Go core (SPEC.md §8). A
  consumer adds no judgment of its own.

## Top level

```jsonc
{
  "surfacelock_json": 1,
  "verb": "lock" | "verify" | "diff",
  "file": "tools.lock",          // the lockfile path this run used
  "exit": 0,                     // == process exit code
  "error": "…",                  // run-level failure only (nothing per-server ran):
                                 //   unreadable/invalid lockfile, usage error
  // lock, success only:
  "name": "…", "tools": 1, "era": "2025-11-25", "surface_hash": "sha256:…",
  // verify/diff only:
  "servers": { "<name>": { /* server object */ } }
}
```

## Server object (`verify` / `diff`)

One entry per server processed this run (the `--name` selection, or every entry).

```jsonc
{
  "outcome": "ok" | "drift" | "transport" | "lockfile" | "inadmissible",
  "error": "…",                  // transport/lockfile/inadmissible only
  "tools": 3, "era": "2025-11-25",   // ok only: the locked entry's count and era
  "diff": { /* diff object */ }      // drift only
}
```

`"outcome"` is **this entry's own verdict**. The process exit code is the *worst*
outcome across entries (§9 precedence: lockfile > inadmissible > transport > drift >
ok), so a run that found drift on one server and a transport failure on another exits
3 — but the drift is still fully reported in its server object. The exit code alone
cannot carry both; the document always does.

## Diff object

Mirrors the SPEC.md §8 classification. `verify` and `diff` emit the identical shape
(the verbs differ only in human-output verbosity).

```jsonc
{
  "severity": "description",     // most severe class present in this diff
  "era_changed": false,
  "old_era": "2025-11-25",       // always present
  "new_era": "2025-11-25",       // always present
  "instructions_changed": true,  // server instructions are prompt text: classifies as description
  "tools": [                     // most severe first, then by name; may be empty
    { "name": "greet", "classes": ["description", "schema"] }  // most severe first, never empty
  ]
}
```

Class names, most severe first: `description`, `schema`, `era`, `metadata`,
`removed`, `added`.
