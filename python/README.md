# surfacelock (Python)

Typed Python bindings for [surfacelock](https://github.com/JsizzleR/surfacelock):
programmatic `lock` / `verify` / `diff` of an MCP server's tool surface, plus the
`surfacelock` CLI itself (each wheel bundles the platform's Go binary, so
`uvx surfacelock` works with no separate install).

```python
import surfacelock

surfacelock.lock("https://example.com/mcp", lockfile="tools.lock")

try:
    surfacelock.verify(lockfile="tools.lock")
except surfacelock.DriftError as e:
    for name in e.report.drifted:
        print(name, e.report.servers[name].severity)
```

Design constraints, deliberate:

- **One canonical parser.** The Go core does all canonicalization, hashing, admission,
  and drift classification; this layer drives it as a subprocess and reads its
  versioned machine report (`CLI-JSON.md`). Nothing is reimplemented here, and the
  severity model arrives from the Go side untouched.
- **Errors are typed on the exit-code contract.** `DriftError`, `TransportError`,
  `LockfileError`, `InadmissibleSurfaceError`, and `UsageError` map the CLI's exit
  codes 1–5, so the remedy can be keyed on the exception type — "the surface changed"
  and "there is no surface to judge" are different types, never one message to parse.
  Whatever is raised, `.report` carries every per-server verdict the run produced.
- **`pin` is not in the API.** Accepting drift is a reviewed VCS diff of the lockfile —
  a human act, kept on the CLI.

Mechanism note: subprocess over c-shared was measured, not assumed — the verbs are
fetch-bound (a local verify floors at ~24 ms; process spawn is ~4 ms of it), the
subprocess route cross-compiles from one machine with CGO off, and it inherits the
CLI's frozen exit-code contract instead of needing a parallel C ABI error contract.

Tests: `python -m pytest tests/` (offline; builds the CLI from the repo with `go build`,
or set `SURFACELOCK_TEST_BIN`). Wheels: `scripts/build-dist.sh` from the repo root.
