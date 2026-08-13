# surfacelock

**Status: pre-release. Nothing here is stable yet.**

surfacelock pins an MCP server's *tool surface* — the tool names, input schemas, and
descriptions an agent is told it can trust — in a reviewable lockfile: `tools.lock`.

An MCP server can change what its tools claim to do at any time, and tool descriptions
are prompt text: a changed description is an injection vector, not metadata. surfacelock
treats the tool surface like a dependency:

- **`surfacelock lock`** — capture a server's surface: per-tool SHA-256 over RFC 8785
  (JCS)-canonicalized input schema and description bytes, rolled into an era-tagged root
  `surface_hash`, written to `tools.lock`.
- **`surfacelock verify`** — re-fetch and compare; non-zero exit on drift. CI-friendly.
- **`surfacelock diff`** — what changed, severity-classified: description drift is the
  most severe class, schema drift next, additive changes last.
- **`surfacelock pin`** — explicit re-lock, so accepting a changed surface is a reviewed
  git diff.
- **`surfacelock proxy`** — the in-band enforcement point: sits on the client path
  (point your MCP client's stdio config at it; the upstream — stdio command or
  Streamable HTTP URL — comes from the lockfile entry), forwards the session, and
  verifies every surface-bearing response *this session* is served: the handshake
  (era, negotiation flow, server instructions) and every `tools/list` page, including
  re-lists after `notifications/tools/list_changed`. Drift is refused, never forwarded
  — strict by default, with `--warn` forwarding non-prompt-text drift only (description
  and instructions changes and added tools refuse even then). Drift, inadmissible
  bytes, and transport failure are distinct refusals with distinct error codes and
  remedies: an unreachable server is an honest error, never a drift verdict.

```jsonc
// where your MCP client config had:  {"command":"npx","args":["-y","some-mcp-server"]}
// or:                                {"type":"http","url":"https://example.com/mcp"}
// point it at the proxy instead:
{"command":"surfacelock","args":["proxy","--file","/abs/path/tools.lock","--name","some-server"]}
```

The `conformance/` package makes the lockfile's era tag a *checkable claim*: a
pre-registered predicate set (`conformance/PREDICATES.md`) turns "conformant to
protocol revision E" into mechanically testable wire behavior, `Check` /
`CheckLockEntry` grade a live server against the era a lock entry records, and
`conformance/gen` maintains the era-conformance matrix (`conformance/matrix.md`,
generated from retained captures — never hand-written; every capture is kept so
the matrix is re-derivable from data alone).

Design premises:

- **Unilateral adoption.** One consumer adopts and is protected — no publisher
  cooperation, no PKI, no registry.
- **In-band verification.** An out-of-band audit connection can be served a clean surface
  while a victim is served a poisoned one; verification hashes what *this session* was
  served. The CLI is the CI face of the same code; a thin client-path proxy library is
  the durable form.
- **`tools.lock` is a format; surfacelock is an implementation.** The artifact will be
  specified precisely enough that other tools can read and write it.

Viability was measured before this repo existed: across 44 real MCP servers (hosted
Streamable HTTP endpoints plus pinned local servers, five fresh-session fully-paginated
`tools/list` calls each), 100% of surfaces were byte-stable after JCS canonicalization —
so `verify` can be strict by default, and canonicalization exists for cross-representation
robustness, not flake repair.

Pure Go, single binary, no cgo.

License: not yet chosen (private pre-release).
