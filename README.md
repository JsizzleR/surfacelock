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
