# surfacelock

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

### Servers behind a credential

An HTTP MCP endpoint sitting behind an authenticator answers an uncredentialed
fetch with a transport failure — which is honest, and useless: the surface is
never reached, so no verb can say anything about it. `--header` attaches a static
header to every request the http transport makes, on every verb:

```jsonc
// the credential is read from the environment, so it is never in argv, where
// any local process can read it for as long as the proxy runs:
{
  "command": "surfacelock",
  "args": ["proxy", "--file", "/abs/path/tools.lock", "--name", "some-server",
           "--header-env", "Authorization: MCP_TOKEN"],
  "env": {"MCP_TOKEN": "Bearer ..."}
}
```

`--header NAME:VALUE` takes the value literally and `--header-env NAME:VAR` reads
it from an environment variable at startup; both repeat.

> **The config block above is often a file you commit** — `.mcp.json` is
> project-scoped by design. `--header-env` keeps the value out of `argv`, where
> any local process can read it; it does not make the value safe to put in
> version control. Supply `MCP_TOKEN` from your shell or a secret manager, and
> keep it out of any file the repository tracks.

What is enforced rather than documented:

- **surfacelock never puts a header into `tools.lock`** — and because a *server*
  can echo what you sent it back into its own `instructions` or a tool
  description, which a lockfile records verbatim, `lock` and `pin` REFUSE to
  write when the rendered bytes contain a value you supplied as a header.
  Refused rather than redacted: a redacted artifact would carry a
  `surface_hash` that no longer describes what the server served. That scan
  matches a value whole and skips values under 8 bytes, so it is a guard with
  stated limits, not a guarantee that no credential can ever reach an artifact.
- **A redirect is never followed.** `net/http` strips only six credential header
  names, and only across hostnames — so a bearer survives a redirect to a
  subdomain, to another port, and from https to http, while a vendor name like
  `X-Api-Key` survives to anywhere at all. The upstream chooses the `Location`,
  and the upstream is what a proxy exists to distrust. A `3xx` is reported as
  the transport failure it is.
- **Names the transport owns cannot be set.** `Content-Type`, `Accept`,
  `Accept-Encoding`, `User-Agent`, `Mcp-Session-Id`, `MCP-Protocol-Version`,
  `Mcp-Method`, `Mcp-Name` and `Last-Event-ID` are refused, not merely
  outranked: the session ones are sent only when the transport HAS them, so on
  the handshake — the request that decides the dialect — a static value would go
  out unopposed; and `Mcp-Method`/`Mcp-Name` mirror the request body, which a
  static value could only contradict. (`Mcp-Param-*` is not reserved: the proxy
  does not yet mirror `x-mcp-header` tool arguments, and a static one is the
  only way to supply a fixed annotated argument until it does.) `Host`, `Content-Length`, `Transfer-Encoding`, `Trailer` and the
  hop-by-hop controls are refused too, because `net/http` derives or owns them
  and setting one is a silent no-op.
- **One credential, one entry.** `verify`, `diff` and `pin` select *every* entry
  when `--name` is absent, so a header there would be sent to every HTTP
  upstream the lockfile names. A header with more than one entry selected is
  refused; pass `--name`. (A single-entry lockfile needs no `--name`.)
- **A blank or unset value is a usage error**, not an absent header. An absent
  credential is a 401, which is reported as a transport failure — a true
  sentence about the wrong cause.
- **`--url` may not carry `user:password@`.** It is a credential `net/http`
  turns into HTTP Basic, and unlike a header it is written into the lockfile's
  `target`.

They apply to the http transport; a stdio server takes its credentials through
`--env`, and naming both is refused rather than silently ignored.

## Install

**From source** (Go 1.26+), which is also how CI pins an exact revision:

```sh
go install github.com/JsizzleR/surfacelock/cmd/surfacelock@v0.2.4
```

**Prebuilt binaries** are attached to each GitHub release for darwin/arm64,
darwin/amd64, linux/amd64 and linux/arm64 — one static binary each, built with
`CGO_ENABLED=0`, no runtime dependencies. Put it anywhere on `PATH`.

**Python** — a wheel per platform bundles that binary, so it carries both the
`surfacelock` console script and the `import surfacelock` bindings (see
[python/README.md](python/README.md)). Not yet on PyPI: install the `.whl` for your
platform from the release assets —

```sh
uv pip install ./surfacelock-0.2.4-py3-none-macosx_12_0_arm64.whl
```

**npm** — a launcher package plus one platform package per binary, resolved by
`os`/`cpu`. Not yet on npm: use the release binary or the wheel until it is.

The registry names are deliberately unclaimed as of this release; the GitHub release
assets are the distribution that exists today, and this section will say so until that
changes.

**Windows is not supported.** The client and proxy use unix process-group teardown
(`syscall.Setpgid` / `syscall.Kill`) and do not compile for `windows` — a porting item,
not a packaging choice. There is deliberately no Windows binary, wheel, or npm package
rather than an untested one.

## The format, and the era tag

[SPEC.md](SPEC.md) specifies `tools.lock` v0 precisely enough for a second
implementation: the artifact, the per-tool and rollup hashes, the admissibility rules,
the severity classes, and the verbs' exit codes. [CLI-JSON.md](CLI-JSON.md) is a
separate, separately-versioned contract for `--json` — the machine report the Python
bindings parse.

The `conformance/` package makes the lockfile's era tag a *checkable claim*: a
pre-registered predicate set (`conformance/PREDICATES.md`) turns "conformant to
protocol revision E" into mechanically testable wire behavior, `Check` /
`CheckLockEntry` grade a live server against the era a lock entry records, and
`conformance/gen` maintains the era-conformance matrix (`conformance/matrix.md`,
generated from retained captures — never hand-written; every capture is kept so
the matrix is re-derivable from data alone).

## Design premises

- **Unilateral adoption.** One consumer adopts and is protected — no publisher
  cooperation, no PKI, no registry.
- **In-band verification.** An out-of-band audit connection can be served a clean surface
  while a victim is served a poisoned one; verification hashes what *this session* was
  served. The CLI is the CI face of the same code; a thin client-path proxy library is
  the durable form.
- **`tools.lock` is a format; surfacelock is an implementation.** The artifact is
  specified precisely enough that other tools can read and write it.
- **One canonical parser.** Canonicalization, hashing, admission and drift
  classification live in the Go core and nowhere else; the Python bindings drive that
  core as a subprocess and read its versioned report, reimplementing none of it.

Viability was measured before this repo existed: across 44 real MCP servers (hosted
Streamable HTTP endpoints plus pinned local servers, five fresh-session fully-paginated
`tools/list` calls each), 100% of surfaces were byte-stable after JCS canonicalization —
so `verify` can be strict by default, and canonicalization exists for cross-representation
robustness, not flake repair.

Pure Go, single binary, no cgo.

## Bounds

Stated here because a tool that hides its limits is worse than one that has none.

**What a lock does not cover.** `tools.lock` pins the *declaration* the model is shown —
never the server's implementation, and never what a tool returns at runtime. Injection
through tool *results* is a real and separate problem needing separate controls. The
first lock is trust-on-first-use: `lock` records what the server served you and what you
reviewed. Drift detection is what you get without waiting for a signing ecosystem that
does not exist yet.

**Measurement bounds.** The 44-server stability result is a feasibility sample, not a
prevalence estimate: servers at pinned versions, observed over about eleven minutes,
answering "are surfaces deterministic enough to hash strictly". It says nothing about
how often real servers drift between releases, and the auth-walled hosted tier went
unmeasured.

**Proxy availability.** Frames are written to the client synchronously, so a forwarded
frame is guaranteed delivered before the next one proceeds. The cost is a teardown edge:
a client that closes the proxy's stdin but stays alive *without* draining the proxy's
stdout stalls the inbound join. The CLI relies on process lifecycle there (a real MCP
client drains its side); a library caller embedding `proxy.Run` leaks one goroutine in
that case, as documented on `Run`. Removing the stall needs an asynchronous client
writer that would either drop a healthy client's final frames or reintroduce a
wedged-sink hang, and neither trade is worth it for the CLI face. This is a stall, not a
bypass: a stalled proxy forwards nothing.

**Proxy memory.** In-flight request ids are capped at 256 and tracked cursors at 1024,
but a single relayed frame is bounded only by 64 MiB, so a client can pin roughly 16 GiB
across its own session's in-flight map. That is self-inflicted — the threat model puts
the hostile party upstream, on the *server* side of the path — and surface-bearing
server responses are separately byte-capped at verification time. Both limits fail
closed.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
