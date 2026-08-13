# Era-conformance predicates — PRE-REGISTERED

This document is committed BEFORE the first probe runs (the D-310 discipline the
toolslock-p0 spike followed with CRITERION.md): the matrix is measurement against
these predicates, and any predicate added or changed after probing began must say
so in its text. The sources are the protocol revisions' own changelogs and
normative sections (modelcontextprotocol.io/specification/<rev>/changelog, read
2026-08-13) plus facts measured previously against real servers (the toolslock-p0
corpus; the mcp==2.0.0b1 SDK; the claude CLI 2.1.229).

## What "conformant to era E" means here

A target is graded against the era **it itself negotiates or advertises** — never
against all five revisions. The graded claim is:

> Speaking era E's wire protocol to this server, the server's observable behavior
> on the read-only, surface-relevant subset of the spec matches what revision E
> requires.

Scope is deliberately the subset a read-only, unauthenticated client can reach:
handshake shape, session semantics, `server/discover` vs `initialize`+`tools/list`,
`_meta` rules, version-negotiation behavior (including when offered a NEWER
revision than E), pagination, and the era-discriminating envelope rules (JSON-RPC
batching, `CacheableResult`, `resultType`). OAuth flows, elicitation, sampling,
tool CALLS, resources and prompts are out of scope: not reachable read-only, or
not surface-bearing.

Every probe is read-only and bounded: no `tools/call`, no state mutation, at most
one short-lived session per flow, pagination capped, per-server etiquette (one
probe run, no retry storms).

## The eras

| era | the revision's own discriminating changes (from its changelog) |
|---|---|
| 2024-11-05 | initial revision: `initialize`/`notifications/initialized` handshake; cursor pagination; native remote transport is HTTP+SSE (predates Streamable HTTP) |
| 2025-03-26 | Streamable HTTP transport (single endpoint, `Mcp-Session-Id`); JSON-RPC **batching added** (support required); tool annotations; OAuth framework |
| 2025-06-18 | JSON-RPC **batching removed**; `MCP-Protocol-Version` header required on subsequent HTTP requests; lifecycle-operation SHOULD→**MUST**; structured output; elicitation |
| 2025-11-25 | icons; tasks (experimental); OIDC discovery; SSE polling clarifications; `Implementation.description`; 403-on-bad-Origin clarified |
| 2026-07-28 | **stateless**: `initialize` handshake and protocol sessions REMOVED (SEP-2575); mandatory `_meta` keys (`io.modelcontextprotocol/protocolVersion`, `clientCapabilities`) on every request; `server/discover` MUST be implemented; `resultType` required on all results; `CacheableResult` (`ttlMs`+`cacheScope`) required on `tools/list`; GET SSE stream replaced by `subscriptions/listen`; version mismatch → `UnsupportedProtocolVersionError` (-32022) |

A server negotiating `2024-11-05` over Streamable HTTP is a hybrid the 2024-11-05
spec never described (the transport postdates the revision). For such targets the
message-level probes are graded and the transport-level ones are recorded
`na-hybrid` — stated here so the matrix cannot silently over-claim.

## Probes and per-era expectations

Normative force per cell: **MUST** (a violation makes the target NONCONFORMANT for
that era), **SHOULD** (violation reported, does not flip the verdict), **OBS**
(recorded, never graded), **N/A** (probe does not apply; reason recorded). A probe
that cannot run at all records `unreached(<reason>)` — an unreached probe is never
counted as a pass (no-silent-caps).

Classic eras = 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25.

### H1 — handshake, own era
`initialize` offering E's version. Classic eras: MUST succeed with
`result.protocolVersion == E`, `serverInfo` present, `capabilities` object
present. Era 2026-07-28: MUST be refused (the handshake was removed; any
non-success — HTTP 4xx or JSON-RPC error — conforms; a successful handshake
result violates).

### H2 — handshake, offered NEWER revision
`initialize` offering `2026-07-28` (newer than any classic E). Classic eras: MUST
respond with a dated revision the server supports (spec rule: "respond with the
latest version it supports"); echoing the offered newer version is conformant
ONLY if the server then actually speaks it (cross-checked by grading it as a
2026-07-28 target too); an error response to the handshake itself is a violation.
Era 2026-07-28: N/A (no handshake; the stateless mismatch arm is V2).

### H3 — lifecycle order
`tools/list` before any handshake, on a fresh session/connection carrying no
session id. Eras 2025-06-18, 2025-11-25: MUST be refused (lifecycle operation is
MUST since 2025-06-18; over HTTP the measured SDK shape refuses at the session
gate). Eras 2024-11-05, 2025-03-26: SHOULD be refused (lifecycle was SHOULD).
Era 2026-07-28: MUST SUCCEED given a well-formed `_meta` envelope (statelessness
is the point — there is no handshake to order against).

### D1 — server/discover, cold
`server/discover` with the full mandatory `_meta` envelope. Era 2026-07-28: MUST
succeed; result MUST carry `supportedVersions` (non-empty, containing
`2026-07-28`), `serverInfo`, `capabilities`. Classic eras: MUST NOT succeed (the
method does not exist in E; method-not-found, a session refusal, or any
non-success conforms).

### D2 — mandatory _meta envelope (2026-07-28 only)
The same request with `_meta` ABSENT. MUST be refused (SEP-2575's envelope is
mandatory). Classic eras: N/A.

### V1 — MCP-Protocol-Version header (HTTP; eras 2025-06-18, 2025-11-25)
After H1 negotiation, `tools/list` WITH `MCP-Protocol-Version: <negotiated>`:
MUST succeed. The same request with the header ABSENT: OBS (the client MUST send
it; server-side enforcement is not mandated — record what the server does).
Other eras: N/A (header introduced 2025-06-18; meaningless under stateless).

### V2 — stateless version mismatch (2026-07-28 only)
A request whose `_meta` `protocolVersion` names a revision the server's
`supportedVersions` does not list. MUST be refused with a version-mismatch error;
the published code is -32022 (`UnsupportedProtocolVersionError`). The refusal
itself is MUST; the exact code is graded SHOULD (the renumbering from -32004
happened inside the draft cycle and SDK grandfathering is explicit in the
allocation policy).

### S1 — session enforcement (HTTP; eras 2025-03-26..2025-11-25)
If H1's response minted `Mcp-Session-Id`: a subsequent `tools/list` WITHOUT the
header MUST be refused (HTTP 4xx or JSON-RPC error), and WITH the header MUST
succeed. If no session id was minted: `na(stateless-server)` — the header is
optional server-side; record the stateless operation. Era 2024-11-05: OBS (the
header postdates the era). Era 2026-07-28: N/A (S2 owns it).

### S2 — no protocol sessions (HTTP; 2026-07-28 only)
Responses MUST NOT mint `Mcp-Session-Id`, and requests carrying none MUST
succeed (SEP-2567).

### T1 — tools/list shape and pagination (all eras)
On the era's own flow: `tools/list` MUST return a `tools` array in which every
member carries a string `name`. If `nextCursor` is returned, following it MUST
terminate within the page bound (8 pages) with no cursor repeated and no tool
name duplicated across pages. (The bound is the harness's, stated in the matrix;
a walk that hits it records `unreached(page-cap)`, never a pass.)

### T2 — invalid cursor (all eras)
`tools/list` with `params.cursor = "surfacelock-era-invalid-cursor"`: SHOULD be
refused with -32602 (the spec's SHOULD). Any non-error acceptance is reported,
never flips the verdict.

### B1 — JSON-RPC batching (the 03-26/06-18 discriminator)
POST a two-element batch `[tools/list, tools/list]` (both transports; over the
era's own negotiated flow). Era 2025-03-26: MUST be accepted (batching support
was added as a requirement). Eras 2025-06-18, 2025-11-25: MUST be refused
(batching was removed; a batch response array is a violation). Era 2024-11-05:
OBS (the MCP spec of that era did not speak to batching). Era 2026-07-28: MUST
be refused.

### C1 — CacheableResult (2026-07-28 only)
The `tools/list` result MUST carry `ttlMs` (number) and `cacheScope`
(`"public"` or `"private"`) — SEP-2549's requirement. Classic eras: N/A.

### R1 — resultType (2026-07-28 only)
Every successful result MUST carry `resultType: "complete"` (SEP-2322). Classic
eras: N/A (clients treat the absent field as complete — the absence is the old
protocol, not a violation of it).

### G1 — GET on the endpoint (HTTP)
GET with `Accept: text/event-stream`. Eras 2025-03-26..2025-11-25: OBS (an SSE
stream and a 405 are both conformant; record which). Era 2026-07-28, when the
target's `supportedVersions` is exactly `["2026-07-28"]`: SHOULD NOT serve the
old SSE stream (it was replaced by `subscriptions/listen`); multi-version
targets: OBS. Era 2024-11-05: `na-hybrid` over Streamable HTTP.

### I1 — identity (all eras)
`serverInfo.name` and `.version` non-empty wherever the era surfaces them:
SHOULD; recorded verbatim in the matrix either way.

## Verdict model

Per (target, era): **CONFORMANT** — every applicable MUST cell passed;
**CONFORMANT\*** — MUSTs passed, one or more SHOULD violations (listed);
**NONCONFORMANT** — at least one MUST violation (each named with its probe id and
the observed bytes' summary); plus the `unreached(...)` set, always printed.
A target that negotiates several eras is graded once per era it demonstrably
speaks. Exclusions (auth-walled, dead endpoint, eager-backend) are recorded with
their measured reason, like the toolslock-p0 corpus did.

## Validity controls (D-292: verdicts are void without both)

- **CTRL-BAD** (hermetic, in-process): a fake claiming 2025-11-25 with FOUR
  planted violations — (a) echoes any offered version verbatim (H2), (b) mints a
  session id but serves `tools/list` without it (S1), (c) accepts a JSON-RPC
  batch (B1), (d) duplicates a tool name across pages (T1). The harness MUST
  report exactly these four MUST violations and no others.
- **CTRL-GOOD** (hermetic, in-process): a fake implementing 2025-11-25 correctly
  — the harness MUST report CONFORMANT with zero violations.
- **CTRL-SDK** (live): an official-SDK server (the toolslock-p0 recipe, SDK
  pinned) MUST grade CONFORMANT or CONFORMANT\* for the era it negotiates; any
  MUST violation it shows is presumed a harness bug until shown otherwise, and
  the resolution is recorded here.

## First targets

Bastle's own faces (the only known 2026-07-28 speakers), then the toolslock-p0
corpus: hosted rows re-probed live; pinned local rows re-launched at their
recorded pins (SDK pinned as part of the pin, per the corpus's own finding).
