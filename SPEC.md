# tools.lock — format specification, version 0 (draft)

**Status: draft. `lockfile_version` 1. Pre-release; every MUST below is subject to change
until this repo tags a release.**

`tools.lock` is a lockfile that pins an MCP server's *tool surface*: the tool names, input
schemas, descriptions, and server instructions an agent is told it can trust. This document
specifies the artifact and the semantics of the four verbs (`lock`, `verify`, `diff`,
`pin`) precisely enough that an independent implementation can be written from it alone.
surfacelock is the reference implementation, not the format's owner.

Conformance language (MUST / SHOULD / MAY) is RFC 2119.

## 1. Threat model, in three sentences

An MCP server can change what its tools claim to do at any time after a human last looked,
and tool descriptions and server instructions are prompt text — a changed description is an
injection vector, not metadata. A consumer that pins the surface at review time and verifies
it in-band (over what *this session* was served, since an out-of-band audit connection can
be shown a clean surface) turns a silent swap into a hard failure. Everything a server sends
is hostile input: this spec fails closed on surfaces it cannot admit, and nothing in the
artifact is trusted because the server asserted it — the hashes are the authority.

## 2. Terminology

- **Tool surface**: the complete set of tool objects returned by a fully-paginated
  `tools/list`, plus the server `instructions` string from `initialize` (if any), under a
  negotiated protocol revision.
- **Era**: the protocol revision the server negotiated at `initialize` (e.g.
  `"2025-11-25"`). The same bytes can mean different things under different revisions, so
  the era is part of the pinned surface, not an annotation on it.
- **JCS**: the JSON Canonicalization Scheme, RFC 8785. Whenever this spec says
  *canonical form* of a JSON value, it means the RFC 8785 transform of that value.
- **Hash**: `"sha256:"` followed by the lowercase hex SHA-256 of the stated preimage.
  `lockfile_version` 1 admits no other algorithm.
- **Absent sentinel**: the literal string `"absent"` used in place of a hash when the
  hashed field does not exist. Absence is part of the surface: a description appearing
  where there was none is drift.

## 3. The artifact

- File name: `tools.lock` by convention (implementations MUST NOT require the name).
- Encoding: UTF-8, no BOM, LF line endings, exactly one trailing newline.
- Content: a single JSON document with this shape (field semantics in §3.1–§3.3):

```json
{
  "lockfile_version": 1,
  "servers": {
    "<server-name>": {
      "transport": "http",
      "target": "https://example.com/mcp",
      "args": [],
      "protocol": { "offered": "2026-07-28", "era": "2025-11-25" },
      "server_info": { "name": "example", "version": "1.2.3" },
      "instructions": "…verbatim…",
      "h_instructions": "sha256:…",
      "surface_hash": "sha256:…",
      "tools": [
        {
          "name": "get_weather",
          "h_desc": "sha256:…",
          "h_schema": "sha256:…",
          "h_tool": "sha256:…",
          "tool": { "…the canonical tool object, re-indented…": "…" }
        }
      ]
    }
  }
}
```

A lockfile MAY pin more than one server. Server names are consumer-chosen labels (map
keys); they identify the *entry*, never the server — the hashes do that.

### 3.1 Server entry fields

- `transport` (string, required): `"http"` (MCP Streamable HTTP) or `"stdio"`.
- `target` (string, required): for `http`, the endpoint URL; for `stdio`, the command
  (argv[0]).
- `args` (array of strings, required, may be empty): for `stdio`, argv[1..]; for `http`,
  MUST be empty. Environment variables are deliberately NOT recorded: secrets never
  transit the lockfile. A verifier runs stdio commands with the caller's environment.
- `protocol.offered` (string, required): the `protocolVersion` the client offered when
  this entry was written. Verifiers MUST re-offer the same value, so negotiation is
  reproducible; a different offer could negotiate a different era, or select a different
  fetch flow (§3.4), and manufacture false drift.
- `protocol.era` (string, required): the `protocolVersion` the fetch was served under.
  This is the era tag; it is bound into `surface_hash` (§5). Classic flow: the
  `initialize` result's `protocolVersion`. Stateless flow (§3.4): the offered revision
  itself, which `server/discover`'s `supportedVersions` MUST have confirmed.
- `server_info` (object, optional, informational): `name` and `version` from the
  `initialize` result's `serverInfo`, stored verbatim. NOT part of the surface, NOT
  hashed, never a drift verdict — a server's self-report is not evidence. Writers MUST
  omit `name` or `version` when the value is not a string, is not valid UTF-8, or exceeds
  256 bytes.
- `instructions` (string, optional): the `instructions` field of the `initialize` (or,
  stateless flow, `server/discover`) result, verbatim. Present iff the server sent a
  string value. Server instructions are prompt text — the same threat class as tool
  descriptions — so they are part of the surface.
- `h_instructions` (string, required): hash of the canonical form of the `instructions`
  JSON string, or the absent sentinel. When `instructions` is present, this MUST equal
  the recomputed hash (§7).
- `surface_hash` (string, required): the rollup, §5.
- `tools` (array, required, may be empty): one entry per tool, sorted ascending by the
  byte-wise (i.e. UTF-8 code unit) order of `name`. Zero tools is a valid surface.

### 3.2 Tool entry fields

- `name` (string, required): the tool's `name`, verbatim. MUST equal `tool.name`.
- `h_tool` (string, required): hash of the canonical form of the **entire tool object**
  as served. This is the per-tool authority: it covers every field, including ones this
  spec has never heard of.
- `h_schema` (string, required): hash of the canonical form of the tool's `inputSchema`
  value, or the absent sentinel.
- `h_desc` (string, required): hash of the canonical form of the tool's `description`
  value (a JSON string token, quotes and escapes included), or the absent sentinel.
- `tool` (object, required): the tool object itself in canonical form, re-indented per
  §4. Stored so that `pin` produces a reviewable git diff of the actual text that
  changed, and so `diff` can attribute drift precisely (§8) — a lockfile of bare hashes
  can only say *that* something changed. `h_desc`, `h_schema`, and `h_tool` are
  derivable from `tool`; they are stored anyway as the interop anchors, and a reader
  MUST treat a mismatch between them and `tool` as a corrupt lockfile (§7).

### 3.3 What is deliberately not in the artifact

- **No timestamps, no tool versions, no provenance.** The same surface MUST produce a
  byte-identical lockfile on every machine, every time. Determinism is the interop claim.
- **No environment, no credentials, no headers.** Secrets never transit the artifact.
- **No signatures.** A lockfile is reviewed and carried in the consumer's own VCS; its
  integrity story is git's. Signing is a possible future layer, not this one.
- **Prompts and resources.** MCP servers also serve prompt and resource surfaces; they
  are the same threat class and a future `lockfile_version` may add sections for them.
  Version 1 pins tools and instructions only.

### 3.4 Fetch flows — classic and stateless

The protocol's 2026-07-28 revision (SEP-2575) removed the `initialize` handshake:
every request is self-describing, carrying the reserved `_meta` envelope keys
(`io.modelcontextprotocol/protocolVersion`, `…/clientInfo`, `…/clientCapabilities`),
and capabilities come from `server/discover`. Fielded server populations are disjoint
in which face they expose (measured: pre-revision SDK servers answer classic only and
refuse a cold `server/discover`; a stateless-only endpoint refuses `initialize`
outright), so a fetcher MUST select its flow from the offered revision:

- **Offered `2026-07-28` or later**: try the stateless flow — `server/discover`
  (whose result supplies `instructions` and `server_info`, and whose
  `supportedVersions` MUST include the offered revision), then fully-paginated
  `tools/list` with the full `_meta` envelope on every request, no handshake. If the
  discover attempt fails for any reason, fall back to one classic attempt on a fresh
  session state; if both fail, report both refusals.
- **Offered pre-revision values**: the classic flow only — `initialize` (offering
  `protocol.offered`), `notifications/initialized`, then fully-paginated `tools/list`.

Because verifiers re-offer `protocol.offered`, an entry locked over either flow is
re-verified over the same flow selection, and the era stays reproducible.

## 4. Canonical rendering

The entire lockfile is rendered by one deterministic algorithm:

1. Build the lockfile as a JSON value.
2. Take its canonical form (RFC 8785). This sorts all object members by UTF-16 code
   units, serializes numbers as ES6 doubles, and fixes string escaping.
3. Re-indent the canonical bytes with the whitespace-only algorithm of §4.1, using
   two-space indentation.
4. Append one LF.

Step 3 inserts whitespace between JSON tokens and does nothing else, so stripping
insignificant whitespace from a rendered lockfile MUST yield exactly the RFC 8785 bytes
of the document. Object member order in the file is therefore RFC 8785 order everywhere;
readers MUST NOT ascribe meaning to member order and MUST accept any valid JSON with the
required shape (a hand-edited or re-serialized lockfile is *valid*; it just won't be
byte-identical until the next `pin` rewrites it).

The stored `tool` objects inherit the same treatment: their bytes in the file are their
RFC 8785 form re-indented at their nesting depth. Recovering a tool's exact canonical
bytes = parse the lockfile, take the `tool` value, apply RFC 8785. (RFC 8785 is
idempotent on its own output, and re-serialization robustness — hash survival across
parse/re-emit — is the reason canonicalization is in the design at all.)

### 4.1 Indentation algorithm

Equivalent to Go's `encoding/json.Indent` with empty prefix and two-space indent:

- After `{` or `[` that is not immediately followed by its closer: newline, then
  (depth × 2) spaces.
- Before `}` or `]` closing a non-empty object/array: newline, then ((depth−1) × 2)
  spaces.
- After each `,` separating members/elements: newline, then (depth × 2) spaces.
- After each `:` in an object member: one space.
- Empty objects render as `{}`, empty arrays as `[]`.
- No other whitespace is emitted. String contents are never touched.

## 5. The surface hash

`surface_hash` is the hash of the canonical form (RFC 8785) of this JSON value:

```json
{
  "era": "<protocol.era>",
  "h_instructions": "<h_instructions>",
  "tools": [
    { "h_tool": "<h_tool>", "name": "<name>" },
    …sorted ascending by byte-wise order of name…
  ]
}
```

Properties, all load-bearing:

- **Era-tagged**: the same tool bytes under a different negotiated revision hash
  differently, because the revision changes what the bytes mean.
- **Injection-proof**: the preimage is a canonicalized JSON structure, not a
  concatenation. There is no separator a hostile tool name can forge (a `name`
  containing `:`  or `\n` is data, escaped by JCS, never structure).
- **Order-independent**: tool list order is excluded by the name sort. Reordering is not
  drift. (An implementation MAY surface order changes as an observation; they are not a
  verdict.)
- **Complete**: `h_tool` covers the whole tool object, so drift in any field — including
  fields unknown to this spec — changes `surface_hash`.

## 6. Admissibility — hostile input rules

A `tools/list` response is hostile input. An implementation MUST refuse to lock, and MUST
refuse to treat as a comparable live surface, any of the following. Refusal is a distinct
outcome from drift (§9): an inadmissible surface never produces a lockfile and never
produces a drift verdict.

- **Duplicate tool names** — two tools with byte-identical `name`, within a page or
  across pages. A duplicate is either a server bug or an aliasing attack (the second
  definition shadows the audited first); there is no safe way to pick one.
- **Nameless or malformed tools** — a tool that is not a JSON object, lacks `name`, or
  whose `name` is not a string.
- **Invalid names** — `name` empty, longer than 128 bytes, not valid UTF-8, or
  containing code points below U+0020 or U+007F (DEL). Names are map keys, sort keys,
  and terminal output; control characters in them are attacks on all three.
- **Type-invalid fields** — `description` present but not a string; `inputSchema`
  present but not an object. Exception: a JSON `null` value for `description`,
  `inputSchema`, or `instructions` is treated as absent (a serializer artifact, not
  content); the null still participates in `h_tool`, which hashes the object verbatim.
- **Pagination abuse** — a `nextCursor` equal to a cursor already seen this fetch
  (a cursor loop), a non-string `nextCursor`, a cursor longer than 4096 bytes, or more
  than the implementation's page limit (reference: 100 pages).
- **Oversized surfaces** — implementations MUST cap per-page bytes, per-tool canonical
  bytes, total canonical surface bytes, tool count, and `instructions` bytes, and refuse
  beyond the cap. The caps are implementation-defined but MUST exist and MUST be
  documented. Reference implementation defaults: 4 MiB/page, 1 MiB/tool, 16 MiB/surface,
  10 000 tools, 64 KiB instructions.
- **Invalid UTF-8** — any page, tool, or instructions value whose RAW bytes are not
  valid UTF-8. This MUST be checked on the wire bytes: most JSON decoders silently
  replace invalid sequences with U+FFFD, so a decoded-string check is vacuous, and
  RFC 8785 passes invalid bytes through verbatim — admitting them would put non-UTF-8
  bytes into the artifact (§3) and let drift hide behind replacement-collapsed
  comparisons.
- **Objects with duplicate member names** — RFC 8785 rejects them (measured:
  `gowebpki/jcs` errors), and this spec relies on that: a duplicate-key tool object is
  uncanonicalizable, hence inadmissible. An implementation whose canonicalizer
  tolerates duplicate keys MUST refuse them itself — decoder last-key-wins semantics
  would let a tool present one value to the hash and another to a consumer.
- **Case-variant collisions on the `tools` page key** — `{"tools":[…],"TOOLS":[…]}` has
  two DISTINCT members to a canonicalizer (so it survives the duplicate-key rule), but
  a decoder that matches object keys case-insensitively (Go's `encoding/json` does)
  would silently pick one. An implementation MUST read the `tools` array by an exact,
  case-sensitive key and refuse a page carrying any case-variant of it.
- **Uncanonicalizable JSON** — any value RFC 8785 cannot transform (e.g. numbers outside
  IEEE-754 double range, lone surrogate escapes). Fail closed; never approximate.
  Stated bound, inherent to RFC 8785's ES6 number serialization: integers of magnitude
  above 2^53 collapse to their nearest double (`9007199254740993` and
  `9007199254740992` canonicalize identically), so drift within one double-equivalence
  class is invisible to the hashes. Such constants in tool schemas are already
  non-interoperable JSON (RFC 7493).
- **Missing era** — an `initialize` result without a string `protocolVersion` is a
  protocol failure (§9 exit 3): the surface cannot be era-tagged, so there is no surface.

Non-JSON noise on a stdio server's stdout (log lines interleaved with JSON-RPC) SHOULD be
tolerated and skipped, bounded by the fetch deadline; it is endemic in real servers and
is not part of the surface.

## 7. Lockfile validity

A reader MUST reject (as a lockfile error, not drift):

- JSON that does not parse, or `lockfile_version` ≠ 1.
- Missing required fields, wrong types, or an unknown `transport`.
- `tools` not sorted by name, or a `name` ≠ its `tool.name`.
- **Self-inconsistency**: any stored hash (`h_desc`, `h_schema`, `h_tool`,
  `h_instructions`, `surface_hash`) that does not equal the value recomputed from the
  stored content by §2/§5. A lockfile whose hashes disagree with its own content has
  been corrupted or tampered with; comparing a live surface against it would produce a
  confident verdict about nothing.

Unknown *additional* fields in the lockfile MUST be rejected too (`lockfile_version` is
the extension mechanism; tolerant readers create silent forks of the format).

## 8. Drift classes and severity

When a locked entry and an admissible live surface differ, every difference is classified.
Classes, most severe first:

1. **`description`** — prompt text changed on an existing tool or the server: the
   top-level `description`, **any string value whose object key is `description`
   anywhere inside the tool object** (schemas embed per-property descriptions; an
   attacker who moves injection text into a property description must not earn a milder
   class), or the server `instructions`. Rationale: this is the injection vector; a
   description change is a change to what the model is told, inverting the package-manager
   intuition that prose changes are cosmetic.
2. **`schema`** — the machine-consumed contract changed: `inputSchema` or `outputSchema`
   differ in any way that is not purely embedded-description drift, or the tool's
   `annotations` changed (hints like `readOnlyHint`/`destructiveHint` steer client
   confirmation behavior, so a flipped hint changes what runs without a human).
3. **`era`** — `protocol.era` differs: the negotiated revision changed, which
   re-interprets the whole surface even where bytes agree.
4. **`metadata`** — an existing tool changed in some other way: `title`, or any field
   this spec does not know (detected via `h_tool` after the classes above are
   excluded).
5. **`removed`** — a locked tool is gone. Capability loss; breaks consumers; not an
   injection.
6. **`added`** — a new tool appeared. Least severe *for review ordering* — its full
   content is present in the diff for human review — but it is still drift: `verify`
   fails on additive change like any other, because a new tool is new prompt text.

A changed tool can carry several classes at once (e.g. description + schema);
implementations MUST report the most severe and SHOULD report every class that applies.
`server_info` differences are never drift (§3.1). Tool order changes are never drift (§5).

## 9. Verbs and exit codes

All four verbs share one fetch discipline: a fresh session (for stdio, a fresh
process) driven through the flow §3.4 selects from the offered revision, then
fully-paginated `tools/list`, applying §6 throughout. Verification is **in-band by
design**: the hash that matters is over what this connection was served. The CLI is the
CI face of the same code path; a client-path proxy that verifies the session actually
used is the durable form (out of scope for this version of the spec).

- **`lock`** — fetch, admit, write a new entry. MUST refuse to overwrite an existing
  entry of the same name (that is `pin`'s job; the distinction is what makes accepting
  drift an explicit, reviewable act).
- **`verify`** — for each entry (or one named entry): fetch, admit, compare. Reports
  drift per §8; exits non-zero on any drift. The CI verb: quiet on success.
- **`diff`** — like `verify`, but the point is the report: per-tool, severity-classified,
  most severe first. Exit follows `diff(1)` convention.
- **`pin`** — fetch, admit, **rewrite** an existing entry (refuses a missing one). The
  resulting VCS diff of the lockfile — actual descriptions, schemas, instructions — is
  the review artifact. `pin` accepts the current surface; it never merges.

Exit codes (CI-grade; each condition is distinguishable by a script):

| code | meaning |
|---|---|
| 0 | success; `verify`/`diff`: no drift |
| 1 | drift (`verify`) / differences found (`diff`) |
| 2 | usage error |
| 3 | transport or protocol failure — no admissible surface could be fetched |
| 4 | lockfile error — missing, unparseable, invalid, or self-inconsistent (§7) |
| 5 | inadmissible surface (§6) — the server served something no verdict can be built on |

Codes 3–5 are deliberately not 1: "the surface changed" and "there is no surface to
judge" must never be confused by a pipeline, in either direction.

Untrusted strings (names, descriptions, server info) rendered to a terminal MUST be
escaped (control characters made visible); a hostile description must not be able to
rewrite the report that quotes it.

## 10. Versioning and interoperability

- `lockfile_version` is an integer, bumped on any change to hashing preimages, rollup
  construction, admissibility that affects artifact content, or artifact shape. Readers
  MUST reject versions they do not implement (§7).
- Two conforming implementations locking the same admissible surface MUST produce
  byte-identical lockfiles. That is testable, and it is the point of §4.
- The format is `tools.lock`; surfacelock is one implementation. Nothing in this spec
  depends on surfacelock internals.
