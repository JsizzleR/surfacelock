# MCP era-conformance matrix

Generated from the retained captures by `conformance/gen` — never hand-edited.
Predicates and verdict model: `conformance/PREDICATES.md` (pre-registered).

| target | kind | era | verdict | MUST violations | SHOULD violations | unreached |
|---|---|---|---|---|---|---|
| bastle-bridge-legacy | http | 2026-07-28 | NONCONFORMANT | D2.nometa, V2.mismatch, C1.cacheable, R1.resulttype | T2.badcursor | — |
| bastle-bridge-modern | http | 2026-07-28 | CONFORMANT* | — | T2.badcursor | — |
| bastle-okffacade | http | 2026-07-28 | NONCONFORMANT | D2.nometa | — | — |
| ref-everything | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |

## Evidence (violations and unreached cells)

### bastle-bridge-legacy @ 2026-07-28

- `D2.nometa` MUST! — request without the mandatory _meta envelope SERVED
- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)
- `V2.mismatch` MUST! — request naming an unsupported protocolVersion was SERVED
- `C1.cacheable` MUST! — tools/list result lacks CacheableResult fields (ttlMs=false cacheScope=false)
- `R1.resulttype` MUST! — H3.cold result lacks resultType:"complete"

### bastle-bridge-modern @ 2026-07-28

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### bastle-okffacade @ 2026-07-28

- `D2.nometa` MUST! — request without the mandatory _meta envelope SERVED

### ref-everything @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

---
Graded from 4 capture(s): bastle-bridge-legacy@2026-07-28.json, bastle-bridge-modern@2026-07-28.json, bastle-okffacade@2026-07-28.json, ref-everything@2025-11-25.json
