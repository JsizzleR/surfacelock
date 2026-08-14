# MCP era-conformance matrix

Generated from the retained captures by `conformance/gen` — never hand-edited.
Predicates and verdict model: `conformance/PREDICATES.md` (pre-registered).

| target | kind | era | verdict | MUST violations | SHOULD violations | unreached |
|---|---|---|---|---|---|---|
| astro-docs | http | 2025-06-18 | CONFORMANT* | — | T2.badcursor | — |
| bastle-bridge-legacy | http | 2026-07-28 | CONFORMANT* | — | T2.badcursor | — |
| bastle-bridge-modern | http | 2026-07-28 | CONFORMANT* | — | T2.badcursor | — |
| bastle-okffacade | http | 2026-07-28 | CONFORMANT | — | — | — |
| cloudflare-docs | http | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| coingecko | http | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| context7-remote | http | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| deepwiki | http | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| gitmcp-docs | http | 2025-03-26 | NONCONFORMANT | B1.batch | T2.badcursor | — |
| gitmcp-mcp-repo | http | 2025-03-26 | NONCONFORMANT | B1.batch | T2.badcursor | — |
| huggingface | http | 2025-11-25 | NONCONFORMANT | B1.batch | T2.badcursor | — |
| mslearn | http | 2025-06-18 | NONCONFORMANT | S1.session | T2.badcursor | — |
| py-arxiv | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-awsdocs | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-blender | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-calculator | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-ddg | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-excel | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-fetch | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-git | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-markitdown | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| py-sentry | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-sqlite | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| py-time | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| ref-awskb | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-brave | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-everart | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-everything | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| ref-filesystem | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| ref-github | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-gitlab | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-gmaps | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-memory | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| ref-postgres | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-puppeteer | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| ref-seqthinking | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| ref-slack | stdio | 2024-11-05 | CONFORMANT* | — | T2.badcursor | — |
| tp-airbnb | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-context7 | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-context7-modern | stdio | 2026-07-28 | NONCONFORMANT | D1.discover, V2.mismatch, C1.cacheable, R1.resulttype | T2.badcursor | I1.identity |
| tp-desktop-cmd | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-ea-playwright | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-exa | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-firecrawl | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-kubernetes | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-notion | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-playwright | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |
| tp-tavily | stdio | 2025-11-25 | CONFORMANT* | — | T2.badcursor | — |

## Evidence (violations and unreached cells)

### astro-docs @ 2025-06-18

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### bastle-bridge-legacy @ 2026-07-28

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### bastle-bridge-modern @ 2026-07-28

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### cloudflare-docs @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### coingecko @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### context7-remote @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### deepwiki @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### gitmcp-docs @ 2025-03-26

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)
- `B1.batch` MUST! — batch refused on the era that requires batching: HTTP 200, result

### gitmcp-mcp-repo @ 2025-03-26

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)
- `B1.batch` MUST! — batch refused on the era that requires batching: HTTP 200, result

### huggingface @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)
- `B1.batch` MUST! — batch ACCEPTED on an era that removed batching

### mslearn @ 2025-06-18

- `S1.session` MUST! — minted a session id but served tools/list without it
- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-arxiv @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-awsdocs @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-blender @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-calculator @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-ddg @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-excel @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-fetch @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-git @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-markitdown @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-sentry @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-sqlite @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### py-time @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-awskb @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-brave @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-everart @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-everything @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-filesystem @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-github @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-gitlab @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-gmaps @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-memory @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-postgres @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-puppeteer @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-seqthinking @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### ref-slack @ 2024-11-05

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-airbnb @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-context7 @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-context7-modern @ 2026-07-28

- `D1.discover` MUST! — serverInfo absent
- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)
- `V2.mismatch` MUST! — request naming an unsupported protocolVersion was SERVED
- `C1.cacheable` MUST! — tools/list result lacks CacheableResult fields (ttlMs=false cacheScope=false)
- `R1.resulttype` MUST! — H3.cold result lacks resultType:"complete"
- `I1.identity` unreached — no serverInfo to read

### tp-desktop-cmd @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-ea-playwright @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-exa @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-firecrawl @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-kubernetes @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-notion @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-playwright @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

### tp-tavily @ 2025-11-25

- `T2.badcursor` should! — invalid cursor ACCEPTED (spec SHOULD refuse with -32602)

---
Graded from 48 capture(s): astro-docs@2025-06-18.json, bastle-bridge-legacy@2026-07-28.json, bastle-bridge-modern@2026-07-28.json, bastle-okffacade@2026-07-28.json, cloudflare-docs@2025-11-25.json, coingecko@2025-11-25.json, context7-remote@2025-11-25.json, deepwiki@2025-11-25.json, gitmcp-docs@2025-03-26.json, gitmcp-mcp-repo@2025-03-26.json, huggingface@2025-11-25.json, mslearn@2025-06-18.json, py-arxiv@2025-11-25.json, py-awsdocs@2025-11-25.json, py-blender@2025-11-25.json, py-calculator@2025-11-25.json, py-ddg@2025-11-25.json, py-excel@2025-11-25.json, py-fetch@2025-11-25.json, py-git@2025-11-25.json, py-markitdown@2024-11-05.json, py-sentry@2025-11-25.json, py-sqlite@2025-11-25.json, py-time@2025-11-25.json, ref-awskb@2024-11-05.json, ref-brave@2024-11-05.json, ref-everart@2024-11-05.json, ref-everything@2025-11-25.json, ref-filesystem@2025-11-25.json, ref-github@2024-11-05.json, ref-gitlab@2024-11-05.json, ref-gmaps@2024-11-05.json, ref-memory@2025-11-25.json, ref-postgres@2024-11-05.json, ref-puppeteer@2024-11-05.json, ref-seqthinking@2025-11-25.json, ref-slack@2024-11-05.json, tp-airbnb@2025-11-25.json, tp-context7-modern@2026-07-28.json, tp-context7@2025-11-25.json, tp-desktop-cmd@2025-11-25.json, tp-ea-playwright@2025-11-25.json, tp-exa@2025-11-25.json, tp-firecrawl@2025-11-25.json, tp-kubernetes@2025-11-25.json, tp-notion@2025-11-25.json, tp-playwright@2025-11-25.json, tp-tavily@2025-11-25.json
