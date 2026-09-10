# SkillProof verification #07 — invariants (defined BEFORE execution)

**Target:** `@modelcontextprotocol/server-memory` 0.6.2 — the official MCP
memory server (TypeScript), source
`https://github.com/modelcontextprotocol/servers` (`src/memory`), pinned
commit `94a36286d2ea49d095704167846283f0c2c2d5d1` (tag
`typescript-servers-0.6.2`).

**Tool surface under test** (from `index.ts`, `ListToolsRequestSchema`
handler — verified live via `tools/list` before writing the battery):

| Tool | Advertised description |
|------|------------------------|
| `create_entities` | "Create multiple new entities in the knowledge graph" |
| `create_relations` | "Create multiple new relations between entities in the knowledge graph. Relations should be in active voice" |
| `add_observations` | "Add new observations to existing entities in the knowledge graph" |
| `delete_entities` | "Delete multiple entities and their associated relations from the knowledge graph" |
| `delete_observations` | "Delete specific observations from entities in the knowledge graph" |
| `delete_relations` | "Delete multiple relations from the knowledge graph" |
| `read_graph` | "Read the entire knowledge graph" |
| `search_nodes` | "Search for nodes in the knowledge graph based on a query" |
| `open_nodes` | "Open specific nodes in the knowledge graph by their names" |

Implementation notes (source, to be confirmed/refuted by execution):
the graph is file-backed at a **fixed** path
`MEMORY_FILE_PATH = path.join(__dirname, 'memory.json')` — no tool accepts
a path. `saveGraph` rewrites the whole file as one-JSON-object-per-line;
`loadGraph` returns an empty graph on ENOENT and throws on corrupt JSON.
Entity matching is exact, case-sensitive string equality. `create_relations`
does **not** check that endpoints exist. `add_observations` throws on a
missing entity; `delete_observations` silently succeeds on one.

**Fixture:** none needed — `memory.json` is deleted at the start of every
seed (fresh empty graph). Honest ops are self-contained (create their own
per-op entities) so the shuffled battery order is safe.

### INV1 — entity/relation isolation (class: authorization)

Adversarial input must not leak or corrupt unrelated entities or relations:
deleting entity `isoA` leaves prefix-sibling `isoAX` byte-identical;
`delete_observations` on `isoB` leaves `isoC`'s observations untouched;
observations added to `CaseX_a1` never appear on case-differing `casex_a1`.

### INV2 — file-path confinement (class: data_flow)

No tool writes outside the fixed `memory.json`: entity names and observation
content containing `../`, `../../evil.txt`, embedded newlines, and forged
JSONL lines are data, never paths. The `dist/` directory listing (minus
`memory.json` itself) is unchanged across the battery, no stray files
appear, and `memory.json` stays valid JSONL with exactly one line per
entity/relation.

### INV3 — injection persistence (class: injection)

Hostile observation content (embedded `\n`, a literal
`{"type":"entity",...}` line, `__proto__`, RTL override `a\u202Eb`,
`<script>` markup, traversal text) and hostile `relationType` strings are
stored and retrieved **verbatim** — and must not materialize phantom graph
objects (no `forged` entity appears; the file keeps one-line-per-object
structure).

### INV4 — description fidelity (class: description_fidelity)

`read_graph` / `search_nodes` / `open_nodes` are advertised as reads: the
`memory.json` byte-hash is identical before and after they run. Relations
are advertised as being *between entities*: `create_relations` with
nonexistent endpoints must not persist a dangling relation. A
`delete_relations` call with a wrong `relationType` must be a no-op.

### INV5 — fail-closed (class: fail_closed)

Malformed inputs — missing `entities` arg, `add_observations` on a missing
entity, non-string `search_nodes` query, unknown tool — fail closed with
errors, never hangs or silent success. A corrupted `memory.json` makes every
tool error (no partial state) while the server stays alive, and the graph
recovers after the file is repaired. The server answers `tools/list` after
the last op of every seed.

## Pre-registered severity guidance

- **high** — code execution via content; any write outside `memory.json`.
- **medium** — referential-integrity breaks (dangling relations persisted);
  read-path mutation; forged graph objects materializing from content.
- **info** — silent no-ops, dedup behavior, fail-closed asymmetries,
  validation inconsistencies with no demonstrated harmful effect.

## Verdict scale (decided up front)

- `pass` — every invariant held, no finding above info.
- `pass_with_notes` — all invariants held but ≥1 info-level finding.
- `fail` — **any invariant `not_held`. No exceptions.**

## Anti-vacuity minimums for this battery

- ≥10 honest successes (battery provides 10 honest ops × 3 seeds = 30).
- Every adversarial case (17 × 3 seeds = 51) produces an *observed* server
  verdict (`success` / `error` / `timeout`) — driver-side spawn failures do
  not count as landings and are reported separately.
- Server alive at end of battery (`tools/list` succeeds after the last op).
- Integrity snapshots (byte-hash of `memory.json`, entity/relation counts,
  JSONL line-count invariant) taken before the first op and after the last,
  per seed; fixture file deleted at the start of every seed.
