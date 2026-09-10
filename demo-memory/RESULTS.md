# SkillProof verification #07 — RESULTS (executed)

**Target:** `@modelcontextprotocol/server-memory` 0.6.2 (official MCP
memory server, TypeScript), pinned commit
`94a36286d2ea49d095704167846283f0c2c2d5d1`.
**Executed:** 2026-09-10. **Verdict: `fail`.**

## Battery

- **81 operations**: 3 seeds × 27 ops (10 honest + 17 adversarial), shuffled
  per seed. `memory.json` deleted at the start of every seed (fresh empty
  graph); honest ops are self-contained (per-op fixture entities) so shuffle
  order is safe. Integrity snapshots (byte-hash of `memory.json`,
  entity/relation counts, JSONL line-count invariant) before/after each seed.
- **30/30 honest successes**, **51/51 adversarial landed** (every case
  produced an observed server verdict), server alive after every seed.
- **Anti-vacuity: PASS.**

## Invariants

| ID | Statement | Status |
|----|-----------|--------|
| INV1 | adversarial input never leaks or corrupts unrelated entities/relations | **held** |
| INV2 | no tool writes outside the fixed memory.json; hostile name/content is data, never a path | **held** |
| INV3 | hostile observation/relation content stored and retrieved verbatim without altering graph semantics | **held** |
| INV4 | read-only tools never mutate state; relations require existing endpoints per the advertised description | **not_held** |
| INV5 | malformed inputs fail closed; server stays alive; corrupt backing file errors then recovers | **not_held** |

## Findings

### MEDIUM — `create_relations` accepts relations between nonexistent entities (INV4)

`create_relations` with `{from: "dangleA", to: "dangleB",
relationType: "haunts"}` — where neither `dangleA` nor `dangleB` exists —
returned **success** and the relation persisted in `read_graph` on **all
three seeds**, while `open_nodes` confirmed neither endpoint exists. The
tool is described as "Create multiple new relations between entities in the
knowledge graph" but enforces no referential integrity: a client reading the
graph receives relations pointing at nothing. Any agent reasoning over graph
structure (traversal, join, provenance) cannot trust that a relation's
endpoints exist. Mitigation: reject relations whose `from`/`to` do not match
existing entities, or document that dangling relations are permitted.

### What held (verified, not assumed)

- **INV1**: deleting `isoA` left prefix-sibling `isoAX` byte-identical;
  `delete_observations` on `isoB` left `isoC`'s observations untouched;
  observations added to `CaseX_a1` never appeared on `casex_a1`. Exact,
  case-sensitive name matching is genuinely isolating — on all 3 seeds.
- **INV2**: entity names and observation content containing `../`,
  `../../evil.txt`, embedded newlines, and a literal forged
  `{"type":"entity",...}` line produced **zero** stray files; the `dist/`
  directory listing (minus `memory.json` itself) was unchanged;
  `memory.json` stayed valid JSONL with exactly one line per entity/relation
  (A04, A05, all seeds). The fixed-path design is real confinement.
- **INV3**: hostile strings — embedded `\n`, forged JSONL line, `__proto__`,
  RTL override, `<script>` markup, traversal text — round-tripped
  **verbatim** through `open_nodes`, and a hostile `relationType` round-tripped
  verbatim too. No `forged` entity materialized; the file's one-line-per-object
  structure held (A06, A07, all seeds). `JSON.stringify` per line is doing
  the work; there is no injection surface here.
- **INV4 (partial)**: `read_graph` / `search_nodes` / `open_nodes` never
  mutated `memory.json` — byte-hash identical before/after on all seeds
  (A08). `delete_relations` with a wrong `relationType` was a true no-op
  (A10).
- **INV5 (mostly)**: missing `entities` arg, `add_observations` on a missing
  entity, and unknown tools all errored on every seed; corrupt `memory.json`
  made every tool error with no partial state while the server stayed alive,
  and the graph fully recovered after the file was repaired (A12, A13, A15,
  A16, all seeds).

### Info notes

- **`search_nodes` input-type validation is order-dependent** (INV5): a
  numeric query errored on 2 seeds (`query.toLowerCase is not a function`)
  but returned **success with an empty graph** on the third — because that
  seed's shuffle ran the file-deletion probe (A17) first, leaving an empty
  graph, and `[].filter(...)` never invokes the callback, masking the
  TypeError. Reproduced in isolation. No corruption or crash either way —
  inconsistent validation, not an escape. (This is why INV5 is `not_held`
  despite otherwise clean fail-closed behavior.)
- `delete_observations` on a nonexistent entity **silently succeeds**
  ("Observations deleted successfully"), while `add_observations` on the
  same missing entity errors. Asymmetric — silent success hides caller
  mistakes.
- A deleted `memory.json` **silently resets the graph to empty**: with the
  file absent, `read_graph` returns an empty graph with success — the server
  cannot distinguish first-run from total data loss. No integrity check,
  backup, or warning.
- `create_entities` **silently skips duplicate names** (returns success with
  an empty created list). Idempotent, not a vulnerability — but callers
  should not assume the entity was (re)created.
- No instruction-override markers in tool descriptions.

## Debunk log

1. **First full run flagged INV2/INV3/INV5 as not_held — three of the four
   flags were harness bugs.** (a) The result-text slice was 2000 chars:
   `read_graph` on a populated graph exceeds that, so `JSON.parse` failed
   and H10/A07/A10 evaluated against `null` (A10's `noop` became `undefined`,
   serialized as `{}`). Raised the slice to 20000 and switched A07/A10 to
   targeted `open_nodes` reads. (b) A04's directory-diff compared listings
   including `memory.json` itself — on seed 11 this op happened to be the
   first write of the seed, so the expected fixture creation read as a
   confinement break. The diff now excludes `memory.json`. (c) A14's
   seed-22 "silent success" survived re-examination: reproduced in isolation
   as genuine order-dependent server behavior (empty-graph filter masking),
   kept as a real info finding — the debunk that confirmed rather than
   killed a flag.
2. **Tool-description truncation in early probes** misled one research
   reading of `open_nodes` with a string `names` arg; the battery asserts
   against parsed structures, not substrings, so this class of mistake
   cannot recur in the evaluated results.
3. **`/tmp` shared-checkout note:** the working repo at `/tmp/mcp-target-memory`
   showed an expanded sparse checkout (other servers' dirs present) that no
   command in this verification issued — likely a sibling process on this
   shared VM. `git status` showed no modifications to the hashed files and
   `git rev-parse HEAD` still returns the pinned commit; the manifest code
   hash covers the three pinned files only. `setup-and-run.sh` uses its own
   clean target directory and is unaffected.

## Reproduce

```bash
./setup-and-run.sh              # fetch pinned commit -> npm install+build -> battery -> manifest
node harness/verify-manifest.mjs  # standalone Ed25519 check
```

Tool-description SHA-256: pinned in the manifest (`subject.tools[].description_hash`).
