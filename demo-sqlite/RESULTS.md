# SkillProof verification #04 — RESULTS (executed)

**Target:** `@modelcontextprotocol/server-sqlite` v0.6.2 (official MCP SQLite server)
**Commit:** `94a36286d2ea49d095704167846283f0c2c2d5d1`
**Verdict: `fail`**

## Battery Summary
- **81 operations**: 3 seeds × 27 ops (21 honest + 60 adversarial landed)
- **Anti-vacuity: PASS**
- **Invariants held**: 3 of 5
- **Invariants failed**: 2 of 5 (INV1, INV2)

## Findings

### HIGH — Arbitrary file-write primitive via `VACUUM INTO` (INV1)
`VACUUM INTO '/path/...'` executed through `write-query` creates a complete SQLite database copy at any filesystem location writeable by the process. Demonstrated across all 3 seeds. An unrestricted file-write primitive exists behind the query execution tool.

### MEDIUM — Non-INSERT/UPDATE/DELETE queries allowed (INV2)
`write-query` advertises INSERT/UPDATE/DELETE queries only. Enforcement consists purely of checking that the query does not start with SELECT. Queries such as `DROP TABLE`, `ALTER TABLE`, and `PRAGMA` execute unconditionally.
