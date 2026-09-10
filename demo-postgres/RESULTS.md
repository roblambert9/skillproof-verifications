# SkillProof verification #03 — RESULTS (executed)

**Target:** `@modelcontextprotocol/server-postgres` v0.6.2 (official MCP postgres server)
**Commit:** `94a36286d2ea49d095704167846283f0c2c2d5d1`
**Verdict: `fail`**

## Battery Summary
- **96 operations**: 3 seeds × 32 ops (18 honest + 78 adversarial landed)
- **Anti-vacuity: PASS**
- **Invariants held**: 3 of 5
- **Invariants failed**: 2 of 5 (INV1, INV2)

## Findings

### HIGH — Read-only transaction escape via multi-statement queries (INV1, INV2)
The tool advertises "run a read-only SQL query." The server issues `BEGIN TRANSACTION READ ONLY`, but passes caller SQL verbatim to `client.query()`. Because `node-postgres` supports stacked statements:
```sql
SELECT 1; COMMIT; INSERT INTO items(name) VALUES('escape6b');
```
The `COMMIT` ends the read-only transaction, and the stacked `INSERT` executes under autocommit. The row persisted across all 3 seeds. Server-enforced read-only safety does not exist; safety is entirely dependent on database-level grants.
