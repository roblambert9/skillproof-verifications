# SkillProof verification #07 — `@modelcontextprotocol/server-memory` v0.6.2

**Target:** `@modelcontextprotocol/server-memory` 0.6.2 — the official MCP
memory server (TypeScript), source
`https://github.com/modelcontextprotocol/servers` (`src/memory`), pinned
commit `94a36286d2ea49d095704167846283f0c2c2d5d1` (tag
`typescript-servers-0.6.2`).

**Method:** live adversarial execution over MCP stdio against the
file-backed knowledge graph (`memory.json`, deleted fresh per seed).
Battery: 3 seeds × 27 ops (10 honest + 17 adversarial), shuffled per seed,
integrity snapshots before/after.

**Status:** see RESULTS.md for the executed verdict (`fail`: dangling
relations accepted; order-dependent input validation).

## Files

- `INVARIANTS.md` — the five invariants, defined *before* execution, with
  pre-registered severity guidance and verdict scale.
- `RESULTS.md` — executed battery, findings, debunk log.
- `trust-manifest.json` — signed Ed25519 Trust Manifest (verdict + findings
  + code hash of the pinned source).
- `harness/verifier-public-key.hex` — issuer public key for standalone
  verification.
- `harness/driver.mjs` — the adversarial battery (3 seeds × 27 ops).
- `harness/mcp-stdio.js` — target-agnostic MCP stdio client (shared).
- `harness/adapters/db-memory.js` — fixture lifecycle + snapshots
  (memory.json hash, JSONL line-count invariant, dist-dir listing).
- `harness/issue-manifest.mjs` — opt-in manifest issuance (refuses unless
  the battery ran and the vacuity gate passed).
- `harness/verify-manifest.mjs` — standalone signature check.
- `setup-and-run.sh` — fresh-machine flow.

## Reproduce

```bash
./setup-and-run.sh   # fetch pinned commit -> npm install+build -> battery -> manifest
node harness/verify-manifest.mjs   # standalone signature check
```

Build note: the package's `prepare` hook runs `tsc`, which needs the repo
root `tsconfig.json` — the sparse checkout includes it, and setup builds
with `npm install --ignore-scripts` + `npm run build` explicitly for a
deterministic build.

## Headline finding

`create_relations` persists relations between entities that do not exist
(medium, INV4). Everything else adversarial — traversal content, newline /
JSON-forgery injection, hostile `__proto__`/RTL strings, corrupt backing
file, malformed inputs — was contained or failed closed.
