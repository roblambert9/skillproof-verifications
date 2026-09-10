# SkillProof public verifications

Behavioral verification of MCP servers: we execute the skill adversarially and issue a signed Ed25519 Trust Manifest. Scanners guess — we prove.

**Corpus: 4 of 5 official MCP servers FAIL.** The one that passed is documented too — execution exonerates as well as condemns.

| # | Target | Ops | Adversarial | Verdict | Location |
|---|--------|-----|-------------|---------|----------|
| 01 | `@modelcontextprotocol/server-filesystem` v0.6.3 | 228 | 174 | ✅ `pass_with_notes` | `demo-filesystem/` |
| 02 | `mcp-server-fetch` v0.6.3 *(self-corrected)* | 63 | 48 | ❌ `fail` | `demo-fetch/` |
| 03 | `@modelcontextprotocol/server-postgres` v0.6.2 | 96 | 78 | ❌ `fail` | `demo-postgres/` |
| 04 | `@modelcontextprotocol/server-sqlite` v0.6.2 | 81 | 60 | ❌ `fail` | `demo-sqlite/` |
| 07 | `@modelcontextprotocol/server-memory` v0.6.2 | 81 | 51 | ❌ `fail` | `demo-memory/` |

### On the self-correction (#02)

Verification #02 (fetch server) was initially issued as `pass_with_notes`. The battery correctly found the SSRF finding — but our verdict driver computed the verdict from per-operation violations only, ignoring invariant `not_held` status. After we discovered the bug we re-ran the full 63-op battery against the pinned commit, fixed the driver, and **re-issued the manifest as `fail`**. The original superseded manifest and correction log are in `demo-fetch/RESULTS.md`. We downgraded our own verdict publicly.

A verification service that publicly downgrades its own verdict is one you can trust with yours.

---

## Folders

- **demo-filesystem/** — #01: official filesystem server. All 5 confinement invariants held. `pass_with_notes`.
- **demo-fetch/** — #02 (corrected): official fetch server. SSRF via 302 redirect demonstrated; loopback fetched. `fail`.
- **demo-postgres/** — #03: official postgres server. Read-only SQL transaction escape demonstrated. `fail`.
- **demo-sqlite/** — #04: official sqlite server. Arbitrary file-write primitive via `VACUUM INTO`. `fail`.
- **demo-memory/** — #07: official memory server. `create_relations` accepts dangling references to nonexistent entities. `fail`.
- **a2a-interface/** — Machine-readable service descriptor + JSON schemas + reference HTTP service so agents can discover, request, and pay for verification programmatically. See `a2a-interface/README.md`.
- **scoreboard-gate/** — Zero-dependency GitHub Action + local CLI for CI pipelines. Blocks builds on tampered, expired, or FAIL manifests. 7/7 tests green.
- **protocol/** — Trust Protocol v1 client (`trust-gate.mjs`). Agents verify tool manifests at runtime before invocation (enforce/warn/audit modes). 7/7 tests green.
- **warranty/** — SkillProof Warranty policy: 10x fee payouts backing PASS manifests.
- **leaderboard.html** & **leaderboard.json** — Public living scorecard and machine-readable feed of evaluated MCP servers.

Each verification re-runs end to end:

```bash
node harness/verify-manifest.mjs # standalone Ed25519 check (no network needed)
```

---

## Pending (waiting on credentials — not agent-executable)

- **#05 GitHub MCP** — needs `GITHUB_TOKEN`
- **#06 Slack MCP** — needs `SLACK_BOT_TOKEN`

---

*Services: Sprint \$500 / Standard \$1,500 / Continuous \$300/mo. Don't trust the badge — re-run the harness.*
