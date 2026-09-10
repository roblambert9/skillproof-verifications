# SkillProof Verification #04 — SQLite MCP Server

Behavioral verification of official `@modelcontextprotocol/server-sqlite` v0.6.2.
Verdict: **FAIL** (Arbitrary file-write primitive via `VACUUM INTO` and unconstrained write permissions).

See `RESULTS.md` for full test details and `trust-manifest.json` for the signed manifest.
