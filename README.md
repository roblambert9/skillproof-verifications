# SkillProof public verifications

Behavioral verification of MCP servers: we execute the skill adversarially and issue a signed Trust Manifest. Scanners guess — we prove.

- **demo-filesystem/** — verification #01: official `@modelcontextprotocol/server-filesystem` v0.6.3. 228 ops, 174 adversarial, 0 violations. Verdict: `pass_with_notes`.
- **demo-fetch/** — verification #02: official `mcp-server-fetch` v0.6.3. 63 ops, 48 adversarial, 0 violations — with a demonstrated SSRF-via-redirect finding. Verdict: `pass_with_notes`.

Each demo re-runs end to end: `./setup-and-run.sh` (fetches the pinned upstream commit, builds, runs the battery, issues the manifest).
