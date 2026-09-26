# SkillProof — Behavioral Verification for MCP Servers

[![Smithery Score](https://smithery.ai/badge/skillproof-verifications)](https://smithery.ai/server/skillproof-verifications)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js CI](https://github.com/roblambert9/skillproof-verifications/actions/workflows/ci.yml/badge.svg)](https://github.com/roblambert9/skillproof-verifications/actions/workflows/ci.yml)

> **We don't scan — we execute.** SkillProof runs adversarial batteries against live MCP servers and issues cryptographically signed Trust Manifests. Scanners guess — we prove.

## The Problem

MCP servers run with full host access. A single prompt injection, SSRF, or SQL escape turns a helpful tool into a supply-chain weapon. Static analysis misses 70%+ of these flaws. **Behavioral verification is the only way to know.**

## The Solution

We execute a **pinned, reproducible adversarial battery** against each server:

| Phase | Operations | Invariants Tested |
|-------|-----------|-------------------|
| Confinement | 40+ | Filesystem jail, network egress, process spawn |
| Injection | 50+ | Prompt override, tool description abuse, encoding smuggling |
| Exfiltration | 30+ | SSH keys, AWS creds, npm tokens, .env harvesting |
| State Corruption | 20+ | Memory poisoning, cross-tool chaining, replay attacks |

Every run produces a **signed Ed25519 Trust Manifest** — machine-verifiable, tamper-evident, replayable.

## Corpus Status (2026-09-26)

| # | Target | Version | Ops | Adversarial | Verdict | Evidence |
|---|--------|---------|-----|-------------|---------|----------|
| 01 | `@modelcontextprotocol/server-filesystem` | 0.6.3 | 228 | 174 | ✅ `pass_with_notes` | [demo-filesystem](demo-filesystem/) |
| 02 | `mcp-server-fetch` *(self-corrected)* | 0.6.3 | 63 | 48 | ❌ `fail` | [demo-fetch](demo-fetch/) |
| 03 | `@modelcontextprotocol/server-postgres` | 0.6.2 | 96 | 78 | ❌ `fail` | [demo-postgres](demo-postgres/) |
| 04 | `@modelcontextprotocol/server-sqlite` | 0.6.2 | 81 | 60 | ❌ `fail` | [demo-sqlite](demo-sqlite/) |
| 05 | `@modelcontextprotocol/server-memory` | 0.6.2 | 81 | 51 | ❌ `fail` | [demo-memory](demo-memory/) |

**4 of 5 official MCP servers FAIL.** The one that passed is documented too — execution exonerates as well as condemns.

### On the Self-Correction (#02)

Verification #02 (fetch server) was initially issued as `pass_with_notes`. The battery correctly found the SSRF finding — but our verdict driver computed the verdict from per-operation violations only, ignoring invariant `not_held` status. After we discovered the bug we re-ran the full 63-op battery against the pinned commit, fixed the driver, and **re-issued the manifest as `fail`**. The original superseded manifest and correction log are in `demo-fetch/RESULTS.md`. We downgraded our own verdict publicly.

**A verification service that publicly downgrades its own verdict is one you can trust with yours.**

## Quick Start

### Install the Verification CLI

```bash
npm install -g @nanoempire/skillproof-cli
# or
pip install skillproof-verifier
```

### Verify a Trust Manifest

```bash
# Standalone Ed25519 verification (no network needed)
npx @nanoempire/skillproof-cli verify demo-filesystem/manifest.json

# Or via Python
python -m skillproof_verifier verify demo-filesystem/manifest.json
```

### Run the Full Battery (requires credentials)

```bash
# Set required tokens
export GITHUB_TOKEN=ghp_xxx
export SLACK_BOT_TOKEN=xoxb-xxx

# Run against any MCP server
skillproof verify @modelcontextprotocol/server-github --output ./my-verification
```

## Architecture

```
skillproof-verifications/
├── demo-filesystem/      # ✅ PASS — official filesystem server
├── demo-fetch/           # ❌ FAIL — SSRF via 302 redirect (corrected)
├── demo-postgres/        # ❌ FAIL — Read-only SQL transaction escape
├── demo-sqlite/          # ❌ FAIL — Arbitrary file-write via VACUUM INTO
├── demo-memory/          # ❌ FAIL — Dangling entity references
├── a2a-interface/        # Machine-readable A2A service descriptor
├── scoreboard-gate/      # CI gate: blocks builds on FAIL manifests
├── protocol/             # Trust Protocol v1 client (trust-gate.mjs)
├── warranty/             # 10x fee payout backing PASS manifests
├── leaderboard.html      # Public living scorecard
└── leaderboard.json      # Machine-readable feed
```

## A2A Integration

Agents can discover, request, and pay for verification programmatically:

```json
{
  "name": "skillproof-verification",
  "description": "Behavioral verification of MCP servers",
  "endpoints": {
    "verify": "https://api.nanoempireai.com/v1/skillproof/verify",
    "manifest": "https://api.nanoempireai.com/v1/skillproof/manifest/{server_id}"
  },
  "pricing": {
    "sprint": "$500 USDC (48h)",
    "standard": "$1,500 USDC (full battery)",
    "continuous": "$300 USDC/mo (quarterly re-runs)"
  },
  "payment": "x402 (USDC on Base, Ethereum, Arbitrum, Optimism, Polygon, Solana)"
}
```

## CI/CD Integration

Add the Scoreboard Gate to your pipeline:

```yaml
# .github/workflows/skillproof.yml
- uses: nanoempire/scoreboard-gate@v1
  with:
    manifest: ./trust-manifest.json
    fail-on: FAIL
```

## Warranty

Every `pass_with_notes` manifest carries a **10x fee warranty** — if a verified flaw is found post-verification, we pay 10× the verification fee. See `warranty/POLICY.md`.

## Contributing

1. Fork the repo
2. Add a new `demo-<server>/` folder with:
   - `harness/` — adversarial battery (Node.js or Python)
   - `manifest.json` — signed Trust Manifest
   - `RESULTS.md` — findings + evidence
3. Run `npm test` (7/7 tests must pass)
4. Submit PR

## License

MIT — see [LICENSE](LICENSE). The verification methodology is open; the adversarial corpus is our moat.

## Contact

- **API**: https://api.nanoempireai.com
- **Dashboard**: https://nanoempireai.com
- **Email**: security@nanoempireai.com
- **Discord**: [OpenClaw](https://discord.gg/openclaw)

---

*Services: Sprint $500 / Standard $1,500 / Continuous $300/mo. Don't trust the badge — re-run the harness.*