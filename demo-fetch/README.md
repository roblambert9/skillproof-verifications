# SkillProof demo #02 — adversarial verification of `mcp-server-fetch`

Second public Trust Manifest verification. Target: the official MCP fetch
server (`mcp-server-fetch` v0.6.3, Python) — the tool that gives agents
internet access.

**Headline:** 63 operations, 48 adversarial cases landed, 0 invariant
violations — and one demonstrated SSRF mechanism: the server followed a 302
redirect to a loopback canary and fetched it. Scanners can't find that;
execution did.

## Layout

- `RESULTS.md` — what was tested, invariants, findings
- `trust-manifest.json` — the signed Trust Manifest (Ed25519)
- `harness/driver.mjs` — the adversarial battery (spawns the real server over MCP stdio)
- `harness/test-servers.py` — deterministic local test servers (canary, redirector, robots-deny, honest)
- `harness/issue-manifest.mjs` — manifest issuance + signing
- `harness/report.json` — raw per-operation results
- `harness/verifier-public-key.hex` — issuer public key for independent verification
- `setup-and-run.sh` — one-command fresh-machine reproduction

## Reproduce

```bash
./setup-and-run.sh
```

Requires: git, python3 (venv), node, internet access.
