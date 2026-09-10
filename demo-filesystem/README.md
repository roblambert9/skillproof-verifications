# Demo: first SkillProof Trust Manifest

This directory is the public proof that the SkillProof methodology executes
for real: a full adversarial verification of the **official MCP filesystem
server** (`@modelcontextprotocol/server-filesystem` v0.6.3, 14 tools),
with a **signed, machine-readable Trust Manifest** as the output.

## What this proves

- 228 operations executed against a live server (3 seeds): 54 honest, **174
  adversarial** — traversal, symlink escape, null bytes, home expansion,
  cross-boundary moves, batch exfiltration probes.
- 5 behavioral invariants held, 0 violations. One residual risk named openly.
- The manifest is Ed25519-signed over a canonical payload that includes the
  achieved execution minimums — **it cannot be issued for a skill that was
  never executed.**

## For agents (machine-readable)

`trust-manifest.json` conforms to `../trust-manifest.schema.json`. Verify the
signature offline with `../harness/verifier-public-key.hex`
(`harness/verifier-public-key.hex` here); check `validity.revoked` and that
`subject.code_hash` matches the artifact you intend to install.

## For humans

Read `RESULTS.md` — headline numbers, the adversarial battery, the four
flags that were debunked as harness bugs (not server bugs), and the residual
TOCTOU note.

## Reproduce it yourself

```bash
node harness/driver.mjs          # re-runs the full battery
node harness/issue-manifest.mjs  # re-issues the signed manifest
```

That's the whole pitch: don't trust the badge — re-run the harness.
