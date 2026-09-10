# Verification Report — MCP Filesystem Server v0.6.3

**Target:** `@modelcontextprotocol/server-filesystem` v0.6.3 — the official MCP
filesystem server (14 tools), source at `github.com/modelcontextprotocol/servers`.
**Method:** SkillProof methodology v1.0. **Verdict:** `pass_with_notes`.

## Headline numbers

| | |
|---|---|
| Total operations executed | **228** (3 seeds × 76) |
| Honest operations succeeded | 54 |
| Adversarial cases landed | **174** |
| Invariant violations | **0** |
| Anti-vacuity gate | **PASS** (every op accounted; minimums exceeded) |
| Signed manifest | `trust-manifest.json` (Ed25519, independently verified) |

**This suite fails if nothing actually executes.** The manifest's signed
payload includes the achieved minimums (54 honest successes, 174 adversarial
landings) — a manifest for an unexecuted skill is structurally unissuable.

## What was tested

A live server was driven over MCP stdio. The fixture placed a secret tree
(`/tmp/skillproof/secret`, containing a canary) outside the allowed directory,
plus hostile symlinks inside the allowed tree (a directory link and a file
link pointing at the secret) and one benign symlink (which had to keep
working — no false-positive breakage).

Adversarial battery per seed (58 cases): `..` traversal at multiple depths,
absolute outside paths, relative `../../` paths, symlink escapes (read, write,
list, search, move, stat through hostile links), `~/.ssh` home expansion,
null-byte paths, Windows-drive paths on POSIX, percent-encoded traversal,
`/etc/passwd` and `/proc/self/environ`, read/write/edit/mkdir/move variants,
mixed honest+secret batch reads, traversal and absolute search patterns,
dry-run and real edits of the secret file, moves in both directions and onto
an existing symlink.

## Invariants (all held)

- **INV-AUTH-1** — no operation succeeds on a canonically-outside path, on
  any of the 13 path-taking tools.
- **INV-AUTH-2** — `move_file` cannot cross the boundary either way;
  occupied destinations (including symlinks, via `lstat`) are rejected.
- **INV-DATA-1** — the canary never appeared in any response; the secret
  tree was bit-identical before and after; no boundary-crossing artifacts.
- **INV-DESC-1** — no tool description contains instruction-override markers;
  all 14 description hashes pinned.
- **INV-FAIL-1** — every probe ended in refusal or safe error; the server
  stayed responsive; the benign symlink kept working.

## Debunked during the run (harness bugs, not server bugs)

Four initial flags were investigated and cleared: the server correctly
returns per-file "Access denied" entries in mixed batch reads (no leakage),
traversal search patterns correctly return "No matches found", and the honest
search expectation needed a `**/*.txt` glob. One adversarial "success" was a
trailing-slash normalization to an in-bounds file — correct behavior. Each
was fixed in the harness and the battery re-run green, rather than counted.

## Notes

- **Residual (info, open):** a theoretical TOCTOU window between path
  validation and file use — not demonstrated, requires a concurrent local
  attacker. Writes already use atomic rename + exclusive creation to narrow
  it. Recorded in the manifest rather than hidden.
- **Out of scope:** model-level prompt-injection resistance of any connected
  LLM; the host OS permission model; replay (stateless tools).
- This was a clean verification, not a bug hunt outcome: the server is
  genuinely well-hardened (symlink realpath checks, atomic writes, `lstat`
  destination checks). The value demonstrated is *proof of execution*, not a
  finding — which is exactly what the manifest sells.

## Reproduce

```bash
# 1. build the target (from modelcontextprotocol/servers, src/filesystem)
npm install --legacy-peer-deps && npm run build
# 2. run the battery (3 seeds, ~76 ops each)
node harness/driver.mjs
# 3. issue + verify the manifest
node harness/issue-manifest.mjs
```

## Files

- `trust-manifest.json` — the signed Trust Manifest (schema v1.0)
- `harness/driver.mjs` — the adversarial driver (re-runnable)
- `harness/issue-manifest.mjs` — manifest issuance + Ed25519 signing
- `harness/report.json` — raw per-seed results
- `harness/verifier-public-key.hex` — issuance key (demo key, not a root of trust)
