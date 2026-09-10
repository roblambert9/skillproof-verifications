# SkillProof Gate

A zero-dependency GitHub Action (Node 20) that verifies a SkillProof Trust Manifest in CI and fails the run if the skill regressed.

## What it checks
1. Fetches `trust-manifest.json` and verifies the **Ed25519 signature** over canonical JSON — tampering fails the build.
2. Enforces a **verdict floor** (`pass` or `pass_with_notes`, default `pass_with_notes`).
3. Rejects **revoked** or **expired** manifests.
4. Optionally pins the **code hash** so a dependency bump without re-verification fails.

## Usage
```yaml
- uses: skillproof/gate@v1
  with:
    manifest_url: https://example.com/trust-manifest.json
    require_verdict: pass_with_notes
    expected_code_hash: sha256:94a36286d2ea49d095704167846283f0c2c2d5d1
```

## Local / any CI
```bash
node gate.mjs --manifest-url https://example.com/trust-manifest.json \
  --require-verdict pass_with_notes \
  --expected-code-hash sha256:94a36286d2ea49d095704167846283f0c2c2d5d1
```

## Why
Scanners guess, we prove. The Gate turns proof into infrastructure: a dependency bump that breaks a safety invariant cannot ship.
