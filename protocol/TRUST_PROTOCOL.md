# SkillProof Trust Protocol v1 — agents check trust before calling tools

## Actors
- **Verifier** (SkillProof): issues signed manifests.
- **Publisher**: hosts `trust-manifest.json` next to the skill.
- **Agent runtime**: enforces policy before tool invocation.
- **Registry/marketplace**: displays verdicts, distributes manifests.

## Manifest resolution (in order)
1. Tool annotation: the tool description or metadata carries `skillproof_manifest_url`.
2. Well-known: `GET {skill_base_url}/.well-known/skillproof.json` → `{ "trust_manifest": "https://..." }`.
3. Registry lookup: marketplace API by `skill_id` + `version`.

## Enforcement flow (agent runtime)
```
before tool_call(tool, args):
  manifest_url = resolve(tool)
  manifest = fetch_manifest(manifest_url)        # cached, TTL 1h default
  verify_ed25519(manifest)                       # fail closed on bad signature
  check revocation + expiry
  evaluate policy:
    verdict >= require_verdict (default pass_with_notes)
    code_hash == pinned hash (if pinned)
  allow | warn-and-continue | refuse
  log receipt { tool, manifest_url, verdict, decision, timestamp }
```

## Policy modes
- **enforce** (default for production): refuse on any trust failure. Fail closed if the manifest can't be fetched.
- **warn**: log and continue. For staging.
- **audit**: log only, always continue. For dry-runs and measurement.

## Reference implementation
`trust-gate.mjs` — zero-dependency Node 20+ module. Drop it in front of any MCP client:

```js
import { guardedCall } from './trust-gate.mjs';
const result = await guardedCall({
  manifestUrl: 'https://example.com/trust-manifest.json',
  policy: { mode: 'enforce', requireVerdict: 'pass', expectedCodeHash: 'sha256:abc123' },
  call: (tool, args) => mcpClient.callTool(tool, args),
  tool: 'read_query',
  args: { sql: 'SELECT 1' },
});
```

## Caching & revocation
- Manifests cached up to `cacheTtlMs` (default 1h); revocation is checked on each fresh fetch.
- For high-security deployments set TTL to 5 minutes; the manifest is small.

## Receipts
Every decision logs a signed receipt. In a dispute, the receipt + manifest + reproducer reconstruct exactly what the agent was allowed to do — this is the accountability layer enterprises and insurers need.

## Roadmap
- v1: this spec + reference client (done).
- v2: revocation feed (`/v1/revocations`), registry-signed manifests.
- v3: metered trust-checks via Tollbooth (`POST /v1/trust-check`), already spec'd in the Verified Pipeline.
