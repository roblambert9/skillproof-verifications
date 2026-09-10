# Trust Protocol — reference implementation

`trust-gate.mjs` enforces SkillProof Trust Manifests at the agent runtime layer: verify before you call.

## Install
Copy `trust-gate.mjs` into your project. Zero dependencies, Node 20+.

## Quick start
```js
import { guardedCall } from './trust-gate.mjs';

const result = await guardedCall({
  manifestUrl: 'https://example.com/trust-manifest.json',
  policy: { mode: 'enforce', requireVerdict: 'pass_with_notes' },
  call: (tool, args) => client.callTool(tool, args),
  tool: 'write_query',
  args: { sql: "SELECT 1" },
});
```

## API
- `guardedCall({ manifestUrl, policy, call, tool, args })` — main entry.
- `fetchManifest(url, { cacheTtlMs })` — fetch with in-memory cache.
- `verifyManifest(manifest)` → `{ ok, reason }` — signature, revocation, expiry.
- `evaluatePolicy(manifest, policy)` → `{ allowed, reason }` — verdict floor + hash pin.
- `clearCache()` — drop the manifest cache.

## Policy fields
- `mode`: `enforce` | `warn` | `audit` (default `enforce`)
- `requireVerdict`: `pass` | `pass_with_notes` (default `pass_with_notes`)
- `expectedCodeHash`: e.g. `sha256:abc123` (optional)
- `cacheTtlMs`: manifest cache TTL (default 3600000)

## Tests
```bash
node test.mjs   # 7 assertions, all green
```

See `TRUST_PROTOCOL.md` for the full spec.
