# SkillProof A2A — machine-to-machine verification requests

Reference implementation. Lets **agents** (not humans reading PDFs) discover the
SkillProof service, get a fixed-fee quote, open a verification job, and later
fetch + offline-verify the signed Trust Manifest. This is the "paying machines"
revenue line: agents buying verification for the skills they depend on.

Zero dependencies. Plain `node:http`. Node ≥ 18.

## Run it locally

```bash
cd skillproof-a2a-interface
node server.js        # listens on http://localhost:8787 (PORT to change)
node test.js          # exercises every endpoint, asserts the quote math
```

Expected: `ALL TESTS PASSED` (46 assertions). The server self-checks that the
descriptor tier table matches the quote math in `server.js` on startup and
refuses to boot if they drift.

## The 3-step agent flow

### 1. DISCOVER — fetch the service descriptor

```bash
curl http://localhost:8787/.well-known/skillproof.json
```

Returns capabilities, the tier table (prices + SLAs), supported targets
(MCP servers over stdio/http/sse, skill packs), the verification-method
summary, the manifest schema URL, and the revocation endpoint placeholder.

### 2. REQUEST — quote, then open a job

```bash
# quote: fixed fee from the tier table, 24h expiry
curl -X POST http://localhost:8787/v1/quote \
  -H 'Content-Type: application/json' \
  -d '{
    "target": {
      "package": "mcp-server-fetch",
      "version": "0.6.3",
      "transport": "stdio",
      "repo_url": "https://github.com/modelcontextprotocol/servers"
    },
    "tier": "standard",
    "contact": { "agent_id": "agent:acme-deploy-bot" },
    "callback": { "webhook_url": "https://acme.example/skillproof-hook" }
  }'
# -> { "quote_id": "q_...", "tier": "standard", "fee_usd": 1500, "sla": "5d",
#      "expires_at": "...", "payment_instructions": {...}, "manifest_delivery": {...} }

# request: accept the quote, get a job id + status URL
curl -X POST http://localhost:8787/v1/request \
  -H 'Content-Type: application/json' \
  -d '{ "quote_id": "q_...from-above..." }'
# -> { "job_id": "job_...", "status": "queued", "status_url": "http://localhost:8787/v1/jobs/job_..." }
```

Unknown tier → `400`. Unknown/expired quote id → `404`/`410`. Malformed
request → `400` with details. Request schemas live in `schemas/`.

### 3. VERIFY — poll the job, then check the manifest yourself

```bash
curl http://localhost:8787/v1/jobs/job_...
# queued -> running -> complete; when complete, "manifest_url" is set
```

On completion, fetch `manifest_url`, then **verify offline, trusting no
server**:

1. Verify the Ed25519 `signature.value` over the canonical manifest JSON
   against `verifier.public_key` (published in the descriptor).
2. Confirm `subject.code_hash` matches the artifact you pinned — a version
   bump without re-verification lapses the badge by design.
3. Check `validity.revoked === false` (and re-check the revocation endpoint
   before high-stakes installs).

## Files

| File | What it is |
|---|---|
| `.well-known/skillproof.json` | Machine-readable service descriptor: tiers, SLAs, targets, method, schema URL, revocation placeholder |
| `schemas/verification-request.schema.json` | Draft 2020-12 schema for `POST /v1/quote` bodies |
| `schemas/quote-response.schema.json` | Draft 2020-12 schema for quote responses |
| `server.js` | Reference HTTP service: descriptor, quote, request, job status; no deps |
| `metering.js` | **Stub.** Marked Tollbooth metering hooks (`meterQuote`, `meterRequest`, `meterJobEvent`, `meterTrustCheck`) — no-ops that log, with a TODO wiring checklist. No real billing. |
| `test.js` | Spawns the server, exercises all endpoints, asserts quote math for all 4 tiers |
| `package.json` | `npm start` / `npm test` (equivalents of the `node` commands above) |
| `queue.jsonl` | Created at runtime: append-only job queue (demo scale; a real deploy uses a DB) |

## Tier table (single source of truth: `.well-known/skillproof.json`, mirrored in `server.js`)

| Tier | Fee | SLA |
|---|---|---|
| `sprint` | $500 one-time / version | 48h |
| `standard` | $1,500 one-time / version | 5 days |
| `rush` | $2,500 one-time / version | 24h |
| `continuous` | $300 / month / skill | re-verify on every version bump |

50% upfront, balance on manifest issuance (commercial terms in the descriptor).

## What is implemented vs stubbed

**Implemented:** descriptor serving, request validation, fixed-fee quoting from
the tier table (with 400s for unknown tier / bad input), quote expiry (24h),
job creation into a JSONL queue, job status with the `queued → running →
complete` lifecycle and manifest-URL placeholder on completion.

**Stubbed (marked in code):**
- `metering.js` — all Tollbooth hooks are no-ops. Per
  TOLLBOOTH_INTEGRATION.md, trust-check metering at fractions of a cent is the
  billions-of-agents line; wire it here at deploy time.
- `payment_instructions` in the quote response — placeholder; replace with a
  live Tollbooth invoice URL.
- `manifest_url` — placeholder `https://skillproof.dev/manifests/<job>.json`;
  in production this points at the real Ed25519-signed manifest.
- `verifier.public_key` in the descriptor is `ed25519:REPLACE_WITH_PUBLISHED_KEY`.
- Quotes live in memory; jobs in a JSONL file. A production deploy uses a real
  datastore and authentication on the endpoints.

**Demo-only (never in production):** run with `SKILLPROOF_DEMO=1` to enable
`POST /v1/jobs/:id/advance` for walking a job through its lifecycle in tests.
In production the verification pipeline advances jobs.

## Deploying on the VPS (human lane — not done here)

1. Copy this directory to the VPS (`147.5.105.20`) from your Windows side;
   run it under a process manager (e.g. `pm2` or systemd) behind the existing
   nginx on `api.nanoempireai.com`, e.g. `location /skillproof/ { proxy_pass
   http://127.0.0.1:8787/; }`. Set `SKILLPROOF_BASE_URL=https://api.nanoempireai.com/skillproof`
   so quote/job URLs are public.
2. Tollbooth key: wire the live signing key from the VPS (Secure Vault / env
   var — never in this repo), implement `meterQuote`/`meterRequest`/
   `meterTrustCheck` in `metering.js` against the local Tollbooth gateway
   (port 8403), and replace `payment_instructions` with the Tollbooth invoice
   URL.
3. Replace `verifier.public_key` in `.well-known/skillproof.json` with the
   real published Ed25519 key, point `manifest_schema_url` and
   `revocation_endpoint` at their live URLs, and remove `SKILLPROOF_DEMO`.
