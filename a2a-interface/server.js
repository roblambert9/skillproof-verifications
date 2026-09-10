#!/usr/bin/env node
/**
 * SkillProof A2A machine interface — reference implementation.
 *
 * Agents: DISCOVER -> QUOTE -> REQUEST -> VERIFY.
 *   GET  /.well-known/skillproof.json   machine-readable service descriptor
 *   POST /v1/quote                     fixed-fee quote for a verification request
 *   POST /v1/request                   accept a quote, open a job (JSONL queue)
 *   GET  /v1/jobs/:id                  job status: queued -> running -> complete
 *
 * No dependencies. Plain node:http. Runs locally:
 *   node server.js            # listens on PORT (default 8787)
 *   node test.js              # exercises every endpoint, asserts quote math
 *
 * Demo mode (local testing only, NEVER in production):
 *   SKILLPROOF_DEMO=1 node server.js
 * enables POST /v1/jobs/:id/advance to walk a job queued -> running -> complete.
 * In production the verification pipeline (human lane) advances jobs.
 *
 * Billing is NOT implemented. metering.js is a marked stub; payment_instructions
 * in the quote response is a placeholder (see TODO below).
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const metering = require('./metering');

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8787);
const BASE_URL = process.env.SKILLPROOF_BASE_URL || `http://localhost:${PORT}`;
const QUEUE_FILE = path.join(ROOT, 'queue.jsonl');
const DEMO = process.env.SKILLPROOF_DEMO === '1';

// ---------------------------------------------------------------- tiers ---
// Single source of truth for fixed-fee quote math. Keep in sync with
// .well-known/skillproof.json ("tiers") and schemas/quote-response.schema.json.
const TIERS = {
  sprint:     { fee_usd: 500,  sla: '48h',             recurring: false,     recurring_unit: null },
  standard:   { fee_usd: 1500, sla: '5d',              recurring: false,     recurring_unit: null },
  rush:       { fee_usd: 2500, sla: '24h',             recurring: false,     recurring_unit: null },
  continuous: { fee_usd: 300,  sla: 'per_version_bump', recurring: 'monthly', recurring_unit: 'per skill' },
};
const QUOTE_TTL_MS = 24 * 60 * 60 * 1000; // quotes expire after 24h

// ------------------------------------------------- descriptor / schemas ---
const DESCRIPTOR = JSON.parse(fs.readFileSync(path.join(ROOT, '.well-known/skillproof.json'), 'utf8'));

// Cross-check: descriptor tier table must match the TIERS quote math above.
for (const t of DESCRIPTOR.tiers) {
  const local = TIERS[t.id];
  if (!local || local.fee_usd !== t.fee_usd || local.sla !== t.sla) {
    console.error(`[fatal] tier mismatch between .well-known/skillproof.json and server TIERS for "${t.id}"`);
    process.exit(1);
  }
}

// ------------------------------------------------------------ state -------
const quotes = new Map(); // quote_id -> quote object (in-memory; demo scale)
const jobs = new Map();   // job_id -> job object

function loadQueue() {
  if (!fs.existsSync(QUEUE_FILE)) return;
  for (const line of fs.readFileSync(QUEUE_FILE, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const job = JSON.parse(line);
      jobs.set(job.job_id, job);
    } catch { /* skip corrupt lines */ }
  }
}
function persistJob(job) {
  fs.appendFileSync(QUEUE_FILE, JSON.stringify(job) + '\n');
}
loadQueue();

// ------------------------------------------------- request validation -----
// Reference validator for schemas/verification-request.schema.json.
// Covers the fields the quoting decision depends on (required fields + enums).
// This is a hand-written reference validator, not a full draft-2020-12 engine.
const TRANSPORTS = ['stdio', 'http', 'sse'];
function validateRequest(body) {
  const errors = [];
  if (typeof body !== 'object' || body === null) return ['body must be a JSON object'];
  if (!TIERS[body.tier]) errors.push(`tier must be one of: ${Object.keys(TIERS).join(', ')}`);
  const t = body.target;
  if (typeof t !== 'object' || t === null) {
    errors.push('target is required');
  } else {
    if (typeof t.package !== 'string' || !t.package) errors.push('target.package is required');
    if (typeof t.version !== 'string' || !t.version) errors.push('target.version is required');
    if (!TRANSPORTS.includes(t.transport)) errors.push(`target.transport must be one of: ${TRANSPORTS.join(', ')}`);
    if (t.code_hash && !/^sha256:[0-9a-f]{64}$/.test(t.code_hash)) errors.push('target.code_hash must match ^sha256:[0-9a-f]{64}$');
  }
  const c = body.contact;
  if (typeof c !== 'object' || c === null || typeof c.agent_id !== 'string' || !c.agent_id) {
    errors.push('contact.agent_id is required');
  }
  if (body.callback && typeof body.callback.webhook_url !== 'string') {
    errors.push('callback.webhook_url must be a string URI');
  }
  return errors;
}

// ---------------------------------------------------------------- helpers -
function send(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => {
      if (!raw) return resolve(null);
      try { resolve(JSON.parse(raw)); } catch { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}
const nowIso = () => new Date().toISOString();

// ---------------------------------------------------------------- routes --
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);

  // GET /.well-known/skillproof.json — DISCOVER
  if (req.method === 'GET' && url.pathname === '/.well-known/skillproof.json') {
    return send(res, 200, DESCRIPTOR);
  }

  // POST /v1/quote — QUOTE
  if (req.method === 'POST' && url.pathname === '/v1/quote') {
    let body;
    try { body = await readJson(req); } catch { return send(res, 400, { error: 'invalid_json' }); }
    const errors = validateRequest(body);
    if (errors.length) return send(res, 400, { error: 'invalid_request', details: errors });
    const tier = TIERS[body.tier];
    const quoteId = 'q_' + crypto.randomBytes(12).toString('hex');
    const quote = {
      quote_id: quoteId,
      tier: body.tier,
      fee_usd: tier.fee_usd,
      currency: 'USD',
      sla: tier.sla,
      recurring: tier.recurring,
      ...(tier.recurring_unit ? { recurring_unit: tier.recurring_unit } : {}),
      expires_at: new Date(Date.now() + QUOTE_TTL_MS).toISOString(),
      // TODO(human): replace with a live Tollbooth invoice URL at deploy time.
      // metering.meterQuote() is the hook for the invoice-open event.
      payment_instructions: {
        method: 'placeholder',
        note: 'Reference implementation: payment is wired at deploy time (Tollbooth invoice). No billing is performed here.',
      },
      manifest_delivery: {
        method: body.callback ? 'both' : 'poll',
        status_url: `${BASE_URL}/v1/jobs/{job_id}`,
      },
      target: {
        package: body.target.package,
        version: body.target.version,
        transport: body.target.transport,
        ...(body.target.repo_url ? { repo_url: body.target.repo_url } : {}),
      },
    };
    quotes.set(quoteId, { quote, rawRequest: body, issued_at: nowIso() });
    metering.meterQuote({ quoteId, tier: body.tier, feeUsd: tier.fee_usd });
    return send(res, 200, quote);
  }

  // POST /v1/request — REQUEST (accept quote, open job)
  if (req.method === 'POST' && url.pathname === '/v1/request') {
    let body;
    try { body = await readJson(req); } catch { return send(res, 400, { error: 'invalid_json' }); }
    const qid = body && body.quote_id;
    const entry = qid && quotes.get(qid);
    if (!entry) return send(res, 404, { error: 'unknown_quote', detail: 'quote id not found or not issued by this server' });
    if (new Date(entry.quote.expires_at).getTime() < Date.now()) {
      return send(res, 410, { error: 'quote_expired', detail: 'quotes expire 24h after issuance; request a fresh quote' });
    }
    const jobId = 'job_' + crypto.randomBytes(12).toString('hex');
    const job = {
      job_id: jobId,
      quote_id: qid,
      tier: entry.quote.tier,
      fee_usd: entry.quote.fee_usd,
      status: 'queued',
      target: entry.quote.target,
      callback: entry.rawRequest.callback || null,
      contact: entry.rawRequest.contact,
      manifest_url: null,
      created_at: nowIso(),
      updated_at: nowIso(),
      status_url: `${BASE_URL}/v1/jobs/${jobId}`,
    };
    jobs.set(jobId, job);
    persistJob(job);
    metering.meterRequest({ jobId, quoteId: qid, tier: job.tier, feeUsd: job.fee_usd });
    return send(res, 201, { job_id: jobId, status: 'queued', status_url: job.status_url });
  }

  // GET /v1/jobs/:id — VERIFY (status + manifest URL when complete)
  {
    const m = url.pathname.match(/^\/v1\/jobs\/([^/]+)$/);
    if (req.method === 'GET' && m) {
      const job = jobs.get(m[1]);
      if (!job) return send(res, 404, { error: 'unknown_job' });
      return send(res, 200, job);
    }
  }

  // Demo-only job advancement (SKILLPROOF_DEMO=1). Never enable in production.
  {
    const m = url.pathname.match(/^\/v1\/jobs\/([^/]+)\/advance$/);
    if (req.method === 'POST' && m) {
      if (!DEMO) return send(res, 403, { error: 'demo_disabled', detail: 'set SKILLPROOF_DEMO=1 to enable the demo advance endpoint' });
      const job = jobs.get(m[1]);
      if (!job) return send(res, 404, { error: 'unknown_job' });
      let body;
      try { body = await readJson(req); } catch { return send(res, 400, { error: 'invalid_json' }); }
      const to = body && body.to;
      const order = ['queued', 'running', 'complete'];
      if (!order.includes(to) || order.indexOf(to) !== order.indexOf(job.status) + 1) {
        return send(res, 400, { error: 'invalid_transition', detail: `job is '${job.status}'; next must be '${order[order.indexOf(job.status) + 1] || 'none'}'` });
      }
      const from = job.status;
      job.status = to;
      job.updated_at = nowIso();
      if (to === 'complete') {
        // Placeholder manifest URL. In production this points at the issued,
        // Ed25519-signed manifest for this job's pinned artifact.
        job.manifest_url = `https://skillproof.dev/manifests/${job.job_id}.json`;
      }
      metering.meterJobEvent({ jobId: job.job_id, from, to });
      return send(res, 200, job);
    }
  }

  return send(res, 404, { error: 'not_found' });
});

if (require.main === module) {
  metering.configure({ enabled: false }); // stub: no live billing
  server.listen(PORT, () => {
    console.error(`[skillproof-a2a] listening on ${BASE_URL}${DEMO ? ' (DEMO mode)' : ''}`);
    console.error(`[skillproof-a2a] descriptor: ${BASE_URL}/.well-known/skillproof.json`);
  });
}

module.exports = { server, TIERS };
