#!/usr/bin/env node
/**
 * Issue Trust Manifest #2 — signs the verification report for
 * mcp-server-fetch v0.6.3 (official MCP fetch server) under SkillProof methodology v1.0.
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs/promises';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');
const SRC = process.env.MCP_FETCH_DIR || '/tmp/mcp-target/servers/src/fetch';
const CLONE = process.env.MCP_CLONE_DIR || '/tmp/mcp-target/servers';
const report = JSON.parse(await fs.readFile(path.join(DEMO, 'harness/report.json'), 'utf8'));

// code_hash: deterministic tree hash over the reviewed source
const files = ['src/mcp_server_fetch/server.py', 'src/mcp_server_fetch/__main__.py', 'src/mcp_server_fetch/__init__.py', 'pyproject.toml'].sort();
const tree = createHash('sha256');
for (const f of files) {
  const content = await fs.readFile(`${SRC}/${f}`);
  tree.update(f + ':' + createHash('sha256').update(content).digest('hex') + '\n');
}
const codeHash = `sha256:${tree.digest('hex')}`;
const commit = execSync('git rev-parse --short HEAD', { cwd: CLONE }).toString().trim();
const harnessSrc = await fs.readFile(path.join(DEMO, 'harness/driver.mjs'));
const harnessHash = `sha256:${createHash('sha256').update(harnessSrc).digest('hex')}`;

// verifier keypair (demo issuance key)
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
await fs.writeFile(path.join(DEMO, 'harness/verifier-public-key.hex'), pubHex);

const now = new Date();
const expires = new Date(now.getTime() + 90 * 24 * 3600 * 1000);

const manifest = {
  manifest_version: '1.0',
  subject: {
    skill_id: 'io.github.modelcontextprotocol/server-fetch',
    display_name: 'MCP Fetch Server (official)',
    version: '0.6.3',
    code_hash: codeHash,
    source: 'https://github.com/modelcontextprotocol/servers',
    commit,
    tools: [
      { name: 'fetch', description_hash: report.tool_description_sha256, side_effects: ['network-egress'] },
    ],
  },
  verifier: {
    id: 'skillproof',
    public_key: `ed25519:${pubHex}`,
    methodology: 'skillproof-methodology-1.0',
  },
  scope: {
    tools_reviewed: ['fetch'],
    out_of_scope: [
      'SSRF guard: the server has none by design; documented as a high-severity finding, not a tested-and-held invariant',
      'prompt-injection resistance of any connected LLM (model-level, not skill code)',
      'TLS certificate validation posture of the deployment proxy',
      'content-safety of fetched pages (not a content filter)',
    ],
  },
  invariants: report.invariants.map((i) => ({
    id: i.id,
    class: { INV1: 'authorization', INV2: 'authorization', INV3: 'authorization', INV4: 'authorization', INV5: 'description_fidelity', INV6: 'fail_closed', INV7: 'fail_closed' }[i.id] || 'other',
    statement: i.statement + (i.note ? ` Note: ${i.note}` : ''),
    status: i.status === 'held' ? 'verified' : 'not_held',
    operations_tested: report.totals.operations,
    adversarial_cases: report.totals.adversarial_landed,
  })),
  harness: {
    hash: harnessHash,
    anti_vacuity: true,
    seeds: 3,
    min_successful_operations: report.totals.honest_ok,
    min_adversarial_landed: report.totals.adversarial_landed,
  },
  static_scan: {
    tools: ['skillproof-description-scan (6 instruction-override markers over 1 tool description)'],
    critical_findings: 0,
  },
  findings: report.findings.map((f, n) => ({
    id: `NOTE-FETCH-${n + 1}`,
    severity: f.severity,
    title: f.title,
    description: f.detail,
    status: 'open',
  })),
  verdict: report.verdict,
  validity: {
    issued_at: now.toISOString(),
    valid_for_version: '0.6.3',
    expires_at: expires.toISOString(),
    revoked: false,
  },
};

function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}
const payload = canonicalize(manifest);
const signature = sign(null, Buffer.from(payload), privateKey).toString('hex');
manifest.signature = {
  algorithm: 'Ed25519',
  signed_payload: 'canonical JSON of this manifest excluding the signature object (sorted-keys)',
  value: signature,
};

await fs.writeFile(path.join(DEMO, 'trust-manifest.json'), JSON.stringify(manifest, null, 2));
console.log('manifest issued:', path.join(DEMO, 'trust-manifest.json'));
console.log('verdict:', manifest.verdict, '| signature:', signature.slice(0, 32) + '…');
