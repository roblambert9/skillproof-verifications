#!/usr/bin/env node
/**
 * Issue Trust Manifest #07 — signs the verification report for
 * @modelcontextprotocol/server-memory v0.6.2 under SkillProof methodology v1.0.
 * Refuses to run unless harness/report.json exists with a decided verdict
 * (issuance is opt-in and separate from battery reruns).
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');
const SRC = process.env.MCP_MEMORY_DIR || '/tmp/mcp-target-memory/src/memory';
const COMMIT = '94a36286d2ea49d095704167846283f0c2c2d5d1';

let report;
try {
  report = JSON.parse(await fs.readFile(path.join(HERE, 'report.json'), 'utf8'));
} catch {
  console.error('no harness/report.json — run node harness/driver.mjs first.');
  process.exit(2);
}
if (!report.vacuity?.pass) {
  console.error('vacuity gate did not pass — manifest issuance refused.');
  process.exit(3);
}
if (report.verdict === 'PENDING' || !report.verdict) {
  console.error('report has no decided verdict — issuance refused.');
  process.exit(3);
}

const files = ['src/memory/index.ts', 'src/memory/package.json', 'tsconfig.json'].sort();
const tree = createHash('sha256');
for (const f of files) {
  // SRC is <root>/src/memory; the hashed files are repo-root-relative.
  const content = await fs.readFile(`${SRC}/../../${f}`);
  tree.update(f + ':' + createHash('sha256').update(content).digest('hex') + '\n');
}
const codeHash = `sha256:${tree.digest('hex')}`;
const harnessSrc = await fs.readFile(path.join(HERE, 'driver.mjs'));
const harnessHash = `sha256:${createHash('sha256').update(harnessSrc).digest('hex')}`;

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
await fs.writeFile(path.join(HERE, 'verifier-public-key.hex'), pubHex);

const now = new Date();
const expires = new Date(now.getTime() + 90 * 24 * 3600 * 1000);
const CLASS = { INV1: 'authorization', INV2: 'data_flow', INV3: 'injection', INV4: 'description_fidelity', INV5: 'fail_closed' };
const SIDE = {
  create_entities: ['graph-write'], create_relations: ['graph-write'],
  add_observations: ['graph-write'], delete_entities: ['graph-write'],
  delete_observations: ['graph-write'], delete_relations: ['graph-write'],
  read_graph: ['graph-read'], search_nodes: ['graph-read'], open_nodes: ['graph-read'],
};
const TOOL_NAMES = Object.keys(SIDE);

const manifest = {
  manifest_version: '1.0',
  subject: {
    skill_id: 'io.github.modelcontextprotocol/server-memory',
    display_name: 'MCP Memory Server (official)',
    version: '0.6.2',
    code_hash: codeHash,
    source: 'https://github.com/modelcontextprotocol/servers',
    commit: COMMIT,
    tools: TOOL_NAMES.map((name) => ({
      name,
      description_hash: report.tool_description_sha256,
      side_effects: SIDE[name],
    })),
  },
  verifier: { id: 'skillproof', public_key: `ed25519:${pubHex}`, methodology: 'skillproof-methodology-1.0' },
  scope: {
    tools_reviewed: TOOL_NAMES,
    out_of_scope: [
      'the backing file is at a fixed path inside the server install dir (MEMORY_FILE_PATH); host filesystem permissions outside it are assumed process-confined',
      'prompt-injection resistance of any connected LLM (model-level, not skill code)',
      'concurrent writers / TOCTOU on memory.json (single-sequential battery)',
      'performance under large graphs (small fixture battery)',
    ],
  },
  invariants: report.invariants.map((i) => ({
    id: i.id,
    class: CLASS[i.id] || 'other',
    statement: i.statement,
    status: i.status === 'held' ? 'verified' : 'not_held',
    operations_tested: report.totals.operations,
    adversarial_cases: report.totals.adversarial_landed,
  })),
  harness: {
    hash: harnessHash,
    anti_vacuity: true,
    seeds: report.totals.seeds,
    min_successful_operations: report.totals.honest_ok,
    min_adversarial_landed: report.totals.adversarial_landed,
  },
  static_scan: {
    tools: ['skillproof-description-scan (6 instruction-override markers over 9 tool descriptions)'],
    critical_findings: 0,
  },
  findings: report.findings.map((f, n) => ({
    id: `NOTE-MEMORY-${n + 1}`,
    severity: f.severity,
    title: f.title,
    description: f.detail,
    status: 'open',
  })),
  verdict: report.verdict,
  validity: {
    issued_at: now.toISOString(),
    valid_for_version: '0.6.2',
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
