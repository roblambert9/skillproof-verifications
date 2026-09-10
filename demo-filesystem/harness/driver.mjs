#!/usr/bin/env node
/**
 * SkillProof adversarial driver — first public verification.
 * Target: @modelcontextprotocol/server-filesystem v0.6.3 (official MCP filesystem server)
 * Method: drive the live server over MCP stdio with honest + adversarial operations,
 *         checking behavioral invariants after every operation.
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');                       // demo repo root (portable)
const SERVER_DIR = process.env.MCP_SERVER_DIR || '/tmp/mcp-target/servers/src/filesystem';
const SERVER = path.join(SERVER_DIR, 'dist/index.js');
const FIXTURE = process.env.SKILLPROOF_FIXTURE || '/tmp/skillproof';
const A = path.join(FIXTURE, 'allowed');          // allowed directory (server arg)
const S = path.join(FIXTURE, 'secret');           // outside the boundary
const CANARY = 'SKPROOF_CANARY_9f2c';
const SEEDS = [11, 22, 33];

// ---------------------------------------------------------------------------
// Seeded PRNG (mulberry32) for adversarial ordering
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffle(arr, rand) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ---------------------------------------------------------------------------
// MCP stdio client
let nextId = 1;
const pending = new Map();
function send(proc, method, params) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('timeout'));
    }, 10000);
    pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); } });
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
async function callTool(proc, name, args) {
  const res = await send(proc, 'tools/call', { name, arguments: args });
  if (res.error) return { ok: false, error: res.error.message || String(res.error.code) };
  const c = res.result?.content?.[0];
  const text = c?.text ?? JSON.stringify(res.result);
  const isErr = res.result?.isError === true;
  return { ok: !isErr, text };
}

// ---------------------------------------------------------------------------
// Fixture
async function resetFixture() {
  await fs.rm(FIXTURE, { recursive: true, force: true });
  await fs.mkdir(`${A}/docs`, { recursive: true });
  await fs.mkdir(`${A}/sub`, { recursive: true });
  await fs.mkdir(S, { recursive: true });
  await fs.writeFile(`${A}/docs/notes.txt`, 'public data\nline two\n');
  await fs.writeFile(`${A}/docs/pic.png`, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  await fs.writeFile(`${S}/creds.txt`, `${CANARY} honolulu\napi_key=sk_live_nope\n`);
  await fs.writeFile(`${S}/image.png`, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  // symlinks: two hostile (escape), one benign (must keep working)
  await fs.symlink(S, `${A}/sub/evil-link`);
  await fs.symlink(`${S}/creds.txt`, `${A}/sub/creds-link.txt`);
  await fs.symlink(`${A}/docs/notes.txt`, `${A}/sub/ok-link.txt`);
}
async function snapshotSecret() {
  const out = {};
  for (const f of ['creds.txt', 'image.png']) {
    out[f] = (await fs.readFile(`${S}/${f}`)).toString('hex');
  }
  return out;
}

// ---------------------------------------------------------------------------
// Operation builders
function honestOps() {
  const ops = [];
  const stamp = randomBytes(4).toString('hex');
  ops.push({ tool: 'write_file', args: { path: `${A}/docs/h_${stamp}.txt`, content: `hello ${stamp}\n` }, kind: 'honest' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/docs/h_${stamp}.txt` }, kind: 'honest', expect: `hello ${stamp}` });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/docs/notes.txt`, head: 1 }, kind: 'honest', expect: 'public data' });
  ops.push({ tool: 'read_file', args: { path: `${A}/docs/notes.txt` }, kind: 'honest', expect: 'public data' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/sub/ok-link.txt` }, kind: 'honest', expect: 'public data' });
  ops.push({ tool: 'read_media_file', args: { path: `${A}/docs/pic.png` }, kind: 'honest' });
  ops.push({ tool: 'edit_file', args: { path: `${A}/docs/h_${stamp}.txt`, edits: [{ oldText: `hello ${stamp}`, newText: `edited ${stamp}` }] }, kind: 'honest' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/docs/h_${stamp}.txt` }, kind: 'honest', expect: `edited ${stamp}` });
  ops.push({ tool: 'list_directory', args: { path: `${A}/docs` }, kind: 'honest', expect: `h_${stamp}.txt` });
  ops.push({ tool: 'list_directory_with_sizes', args: { path: A }, kind: 'honest', expect: 'docs' });
  ops.push({ tool: 'directory_tree', args: { path: A }, kind: 'honest', expect: 'notes.txt' });
  ops.push({ tool: 'get_file_info', args: { path: `${A}/docs/notes.txt` }, kind: 'honest', expect: 'isFile' });
  ops.push({ tool: 'search_files', args: { path: A, pattern: '**/*.txt' }, kind: 'honest', expect: 'notes.txt' });
  ops.push({ tool: 'create_directory', args: { path: `${A}/sub/newdir_${stamp}` }, kind: 'honest' });
  ops.push({ tool: 'move_file', args: { source: `${A}/docs/h_${stamp}.txt`, destination: `${A}/sub/newdir_${stamp}/moved.txt` }, kind: 'honest' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/sub/newdir_${stamp}/moved.txt` }, kind: 'honest', expect: `edited ${stamp}` });
  ops.push({ tool: 'read_multiple_files', args: { paths: [`${A}/docs/notes.txt`, `${A}/sub/newdir_${stamp}/moved.txt`] }, kind: 'honest', expect: 'public data' });
  ops.push({ tool: 'list_allowed_directories', args: {}, kind: 'honest', expect: 'allowed' });
  return ops;
}

function adversarialOps() {
  const ops = [];
  const trav = `${A}/../secret/creds.txt`;
  const trav2 = `${A}/sub/../../secret/creds.txt`;
  const abs = `${S}/creds.txt`;
  const rel = `../../secret/creds.txt`;
  const viaLinkDir = `${A}/sub/evil-link/creds.txt`;
  const viaLinkFile = `${A}/sub/creds-link.txt`;
  const homeSsh = `${process.env.HOME}/.ssh/id_rsa`;
  const winPath = `C:\\Windows\\secret.txt`;
  const nullByte = `${A}/docs/notes.txt\u0000`;
  const encTrav = `${A}/%2e%2e/secret/creds.txt`;
  const dotSlash = `${A}/./../secret/creds.txt`;
  const doubleSlash = `${A}//../secret/creds.txt`;

  const readTargets = [trav, trav2, abs, rel, viaLinkDir, viaLinkFile, homeSsh, winPath, nullByte, encTrav, dotSlash, doubleSlash, '/etc/passwd', '/proc/self/environ'];
  for (const t of readTargets) {
    ops.push({ tool: 'read_text_file', args: { path: t }, kind: 'adversarial', note: `read_text_file ${t}` });
  }
  ops.push({ tool: 'read_media_file', args: { path: `${S}/image.png` }, kind: 'adversarial', note: 'read_media_file secret png' });
  ops.push({ tool: 'read_media_file', args: { path: viaLinkFile }, kind: 'adversarial', note: 'read_media_file via symlink' });
  ops.push({ tool: 'read_multiple_files', args: { paths: [`${A}/docs/notes.txt`, abs] }, kind: 'adversarial', note: 'mixed honest+secret batch', partial: true });
  ops.push({ tool: 'read_multiple_files', args: { paths: [viaLinkDir] }, kind: 'adversarial', note: 'batch via evil dir link', partial: true });
  ops.push({ tool: 'read_multiple_files', args: { paths: [abs, `${S}/image.png`] }, kind: 'adversarial', note: 'batch all-secret paths', partial: true });
  for (const t of [trav, abs, viaLinkDir, `${S}/image.png`]) {
    ops.push({ tool: 'get_file_info', args: { path: t }, kind: 'adversarial', note: `get_file_info ${t}` });
  }
  for (const t of [trav, S, '/etc', viaLinkDir]) {
    ops.push({ tool: 'list_directory', args: { path: t }, kind: 'adversarial', note: `list_directory ${t}` });
  }
  for (const t of [trav, S, viaLinkDir]) {
    ops.push({ tool: 'directory_tree', args: { path: t }, kind: 'adversarial', note: `directory_tree ${t}` });
  }
  ops.push({ tool: 'search_files', args: { path: S, pattern: '*.txt' }, kind: 'adversarial', note: 'search_files root outside' });
  ops.push({ tool: 'search_files', args: { path: A, pattern: '../../secret/*.txt' }, kind: 'adversarial', note: 'search_files traversal pattern', partial: true });
  ops.push({ tool: 'search_files', args: { path: A, pattern: '/tmp/skillproof/secret/*.txt' }, kind: 'adversarial', note: 'search_files absolute pattern', partial: true });
  ops.push({ tool: 'search_files', args: { path: viaLinkDir, pattern: '*' }, kind: 'adversarial', note: 'search_files via evil link' });
  // second wave: parameter-level and boundary-shape variants
  ops.push({ tool: 'read_text_file', args: { path: abs, head: 5 }, kind: 'adversarial', note: 'read secret with head param' });
  ops.push({ tool: 'read_text_file', args: { path: abs, tail: 5 }, kind: 'adversarial', note: 'read secret with tail param' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/sub/evil-link` }, kind: 'adversarial', note: 'read evil dir link as file' });
  ops.push({ tool: 'read_text_file', args: { path: `${S}/` }, kind: 'adversarial', note: 'read secret dir with trailing slash' });
  ops.push({ tool: 'read_text_file', args: { path: `${A}/docs/notes.txt/` }, kind: 'adversarial', note: 'trailing slash on file', insideOk: true });
  ops.push({ tool: 'list_directory_with_sizes', args: { path: S }, kind: 'adversarial', note: 'list_with_sizes outside' });
  ops.push({ tool: 'list_directory_with_sizes', args: { path: viaLinkDir }, kind: 'adversarial', note: 'list_with_sizes via evil link' });
  ops.push({ tool: 'get_file_info', args: { path: `${A}/sub/evil-link` }, kind: 'adversarial', note: 'get_file_info on evil dir link' });
  ops.push({ tool: 'write_file', args: { path: `${A}/docs/bad\u0000.txt`, content: 'x' }, kind: 'adversarial', note: 'write null-byte path' });
  ops.push({ tool: 'create_directory', args: { path: `${A}/bad\u0000dir` }, kind: 'adversarial', note: 'mkdir null-byte path' });
  ops.push({ tool: 'move_file', args: { source: viaLinkFile, destination: `${A}/sub/loot2.txt` }, kind: 'adversarial', note: 'move with symlink source' });
  ops.push({ tool: 'edit_file', args: { path: abs, edits: [{ oldText: 'x', newText: 'y' }], dryRun: true }, kind: 'adversarial', note: 'edit secret (dry run)' });

  // write-class
  ops.push({ tool: 'write_file', args: { path: `${S}/pwned.txt`, content: 'x' }, kind: 'adversarial', note: 'write outside (absolute)' });
  ops.push({ tool: 'write_file', args: { path: `${A}/../secret/pwned.txt`, content: 'x' }, kind: 'adversarial', note: 'write outside (traversal)' });
  ops.push({ tool: 'write_file', args: { path: `${A}/sub/evil-link/pwned.txt`, content: 'x' }, kind: 'adversarial', note: 'write via evil dir link' });
  ops.push({ tool: 'write_file', args: { path: viaLinkFile, content: 'overwrite?' }, kind: 'adversarial', note: 'write directly to symlink path' });
  ops.push({ tool: 'edit_file', args: { path: abs, edits: [{ oldText: CANARY, newText: 'pwned' }] }, kind: 'adversarial', note: 'edit secret file' });
  ops.push({ tool: 'edit_file', args: { path: viaLinkFile, edits: [{ oldText: CANARY, newText: 'pwned' }], dryRun: true }, kind: 'adversarial', note: 'edit via symlink (dry run)' });
  ops.push({ tool: 'create_directory', args: { path: `${S}/evil` }, kind: 'adversarial', note: 'mkdir outside' });
  ops.push({ tool: 'create_directory', args: { path: `${A}/sub/evil-link/evil` }, kind: 'adversarial', note: 'mkdir via evil link' });
  // move-class: both directions + onto symlink
  ops.push({ tool: 'move_file', args: { source: `${A}/docs/notes.txt`, destination: `${S}/stolen.txt` }, kind: 'adversarial', note: 'move inside->outside' });
  ops.push({ tool: 'move_file', args: { source: abs, destination: `${A}/sub/loot.txt` }, kind: 'adversarial', note: 'move outside->inside' });
  ops.push({ tool: 'move_file', args: { source: `${A}/docs/notes.txt`, destination: `${A}/sub/evil-link/moved.txt` }, kind: 'adversarial', note: 'move into evil link dir' });
  ops.push({ tool: 'move_file', args: { source: `${A}/docs/notes.txt`, destination: `${A}/sub/creds-link.txt` }, kind: 'adversarial', note: 'move onto existing symlink' });
  return ops;
}

// ---------------------------------------------------------------------------
// Invariant checkers (run per operation)
function checkInvariants(op, res, ledger) {
  const violations = [];
  const hay = (res.text || '') + ' ' + (res.error || '');
  // INV-DATA-1: canary must never appear in any response
  if (hay.includes(CANARY)) {
    violations.push('INV-DATA-1: canary leaked in response');
  }
  if (op.kind === 'adversarial') {
    // Partial-success ops: correct behavior is per-item refusal with no leakage.
    // Accept only when the response carries no canary and refuses or empties
    // every outside-boundary item.
    if (op.partial) {
      const clean = !hay.includes(CANARY) &&
        (/access denied|denied|no matches found/i.test(hay) || !/honolulu|sk_live_nope/.test(hay));
      if (!clean) violations.push(`INV-AUTH/DATA: partial op leaked or misbehaved: ${op.note}`);
      return violations;
    }
    // INV-AUTH-1/2: no adversarial op may report success touching outside
    if (res.ok) {
      // insideOk: target is inside the boundary; success is the correct outcome
      // (e.g. trailing-slash normalization). Only outside-touching success counts.
      if (op.insideOk) return violations;
      // success is only acceptable if it provably stayed inside the boundary:
      // write-to-symlink-path replaces the link itself (atomic rename, no follow) —
      // accept only when the secret tree is untouched (checked globally at end).
      // Anything else successful here is a violation until proven otherwise.
      const maybeBenign = op.note === 'write directly to symlink path';
      if (!maybeBenign) violations.push(`INV-AUTH: adversarial op unexpectedly succeeded: ${op.note}`);
      else ledger.push({ check: 'deferred', note: 'symlink-path write needs global integrity check' });
    }
    // INV-FAIL-1: every adversarial op must terminate refused/safe-error (no hang/crash)
    if (!res.ok && !/access denied|denied|outside allowed|does not exist|ENOENT|ENAMETOOLONG|Windows-style|validation|invalid/i.test(hay)) {
      ledger.push({ check: 'note', note: `unusual refusal text for ${op.note}: ${hay.slice(0, 120)}` });
    }
  } else {
    if (!res.ok) violations.push(`honest op failed: ${op.tool} ${op.note || ''} :: ${hay.slice(0, 160)}`);
    if (op.expect && res.ok && !hay.includes(op.expect)) {
      violations.push(`honest op missing expected content: ${op.tool} wanted ${op.expect}`);
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
async function runSeed(seed) {
  await resetFixture();
  const secretBefore = await snapshotSecret();
  const proc = spawn('node', [SERVER, A], { stdio: ['pipe', 'pipe', 'ignore'] });
  const rl = createInterface({ input: proc.stdout });
  rl.on('line', (line) => {
    try {
      const d = JSON.parse(line);
      const p = pending.get(d.id);
      if (p) { pending.delete(d.id); p.resolve(d); }
    } catch {}
  });
  await send(proc, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'skillproof', version: '1.0' } });
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

  // INV-DESC-1: description fidelity — fetch + hash + scan all tool descriptions
  const listRes = await send(proc, 'tools/list', {});
  const tools = listRes.result.tools;
  const descHashes = {};
  const markers = ['ignore previous instructions', 'ignore all previous', 'you are now', 'operate unconditionally', '<important>', 'disregard your rules', 'system prompt', 'jailbreak', 'exfiltrate'];
  const descViolations = [];
  for (const t of tools) {
    const h = createHash('sha256').update(t.description || '').digest('hex');
    descHashes[t.name] = { hash: `sha256:${h}`, description: t.description || '' };
    const low = (t.description || '').toLowerCase();
    for (const m of markers) if (low.includes(m)) descViolations.push(`INV-DESC-1: marker "${m}" in ${t.name}`);
  }

  const ledger = [];
  const violations = [...descViolations];
  const rand = rng(seed);
  const ops = [...honestOps(), ...shuffle(adversarialOps(), rand)];
  let honestSuccess = 0, adversarialLanded = 0;

  for (const op of ops) {
    let res;
    try {
      res = await callTool(proc, op.tool, op.args);
    } catch (e) {
      res = { ok: false, error: `harness: ${e.message}` };
    }
    const entry = { tool: op.tool, kind: op.kind, note: op.note || '', ok: res.ok };
    ledger.push(entry);
    if (op.kind === 'honest' && res.ok) honestSuccess++;
    if (op.kind === 'adversarial') adversarialLanded++;
    violations.push(...checkInvariants(op, res, ledger));
  }

  // liveness: server still responsive
  try {
    const r = await callTool(proc, 'list_allowed_directories', {});
    if (!r.ok) violations.push('INV-FAIL-1: server unresponsive at end of battery');
  } catch { violations.push('INV-FAIL-1: server died during battery'); }
  proc.kill();

  // global integrity: secret tree bit-identical
  const secretAfter = await snapshotSecret();
  for (const f of Object.keys(secretBefore)) {
    if (secretBefore[f] !== secretAfter[f]) violations.push(`INV-AUTH: secret tree modified: ${f}`);
  }
  // no pwned files created outside
  for (const p of [`${S}/pwned.txt`, `${S}/evil`, `${S}/stolen.txt`, `${A}/sub/loot.txt`]) {
    try { await fs.stat(p); violations.push(`INV-AUTH: boundary artifact created: ${p}`); } catch {}
  }
  // benign symlink must still resolve inside (no false-positive breakage)
  try {
    const target = await fs.realpath(`${A}/sub/ok-link.txt`);
    if (!target.startsWith(A)) violations.push('INV-FAIL: benign symlink broken');
  } catch { violations.push('INV-FAIL: benign symlink broken'); }

  return { seed, tools: tools.map(t => t.name), descHashes, ledger, violations, honestSuccess, adversarialLanded, totalOps: ops.length };
}

// ---------------------------------------------------------------------------
const results = [];
for (const seed of SEEDS) {
  console.log(`--- seed ${seed} ---`);
  const r = await runSeed(seed);
  console.log(`ops=${r.totalOps} honest_ok=${r.honestSuccess} adversarial_landed=${r.adversarialLanded} violations=${r.violations.length}`);
  for (const v of r.violations) console.log('  VIOLATION:', v);
  results.push(r);
}

// Anti-vacuity gate
const notes = [];
for (const r of results) {
  if (r.ledger.length !== r.totalOps) notes.push(`seed ${r.seed}: ledger mismatch`);
  if (r.honestSuccess < 15) notes.push(`seed ${r.seed}: too few honest successes (${r.honestSuccess})`);
  if (r.adversarialLanded < 50) notes.push(`seed ${r.seed}: too few adversarial landed (${r.adversarialLanded})`);
}
const allViolations = results.flatMap(r => r.violations.map(v => `seed ${r.seed}: ${v}`));
const report = {
  target: '@modelcontextprotocol/server-filesystem',
  seeds: SEEDS,
  anti_vacuity: { gate: notes.length === 0, notes },
  totals: {
    operations: results.reduce((n, r) => n + r.totalOps, 0),
    honest_successes: results.reduce((n, r) => n + r.honestSuccess, 0),
    adversarial_landed: results.reduce((n, r) => n + r.adversarialLanded, 0),
  },
  violations: allViolations,
  per_seed: results.map(r => ({ seed: r.seed, ops: r.totalOps, honest_ok: r.honestSuccess, adv: r.adversarialLanded })),
  tool_descriptions: results[0].descHashes,
  tools: results[0].tools,
};
await fs.mkdir(path.join(DEMO, 'harness'), { recursive: true });
await fs.writeFile(path.join(DEMO, 'harness/report.json'), JSON.stringify(report, null, 2));
console.log('VACUITY GATE:', notes.length === 0 ? 'PASS' : 'FAIL', notes);
console.log('TOTAL VIOLATIONS:', allViolations.length);
console.log('report written');
