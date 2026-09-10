// Self-test for gate.mjs: serves signed manifests over localhost and runs the gate as a child process.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.join(here, 'gate.mjs');

function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object' && v !== null) {
    return `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');

function makeManifest(overrides = {}) {
  const m = {
    manifest_version: '1.0',
    subject: { skill_id: 'test/skill', version: '1.0.0', code_hash: 'sha256:abc123' },
    verifier: { id: 'skillproof', public_key: `ed25519:${pubHex}` },
    verdict: 'pass',
    validity: { issued_at: '2026-09-10T00:00:00Z', expires_at: '2026-12-10T00:00:00Z', revoked: false },
    ...overrides,
  };
  const payload = canonicalize(m);
  m.signature = { algorithm: 'Ed25519', value: sign(null, Buffer.from(payload), privateKey).toString('hex') };
  return m;
}

const routes = {
  '/good.json': () => makeManifest(),
  '/tampered.json': () => { const m = makeManifest(); m.verdict = 'pass'; m.subject.version = '9.9.9-evil'; return m; },
  '/failverdict.json': () => makeManifest({ verdict: 'fail' }),
  '/expired.json': () => makeManifest({ validity: { issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-02-01T00:00:00Z', revoked: false } }),
  '/revoked.json': () => makeManifest({ validity: { issued_at: '2026-09-10T00:00:00Z', expires_at: '2026-12-10T00:00:00Z', revoked: true } }),
  '/hash.json': () => makeManifest(),
};

const server = createServer((req, res) => {
  const fn = routes[req.url];
  if (!fn) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': 'application/json', 'connection': 'close' });
  res.end(JSON.stringify(fn()));
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

function runGate(urlPath, extraEnv = {}) {
  return new Promise((resolve) => {
    const child = spawn('node', [GATE], {
      env: { ...process.env, INPUT_MANIFEST_URL: base + urlPath, INPUT_REQUIRE_VERDICT: 'pass_with_notes', ...extraEnv },
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const to = setTimeout(() => { child.kill('SIGKILL'); resolve({ status: null, out: out + '\n[TIMEOUT]' }); }, 15000);
    child.on('close', (code) => { clearTimeout(to); resolve({ status: code, out }); });
  });
}

const cases = [
  ['valid manifest passes', '/good.json', {}, 0],
  ['tampered manifest fails', '/tampered.json', {}, 1],
  ['fail verdict rejected', '/failverdict.json', {}, 1],
  ['expired manifest rejected', '/expired.json', {}, 1],
  ['revoked manifest rejected', '/revoked.json', {}, 1],
  ['code hash pin match passes', '/hash.json', { INPUT_EXPECTED_CODE_HASH: 'sha256:abc123' }, 0],
  ['code hash pin mismatch fails', '/hash.json', { INPUT_EXPECTED_CODE_HASH: 'sha256:wrong' }, 1],
];

let failed = 0;
for (const [name, urlPath, extraEnv, want] of cases) {
  const { status: got, out } = await runGate(urlPath, extraEnv);
  const pass = (want === 0 && got === 0) || (want === 1 && got !== 0 && got !== null);
  console.log(`${pass ? 'PASS' : 'FAIL'} — ${name} (exit ${got})`);
  if (!pass) { console.log(out); failed++; }
}
server.closeAllConnections();
server.close();
if (failed) { console.error(`${failed} gate test(s) failed`); process.exit(1); }
console.log('ALL GATE TESTS PASSED');
