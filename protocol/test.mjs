// Self-test for trust-gate.mjs — all in one process (no spawnSync deadlock).
import { createServer } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { guardedCall, verifyManifest, evaluatePolicy, clearCache, canonicalize } from './trust-gate.mjs';

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
  m.signature = { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(m)), privateKey).toString('hex') };
  return m;
}

const routes = {
  '/good.json': () => makeManifest(),
  '/tampered.json': () => { const m = makeManifest(); m.verdict = 'pass'; m.findings = ['EVIL']; return m; },
  '/fail.json': () => makeManifest({ verdict: 'fail' }),
  '/notes.json': () => makeManifest({ verdict: 'pass_with_notes' }),
};
const server = createServer((req, res) => {
  const fn = routes[req.url];
  if (!fn) { res.writeHead(404, { connection: 'close' }); res.end(); return; }
  res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
  res.end(JSON.stringify(fn()));
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const fakeCall = async (tool, args) => ({ tool, args, executed: true });

let failed = 0;
async function check(name, fn) {
  clearCache();
  try { await fn(); console.log(`PASS — ${name}`); }
  catch (e) { console.log(`FAIL — ${name}: ${e.message}`); failed++; }
}

await check('enforce allows verified PASS tool', async () => {
  const r = await guardedCall({ manifestUrl: base + '/good.json', policy: { mode: 'enforce' }, call: fakeCall, tool: 't', args: {} });
  if (!r.executed) throw new Error('call was not executed');
});
await check('enforce refuses tampered manifest', async () => {
  try { await guardedCall({ manifestUrl: base + '/tampered.json', policy: { mode: 'enforce' }, call: fakeCall, tool: 't', args: {} }); }
  catch (e) { if (!/refused/.test(e.message)) throw e; return; }
  throw new Error('call was not refused');
});
await check('enforce refuses FAIL verdict', async () => {
  try { await guardedCall({ manifestUrl: base + '/fail.json', policy: { mode: 'enforce' }, call: fakeCall, tool: 't', args: {} }); }
  catch (e) { if (!/below required/.test(e.message)) throw e; return; }
  throw new Error('call was not refused');
});
await check('warn mode continues past FAIL verdict', async () => {
  const r = await guardedCall({ manifestUrl: base + '/fail.json', policy: { mode: 'warn' }, call: fakeCall, tool: 't', args: {} });
  if (!r.executed) throw new Error('call was not executed in warn mode');
});
await check('requireVerdict=pass rejects pass_with_notes', async () => {
  try { await guardedCall({ manifestUrl: base + '/notes.json', policy: { mode: 'enforce', requireVerdict: 'pass' }, call: fakeCall, tool: 't', args: {} }); }
  catch (e) { return; }
  throw new Error('call was not refused');
});
await check('verifyManifest unit: good manifest ok', async () => {
  const v = verifyManifest(makeManifest());
  if (!v.ok) throw new Error(v.reason);
});
await check('evaluatePolicy unit: hash pin enforced', async () => {
  const e = evaluatePolicy(makeManifest(), { expectedCodeHash: 'sha256:nope' });
  if (e.allowed) throw new Error('hash mismatch was allowed');
});

server.closeAllConnections(); server.close();
if (failed) { console.error(`${failed} protocol test(s) failed`); process.exit(1); }
console.log('ALL PROTOCOL TESTS PASSED');
