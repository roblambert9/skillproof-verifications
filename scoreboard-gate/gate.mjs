#!/usr/bin/env node
// SkillProof Gate — verify a Trust Manifest in CI. Zero dependencies, Node 20+.
// GitHub Action inputs arrive as env: INPUT_MANIFEST_URL, INPUT_REQUIRE_VERDICT, INPUT_EXPECTED_CODE_HASH
// Local CLI: node gate.mjs --manifest-url URL [--require-verdict pass_with_notes] [--expected-code-hash sha256:...]
import { verify, createPublicKey } from 'node:crypto';
import { appendFileSync } from 'node:fs';

const RANK = { fail: 0, pass_with_notes: 1, pass: 2 };

function arg(name, def = '') {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) return process.argv[i + 1];
  const envKey = 'INPUT_' + name.toUpperCase().replace(/-/g, '_');
  const env = process.env[envKey];
  return (env !== undefined && env !== '') ? env : def;
}
function out(msg) { console.log(msg); }
function die(msg) { console.error(`::error::skillproof-gate: ${msg}`); process.exit(1); }
function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}
function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}
function spkiFromRawEd25519(hex) {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== 32) die(`verifier public key is not 32 bytes (got ${raw.length})`);
  return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
}

const manifestUrl = arg('manifest-url');
const requireVerdict = arg('require-verdict', 'pass_with_notes').toLowerCase();
const expectedCodeHash = arg('expected-code-hash', '');
if (!manifestUrl) die('manifest-url is required');
if (!(requireVerdict in RANK)) die(`unknown require-verdict: ${requireVerdict}`);

let manifest;
try {
  const res = await fetch(manifestUrl, { redirect: 'follow' });
  if (!res.ok) die(`fetch failed: HTTP ${res.status} for ${manifestUrl}`);
  manifest = await res.json();
} catch (e) {
  die(`could not fetch/parse manifest: ${e.message}`);
}

// 1. Ed25519 signature over canonical JSON (excluding signature object)
const sig = manifest.signature || {};
if (sig.algorithm !== 'Ed25519' || typeof sig.value !== 'string' || !sig.value) die('manifest has no Ed25519 signature');
const pubPrefixed = manifest.verifier && manifest.verifier.public_key;
if (typeof pubPrefixed !== 'string' || !pubPrefixed) die('manifest.verifier.public_key missing');
const hex = pubPrefixed.startsWith('ed25519:') ? pubPrefixed.slice(8) : pubPrefixed;
let key;
try {
  key = createPublicKey({ key: spkiFromRawEd25519(hex), format: 'der', type: 'spki' });
} catch (e) {
  die(`bad verifier public key: ${e.message}`);
}
const { signature, ...unsigned } = manifest;
let sigOk = false;
try {
  sigOk = verify(null, Buffer.from(canonicalize(unsigned)), key, Buffer.from(sig.value, 'hex'));
} catch (e) {
  die(`signature verification threw: ${e.message}`);
}
if (!sigOk) die('SIGNATURE INVALID — manifest was tampered with or mis-signed');
out('signature: VALID');

// 2. Verdict meets policy floor
const verdict = String(manifest.verdict || '').toLowerCase();
if (!(verdict in RANK)) die(`unknown manifest verdict: ${manifest.verdict}`);
out(`verdict: ${verdict} (required minimum: ${requireVerdict})`);
if (RANK[verdict] < RANK[requireVerdict]) die(`verdict "${verdict}" is below required "${requireVerdict}"`);
setOutput('verdict', verdict);

// 3. Validity window: not revoked, not expired
const validity = manifest.validity || {};
if (validity.revoked === true) die('manifest has been REVOKED');
if (validity.expires_at) {
  const exp = new Date(validity.expires_at);
  if (Number.isNaN(exp.getTime())) die(`bad validity.expires_at: ${validity.expires_at}`);
  if (exp < new Date()) die(`manifest EXPIRED at ${validity.expires_at}`);
  out(`valid until: ${validity.expires_at}`);
}

// 4. Code-hash pinning (optional but recommended)
const codeHash = manifest.subject && manifest.subject.code_hash;
if (expectedCodeHash) {
  if (codeHash !== expectedCodeHash) die(`code hash mismatch: manifest pins ${codeHash}, expected ${expectedCodeHash}`);
  out(`code hash pinned: ${codeHash}`);
} else {
  out(`code hash (informational, unpinned): ${codeHash}`);
}

out('skillproof-gate: PASS — cleared to ship');
