#!/usr/bin/env node
/**
 * Standalone historical-manifest verifier for verification #07.
 * Verifies the Ed25519 signature over the canonical JSON payload using ONLY
 * the shipped trust-manifest.json + harness/verifier-public-key.hex.
 * Does not rerun the battery, does not reissue anything.
 * Exit 0 = signature valid; exit 1 = invalid or files missing.
 */
import { createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');

function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

async function main() {
  let manifest, pubHex;
  try {
    manifest = JSON.parse(await fs.readFile(path.join(DEMO, 'trust-manifest.json'), 'utf8'));
    pubHex = (await fs.readFile(path.join(HERE, 'verifier-public-key.hex'), 'utf8')).trim();
  } catch (e) {
    console.error('missing trust-manifest.json or verifier-public-key.hex:', e.message);
    process.exit(1);
  }
  const sigHex = manifest.signature?.value;
  if (!sigHex || manifest.signature?.algorithm !== 'Ed25519') {
    console.error('manifest has no Ed25519 signature');
    process.exit(1);
  }
  const { signature, ...unsigned } = manifest;
  const payload = canonicalize(unsigned);
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pubHex, 'hex')]),
    format: 'der', type: 'spki',
  });
  const ok = verify(null, Buffer.from(payload), key, Buffer.from(sigHex, 'hex'));
  console.log(ok ? 'SIGNATURE VALID' : 'SIGNATURE INVALID');
  console.log(`subject: ${manifest.subject?.skill_id} ${manifest.subject?.version} commit ${manifest.subject?.commit}`);
  console.log(`verdict: ${manifest.verdict}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error('verifier fatal:', e); process.exit(1); });
