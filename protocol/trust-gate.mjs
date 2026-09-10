// SkillProof Trust Gate — client-side enforcement for agent runtimes. Zero dependencies, Node 20+.
// Before your agent calls a tool, verify the tool's Trust Manifest. Policies:
//   'enforce' — refuse the call on any trust failure (default)
//   'warn'    — log and continue
//   'audit'   — log only, always continue (for dry-runs)
import { verify, createPublicKey } from 'node:crypto';

const RANK = { fail: 0, pass_with_notes: 1, pass: 2 };
const cache = new Map(); // manifestUrl -> { manifest, fetchedAt }

export function canonicalize(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (v && typeof v === 'object' && v !== null) {
    return `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function spkiFromRawEd25519(hex) {
  const raw = Buffer.from(hex, 'hex');
  if (raw.length !== 32) throw new Error(`verifier public key is not 32 bytes (got ${raw.length})`);
  return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
}

export async function fetchManifest(url, { cacheTtlMs = 3600_000 } = {}) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.fetchedAt < cacheTtlMs) return hit.manifest;
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`manifest fetch failed: HTTP ${res.status}`);
  const manifest = await res.json();
  cache.set(url, { manifest, fetchedAt: Date.now() });
  return manifest;
}

export function clearCache() { cache.clear(); }

// Returns { ok, reason } — signature, revocation, expiry.
export function verifyManifest(manifest) {
  try {
    const sig = manifest.signature || {};
    if (sig.algorithm !== 'Ed25519' || typeof sig.value !== 'string' || !sig.value)
      return { ok: false, reason: 'missing Ed25519 signature' };
    const pubPrefixed = manifest.verifier && manifest.verifier.public_key;
    if (typeof pubPrefixed !== 'string' || !pubPrefixed)
      return { ok: false, reason: 'missing verifier public key' };
    const hex = pubPrefixed.startsWith('ed25519:') ? pubPrefixed.slice(8) : pubPrefixed;
    const key = createPublicKey({ key: spkiFromRawEd25519(hex), format: 'der', type: 'spki' });
    const { signature, ...unsigned } = manifest;
    const ok = verify(null, Buffer.from(canonicalize(unsigned)), key, Buffer.from(sig.value, 'hex'));
    if (!ok) return { ok: false, reason: 'SIGNATURE INVALID — manifest tampered or mis-signed' };
    const validity = manifest.validity || {};
    if (validity.revoked === true) return { ok: false, reason: 'manifest REVOKED' };
    if (validity.expires_at && new Date(validity.expires_at) < new Date())
      return { ok: false, reason: `manifest EXPIRED at ${validity.expires_at}` };
    return { ok: true, reason: 'signature valid' };
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
}

// Policy evaluation on a verified manifest. Returns { allowed, reason }.
export function evaluatePolicy(manifest, policy = {}) {
  const requireVerdict = (policy.requireVerdict || 'pass_with_notes').toLowerCase();
  const verdict = String(manifest.verdict || '').toLowerCase();
  if (!(verdict in RANK)) return { allowed: false, reason: `unknown verdict: ${manifest.verdict}` };
  if (RANK[verdict] < RANK[requireVerdict])
    return { allowed: false, reason: `verdict "${verdict}" below required "${requireVerdict}"` };
  if (policy.expectedCodeHash) {
    const h = manifest.subject && manifest.subject.code_hash;
    if (h !== policy.expectedCodeHash)
      return { allowed: false, reason: `code hash mismatch: ${h} !== ${policy.expectedCodeHash}` };
  }
  return { allowed: true, reason: `verdict ${verdict} meets policy` };
}

// The main entry: wraps any async tool-call function with trust enforcement.
//   await guardedCall({ manifestUrl, policy: { mode: 'enforce', requireVerdict: 'pass' }, call: (tool, args) => client.callTool(tool, args), tool: 'read_query', args: {...} })
export async function guardedCall({ manifestUrl, policy = {}, call, tool, args }) {
  const mode = policy.mode || 'enforce';
  if (typeof call !== 'function') throw new Error('guardedCall: call(tool, args) function is required');
  let manifest;
  try {
    manifest = await fetchManifest(manifestUrl, policy);
  } catch (e) {
    const reason = `could not load trust manifest: ${e.message}`;
    if (mode === 'enforce') throw new Error(`trust gate refused "${tool}": ${reason}`);
    console.warn(`[trust-gate] WARN "${tool}": ${reason}`);
    return call(tool, args);
  }
  const v = verifyManifest(manifest);
  if (!v.ok) {
    if (mode === 'enforce') throw new Error(`trust gate refused "${tool}": ${v.reason}`);
    console.warn(`[trust-gate] WARN "${tool}": ${v.reason}`);
    return call(tool, args);
  }
  const e = evaluatePolicy(manifest, policy);
  if (!e.allowed) {
    if (mode === 'enforce') throw new Error(`trust gate refused "${tool}": ${e.reason}`);
    console.warn(`[trust-gate] WARN "${tool}": ${e.reason}`);
    return call(tool, args);
  }
  return call(tool, args);
}
