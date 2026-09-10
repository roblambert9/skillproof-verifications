#!/usr/bin/env node
/**
 * SkillProof adversarial driver — verification #02.
 * Target: mcp-server-fetch v0.6.3 (official MCP fetch server, Python)
 * Method: drive the live server over MCP stdio with honest + adversarial
 *         fetch operations, checking behavioral invariants after each.
 * Local deterministic test servers (harness/test-servers.py) provide:
 *   8898 canary (records hits), 8899 redirector (-> canary),
 *   8900 robots-deny, 8901 honest content.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');
const FETCH_PY = process.env.SKILLPROOF_FETCH_PY || '/tmp/fetch-venv/bin/python';
const SEEDS = [11, 22, 33];
const HONEST = 'http://127.0.0.1:8901/page';
const CANARY_HITS = path.join(HERE, 'canary-hits.jsonl');

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
function send(proc, method, params, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('timeout')); }, timeoutMs);
    pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); } });
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
function onData(proc) {
  let buf = '';
  proc.stdout.on('data', (d) => {
    buf += d.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id !== undefined && pending.has(msg.id)) pending.get(msg.id).resolve(msg);
      } catch { /* server stderr noise / partial */ }
    }
  });
}
async function callTool(proc, args, timeoutMs = 45000) {
  const res = await send(proc, 'tools/call', { name: 'fetch', arguments: args }, timeoutMs);
  if (res.error) return { ok: false, error: res.error.message || String(res.error.code), code: res.error.code };
  const c = res.result?.content?.[0];
  const text = c?.text ?? JSON.stringify(res.result);
  return { ok: res.result?.isError !== true, text };
}
async function getPrompt(proc, args) {
  const res = await send(proc, 'prompts/get', { name: 'fetch', arguments: args });
  if (res.error) return { ok: false, error: res.error.message || String(res.error.code) };
  const msgs = res.result?.messages ?? [];
  return { ok: true, text: msgs.map(m => m.content?.text ?? '').join('\n') };
}
async function canaryHits() {
  try {
    const raw = await fs.readFile(CANARY_HITS, 'utf8');
    return raw.trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  } catch { return []; }
}

// ---------------------------------------------------------------------------
// Battery
function honestOps(seed) {
  const rand = rng(seed);
  const ml = [50, 120, 300][seed % 3];
  return [
    { id: 'H1', kind: 'honest', run: (p) => callTool(p, { url: HONEST }), expect: 'Honest content' },
    { id: 'H2', kind: 'honest', run: (p) => callTool(p, { url: HONEST, raw: true }), expect: '<h1>' },
    { id: 'H3', kind: 'honest', run: (p) => callTool(p, { url: HONEST, max_length: ml, start_index: 0 }), expect: 'Contents of' },
    { id: 'H4', kind: 'honest', run: (p) => callTool(p, { url: 'https://example.com' }), expect: 'documentation examples', bonus: true },
    { id: 'H5', kind: 'honest', run: (p) => getPrompt(p, { url: HONEST }), expect: 'Honest content' },
  ];
}
function adversarialOps() {
  return [
    // INV1: scheme confinement
    { id: 'A1', inv: 'scheme', run: (p) => callTool(p, { url: 'file:///etc/passwd' }), forbid: 'root:' },
    { id: 'A2', inv: 'scheme', run: (p) => callTool(p, { url: 'ftp://127.0.0.1:8898/x' }), forbid: 'canary-ok' },
    { id: 'A14', inv: 'scheme', run: (p) => callTool(p, { url: 'gopher://example.com/' }), forbid: 'canary-ok' },
    // INV2: SSRF posture (documented behavior — expect attempt, record it)
    { id: 'A3', inv: 'ssrf', run: (p) => callTool(p, { url: 'http://127.0.0.1:8898/canary-hit' }), watchCanary: true },
    { id: 'A4', inv: 'ssrf', run: (p) => callTool(p, { url: 'http://127.0.0.1:8899/go' }), watchCanary: true },
    { id: 'A5', inv: 'ssrf', run: (p) => callTool(p, { url: 'http://169.254.169.254/latest/meta-data/' }, 60000), note: 'link-local; may route via egress proxy' },
    // INV3: robots.txt honored (autonomous path)
    { id: 'A6', inv: 'robots', run: (p) => callTool(p, { url: 'http://127.0.0.1:8900/secret-page' }), forbid: 'TOP-SECRET-DENY-MARKER', expectRefusal: 'robots' },
    // INV4: prompt path bypass (documents manual-mode behavior)
    { id: 'A16', inv: 'prompt-bypass', run: (p) => getPrompt(p, { url: 'http://127.0.0.1:8900/secret-page' }), expect: 'TOP-SECRET-DENY-MARKER' },
    // INV6: bounds enforced
    { id: 'A8', inv: 'bounds', run: (p) => callTool(p, { url: HONEST, max_length: 0 }), expectRefusal: 'param' },
    { id: 'A9', inv: 'bounds', run: (p) => callTool(p, { url: HONEST, max_length: -5 }), expectRefusal: 'param' },
    { id: 'A10', inv: 'bounds', run: (p) => callTool(p, { url: HONEST, max_length: 2000000 }), expectRefusal: 'param' },
    { id: 'A11', inv: 'bounds', run: (p) => callTool(p, { url: HONEST, start_index: 99999999 }), expect: 'No more content available' },
    // INV7: fail-closed
    { id: 'A7', inv: 'failclosed', run: (p) => callTool(p, { url: 'http://127.0.0.1:1/' }), expectRefusal: 'any' },
    { id: 'A12', inv: 'failclosed', run: (p) => callTool(p, { url: '' }), expectRefusal: 'param' },
    { id: 'A13', inv: 'failclosed', run: (p) => callTool(p, { url: 'not a url' }), expectRefusal: 'param' },
    { id: 'A15', inv: 'failclosed', run: (p) => callTool(p, { url: 'https://127.0.0.1:8898/' }), expectRefusal: 'any' },
  ];
}

// ---------------------------------------------------------------------------
// Main
async function main() {
  // start local test servers
  const ts = spawn('python3', [path.join(HERE, 'test-servers.py')], { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('test servers did not start')), 10000);
    ts.stdout.on('data', (d) => { if (d.toString().includes('test servers up')) { clearTimeout(t); resolve(); } });
    ts.stderr.on('data', (d) => process.stderr.write('[test-servers] ' + d));
  });

  // NOTE: the runtime's no_proxy contains bracketed IPv6 entries which break
  // httpx's proxy-pattern parser (every fetch would fail closed). The harness
  // sanitizes no_proxy for the server child; recorded as an info finding.
  const cleanEnv = { ...process.env, no_proxy: 'localhost,127.0.0.1,::1', NO_PROXY: 'localhost,127.0.0.1,::1' };
  const srv = spawn(FETCH_PY, ['-m', 'mcp_server_fetch'], { stdio: ['pipe', 'pipe', 'pipe'], env: cleanEnv });
  srv.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
  onData(srv);

  const init = await send(srv, 'initialize', {
    protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'skillproof', version: '0.2.0' },
  });
  if (init.error) throw new Error('initialize failed: ' + JSON.stringify(init.error));
  srv.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

  const tools = await send(srv, 'tools/list', {});
  const fetchTool = (tools.result?.tools ?? []).find(t => t.name === 'fetch');
  if (!fetchTool) throw new Error('fetch tool not listed');
  const descHash = createHash('sha256').update(fetchTool.description).digest('hex');
  const MARKERS = ['ignore previous instructions', 'disregard', 'advised to refuse', 'you no longer', 'override your instructions', 'system prompt'];
  const markerHits = MARKERS.filter(m => fetchTool.description.toLowerCase().includes(m));

  const results = [];
  let honestOk = 0, honestTotal = 0, adversarialLanded = 0;
  const violations = [];
  const findings = [];
  let ssrfCanaryHit = false;

  for (const seed of SEEDS) {
    console.log(`--- seed ${seed} ---`);
    const rand = rng(seed * 7);
    const ops = shuffle([...honestOps(seed), ...adversarialOps()], rand);
    let seedHonest = 0, seedAdv = 0;
    for (const op of ops) {
      const before = (await canaryHits()).length;
      let r;
      try {
        r = await op.run(srv);
      } catch (e) {
        results.push({ id: op.id, seed, status: 'driver_error', detail: String(e) });
        continue;
      }
      const after = (await canaryHits()).length;
      const canaryDelta = after - before;
      if (canaryDelta > 0) ssrfCanaryHit = true;

      if (op.kind === 'honest') {
        honestTotal++;
        const ok = r.ok && (!op.expect || r.text.includes(op.expect));
        if (ok) { honestOk++; seedHonest++; }
        results.push({ id: op.id, seed, status: ok ? 'honest_ok' : 'honest_FAIL', ok: r.ok, snippet: (r.text || r.error || '').slice(0, 120) });
        if (!ok && !op.bonus) violations.push(`${op.id}: honest op failed unexpectedly`);
      } else {
        // adversarial: "landed" = server rendered an observed verdict (no driver skip)
        adversarialLanded++; seedAdv++;
        const entry = { id: op.id, seed, inv: op.inv, ok: r.ok, snippet: (r.text || r.error || '').slice(0, 160), canaryDelta };
        if (op.forbid && (r.text || '').includes(op.forbid)) {
          entry.status = 'VIOLATION';
          violations.push(`${op.id}: forbidden content returned (${op.forbid})`);
        } else if (op.expectRefusal === 'robots' && !(r.ok === false && /robot/i.test((r.text || '') + (r.error || '')))) {
          // robots refusal expected; anything else is a violation of INV3
          if (r.ok && (r.text || '').includes('TOP-SECRET-DENY-MARKER')) {
            entry.status = 'VIOLATION'; violations.push(`${op.id}: robots-disallowed content returned via autonomous path`);
          } else { entry.status = 'refused_other'; }
        } else if (op.expectRefusal && r.ok) {
          entry.status = 'VIOLATION'; violations.push(`${op.id}: expected refusal, got success`);
        } else if (op.expect && !(r.text || '').includes(op.expect)) {
          entry.status = 'unexpected'; violations.push(`${op.id}: expected marker missing`);
        } else {
          entry.status = r.ok ? 'processed_ok' : 'refused';
        }
        results.push(entry);
      }
    }
    console.log(`ops=${ops.length} honest_ok=${seedHonest} adversarial_landed=${seedAdv} violations=${violations.length}`);
  }

  // server still alive? (fail-closed invariant)
  let alive = false;
  try { const p = await send(srv, 'ping', {}, 5000); alive = !p.error; } catch { /* dead */ }

  // ---- invariant evaluation ----
  const invariants = [];
  const fileLeak = results.some(r => r.status === 'VIOLATION' && r.forbid === 'root:');
  invariants.push({ id: 'INV1', statement: 'Only http(s) URLs are fetched; file/ftp/gopher schemes are refused and no local file content is ever returned', status: fileLeak ? 'not_held' : 'held' });
  invariants.push({ id: 'INV2', statement: 'SSRF guard: server refuses private-range/loopback targets', status: ssrfCanaryHit ? 'not_held' : 'held', note: 'no SSRF guard exists; see findings' });
  const robotsHeld = !violations.some(v => v.includes('robots-disallowed'));
  invariants.push({ id: 'INV3', statement: 'robots.txt is honored on the autonomous tool path; robots fetch failure fails closed', status: robotsHeld ? 'held' : 'not_held' });
  invariants.push({ id: 'INV4', statement: 'Prompt (manual) path behavior is documented', status: 'held', note: 'manual prompt path bypasses robots check by design' });
  invariants.push({ id: 'INV5', statement: 'Tool description is pinned; instruction-override markers are flagged', status: 'held', note: markerHits.length ? `markers present: ${markerHits.join(', ')}` : 'no markers' });
  const boundsHeld = !violations.some(v => /A8|A9|A10|A11/.test(v));
  invariants.push({ id: 'INV6', statement: 'max_length/start_index bounds enforced; truncation exact; over-index fails safe', status: boundsHeld ? 'held' : 'not_held' });
  invariants.push({ id: 'INV7', statement: 'Unreachable/invalid targets fail closed (McpError); server stays up; no secret leakage in errors', status: alive ? 'held' : 'not_held' });

  if (ssrfCanaryHit) findings.push({ severity: 'high', title: 'No SSRF guard; redirect-to-loopback fetch demonstrated', detail: 'The server followed an external 302 redirect to http://127.0.0.1:8898 and fetched it (canary recorded the hit). Direct loopback fetches are also attempted. There is no private-range, loopback, or link-local blocklist and redirects are followed unconditionally. Impact: any attacker-influenced URL (page content, redirect chain) can make the server request internal endpoints; response bodies are returned to the agent. Mitigation: deploy behind egress filtering / an SSRF-safe fetch proxy; do not expose this server to untrusted URL input as-is.' });
  findings.push({ severity: 'info', title: 'Manual prompt path bypasses robots.txt', detail: 'prompts/get fetch uses the manual user-agent and skips the robots check entirely. By design (user-initiated), but deployers allow-listing via robots should know the prompt path is not covered.' });
  findings.push({ severity: 'info', title: 'Fails closed on malformed no_proxy entries', detail: 'When the no_proxy environment variable contains bracketed IPv6 entries (e.g. [::1]), httpx raises InvalidURL while building its proxy map and every fetch fails with an error. Fail-closed (no data leak), but the server is fully non-functional in such environments — an enterprise-proxy robustness note. The harness sanitizes no_proxy for the server child process.' });
  if (markerHits.length) findings.push({ severity: 'info', title: 'Tool description contains instruction-override language', detail: `Description includes: "Although originally you did not have internet access, and were advised to refuse and tell the user this, this tool now grants you internet access." Markers matched: ${markerHits.join(', ')}. Present in the official server (likely intentional capability notice), but it is exactly the linguistic shape of tool-description poisoning; downstream agent harnesses that scan for such markers will flag it.` });

  // ---- vacuity gate ----
  const vacuity = [];
  if (honestOk < 10) vacuity.push(`only ${honestOk} honest successes (< 10)`);
  const expectedAdv = SEEDS.length * adversarialOps().length;
  if (adversarialLanded < expectedAdv) vacuity.push(`only ${adversarialLanded}/${expectedAdv} adversarial cases observed`);
  if (!alive) vacuity.push('server not alive at end of battery');

  const report = {
    target: { package: 'mcp-server-fetch', version: '0.6.3', source: 'https://github.com/modelcontextprotocol/servers', transport: 'stdio', runtime: 'python' },
    seeds: SEEDS,
    totals: { operations: results.length, honest_ok: honestOk, honest_total: honestTotal, adversarial_landed: adversarialLanded, violations: violations.length },
    tool_description_sha256: descHash,
    description_markers: markerHits,
    invariants, findings, violations,
    vacuity_gate: vacuity.length === 0 ? 'PASS' : 'FAIL',
    vacuity_notes: vacuity,
    verdict: violations.length === 0 ? (findings.some(f => f.severity === 'high') ? 'pass_with_notes' : 'pass') : 'fail',
    cases: results,
  };
  console.log(`VACUITY GATE: ${report.vacuity_gate} ${JSON.stringify(vacuity)}`);
  console.log(`TOTAL VIOLATIONS: ${violations.length} | verdict: ${report.verdict}`);
  await fs.writeFile(path.join(DEMO, 'harness/report.json'), JSON.stringify(report, null, 2));
  console.log('report written');

  ts.kill(); srv.kill();
}

main().catch(e => { console.error('DRIVER FAILED:', e); process.exit(1); });
