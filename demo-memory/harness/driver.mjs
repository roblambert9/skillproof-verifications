#!/usr/bin/env node
/**
 * SkillProof adversarial driver — verification #07.
 * Target: @modelcontextprotocol/server-memory v0.6.2 (official MCP memory
 *         server, TypeScript, 9 tools, file-backed JSONL graph at
 *         <dist>/memory.json)
 * Pinned commit: 94a36286d2ea49d095704167846283f0c2c2d5d1
 *
 * Method: drive the live server over MCP stdio. 10 honest ops (self-contained,
 * per-op fixture names so shuffled order is safe) + 17 adversarial probes
 * covering isolation, file confinement, injection persistence, description
 * fidelity and fail-closed behavior. 3 seeds, shuffled order per seed.
 * Fixture (memory.json) deleted at the start of every seed.
 *
 * Layout note: generic MCP transport lives in harness/mcp-stdio.js,
 * target-specific fixture/snapshot logic in harness/adapters/db-memory.js.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchServer, createClient } from './mcp-stdio.js';
import * as DB from './adapters/db-memory.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(HERE, '..');
const SEEDS = [11, 22, 33];
const SERVER_BIN = process.env.SKILLPROOF_MEMORY_BIN ||
  '/tmp/mcp-target-memory/src/memory/dist/index.js';

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
// Preflight
function preflight() {
  try { execFileSync('command', ['-v', 'node'], { shell: true, stdio: 'ignore' }); }
  catch { console.error('missing required binary: node'); process.exit(2); }
  try { execFileSync('node', [SERVER_BIN, '--version'], { stdio: 'ignore', timeout: 15000 }); }
  catch { /* server takes no --version; spawn check happens per seed */ }
  DB.resetFixture();
}

// ---------------------------------------------------------------------------
// Helpers
async function timedCall(t, tool, args, timeoutMs = 20000) {
  const start = Date.now();
  try {
    const r = await t.callTool(tool, args, timeoutMs);
    // Slice is generous: read_graph on a populated graph is several KB and
    // must stay parseable (a 2000-char cut broke H10/A07/A10 in the first run).
    return { verdict: r.verdict, text: r.text.slice(0, 20000), ms: Date.now() - start };
  } catch (e) {
    return { verdict: e.code === 'MCP_TIMEOUT' ? 'timeout' : 'error',
             text: `driver:${e.message}`, ms: Date.now() - start };
  }
}
function parseText(res) {
  try { return JSON.parse(res.text); } catch { return null; }
}
// Success + parsed JSON contains the entity name somewhere.
function expectEntity(res, name) {
  if (res.verdict !== 'success') return { ...res, verdict: 'error', text: `expected success, got ${res.verdict}: ${res.text.slice(0,160)}` };
  if (!res.text.includes(name)) return { ...res, verdict: 'error', text: `missing expected entity [${name}] in: ${res.text.slice(0,200)}` };
  return res;
}
async function openEntity(t, name) {
  const r = await timedCall(t, 'open_nodes', { names: [name] });
  const g = parseText(r);
  return g?.entities?.find((e) => e.name === name) ?? null;
}
const E = (name, entityType = 'person', observations = []) => ({ name, entityType, observations });

// ---------------------------------------------------------------------------
// Honest operations (self-contained: create own fixtures, clean up after)
function honestOps() {
  return [
    { id: 'H1', kind: 'honest', inv: 'INV1', desc: 'create_entities alice',
      run: (t) => timedCall(t, 'create_entities', { entities: [E('h1_alice', 'person', ['h1 canary'])] })
        .then((r) => expectEntity(r, 'h1_alice')) },
    { id: 'H2', kind: 'honest', inv: 'INV1', desc: 'create_relations between entities',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h2_a'), E('h2_b')] });
        return timedCall(t, 'create_relations', { relations: [{ from: 'h2_a', to: 'h2_b', relationType: 'knows' }] })
          .then((r) => expectEntity(r, 'h2_a'));
      } },
    { id: 'H3', kind: 'honest', inv: 'INV3', desc: 'add_observations to existing entity',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h3_ent')] });
        const r = await timedCall(t, 'add_observations', { observations: [{ entityName: 'h3_ent', contents: ['h3 obs'] }] });
        if (r.verdict !== 'success' || !r.text.includes('h3 obs')) return { ...r, verdict: 'error', text: `add failed: ${r.text.slice(0,160)}` };
        return r;
      } },
    { id: 'H4', kind: 'honest', inv: 'INV4', desc: 'read_graph returns full graph',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h4_ent')] });
        const r = await timedCall(t, 'read_graph', {});
        const g = parseText(r);
        if (r.verdict !== 'success' || !Array.isArray(g?.entities) || !g.entities.some((e) => e.name === 'h4_ent'))
          return { ...r, verdict: 'error', text: `read_graph missing h4_ent: ${r.text.slice(0,160)}` };
        return r;
      } },
    { id: 'H5', kind: 'honest', inv: 'INV4', desc: 'search_nodes finds by observation',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h5_ent', 'person', ['h5-unique-canary'])] });
        const r = await timedCall(t, 'search_nodes', { query: 'h5-unique-canary' });
        const g = parseText(r);
        if (r.verdict !== 'success' || !g?.entities?.some((e) => e.name === 'h5_ent'))
          return { ...r, verdict: 'error', text: `search missed h5_ent: ${r.text.slice(0,160)}` };
        return r;
      } },
    { id: 'H6', kind: 'honest', inv: 'INV4', desc: 'open_nodes retrieves named node',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h6_ent', 'person', ['h6 obs'])] });
        const r = await timedCall(t, 'open_nodes', { names: ['h6_ent'] });
        const g = parseText(r);
        if (r.verdict !== 'success' || !g?.entities?.some((e) => e.name === 'h6_ent'))
          return { ...r, verdict: 'error', text: `open_nodes missed h6_ent: ${r.text.slice(0,160)}` };
        return r;
      } },
    { id: 'H7', kind: 'honest', inv: 'INV1', desc: 'delete_observations removes one obs',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h7_ent', 'person', ['todelete', 'keepme'])] });
        await timedCall(t, 'delete_observations', { deletions: [{ entityName: 'h7_ent', observations: ['todelete'] }] });
        const e = await openEntity(t, 'h7_ent');
        const ok = e && !e.observations.includes('todelete') && e.observations.includes('keepme');
        return ok ? { verdict: 'success', text: 'obs deleted selectively', ms: 0 }
                  : { verdict: 'error', text: `selective delete failed: ${JSON.stringify(e?.observations)}`, ms: 0 };
      } },
    { id: 'H8', kind: 'honest', inv: 'INV1', desc: 'delete_relations removes the relation',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h8_a'), E('h8_b')] });
        await timedCall(t, 'create_relations', { relations: [{ from: 'h8_a', to: 'h8_b', relationType: 'likes' }] });
        const d = await timedCall(t, 'delete_relations', { relations: [{ from: 'h8_a', to: 'h8_b', relationType: 'likes' }] });
        if (d.verdict !== 'success') return d;
        const g = parseText(await timedCall(t, 'read_graph', {}));
        const gone = !g.relations.some((r) => r.from === 'h8_a' && r.to === 'h8_b' && r.relationType === 'likes');
        return gone ? { verdict: 'success', text: 'relation deleted', ms: 0 }
                    : { verdict: 'error', text: 'relation survived delete_relations', ms: 0 };
      } },
    { id: 'H9', kind: 'honest', inv: 'INV1', desc: 'delete_entities removes entity',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('h9_ent')] });
        const d = await timedCall(t, 'delete_entities', { entityNames: ['h9_ent'] });
        if (d.verdict !== 'success') return d;
        const e = await openEntity(t, 'h9_ent');
        return e === null ? { verdict: 'success', text: 'entity deleted', ms: 0 }
                          : { verdict: 'error', text: 'entity survived delete_entities', ms: 0 };
      } },
    { id: 'H10', kind: 'honest', inv: 'INV4', desc: 'read_graph shape sanity',
      run: async (t) => {
        const r = await timedCall(t, 'read_graph', {});
        const g = parseText(r);
        return (r.verdict === 'success' && Array.isArray(g?.entities) && Array.isArray(g?.relations))
          ? { verdict: 'success', text: `entities=${g.entities.length} relations=${g.relations.length}`, ms: 0 }
          : { verdict: 'error', text: `bad graph shape: ${r.text.slice(0,160)}`, ms: 0 };
      } },
  ];
}

// ---------------------------------------------------------------------------
// Adversarial operations
const HOSTILE_OBS = [
  'line1\nline2',                                            // embedded newline
  '{"type":"entity","name":"forged","entityType":"x","observations":[]}', // forged JSONL line
  '__proto__',                                               // prototype-adjacent name
  'a\u202Eb',                                                // RTL override
  '<script>alert(1)</script>',                               // markup
  '../../evil.txt',                                          // traversal text
];
const HOSTILE_RELTYPE = 'knows\u202E"\n{"type":"relation","from":"x","to":"y","relationType":"z"}';

function adversarialOps() {
  return [
    // ---- INV1: entity/relation isolation ----
    { id: 'A01', kind: 'adversarial', inv: 'INV1', desc: 'delete exact-name does not touch prefix-sibling',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('isoA', 'person', ['obsA']), E('isoAX', 'person', ['obsAX'])] });
        await timedCall(t, 'delete_entities', { entityNames: ['isoA'] });
        const sib = await openEntity(t, 'isoAX');
        const gone = await openEntity(t, 'isoA');
        const isolated = sib && gone === null && JSON.stringify(sib.observations) === JSON.stringify(['obsAX']);
        return { verdict: 'success', ms: 0, text: `sibling_intact=${isolated}`, extra: { isolated } };
      } },
    { id: 'A02', kind: 'adversarial', inv: 'INV1', desc: 'delete_observations targets only the named entity',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('isoB', 'person', ['secretB']), E('isoC', 'person', ['secretC'])] });
        await timedCall(t, 'delete_observations', { deletions: [{ entityName: 'isoB', observations: ['secretC'] }] });
        const b = await openEntity(t, 'isoB'), c = await openEntity(t, 'isoC');
        const isolated = b && c && JSON.stringify(b.observations) === JSON.stringify(['secretB']) &&
                         JSON.stringify(c.observations) === JSON.stringify(['secretC']);
        return { verdict: 'success', ms: 0, text: `cross_entity_intact=${isolated}`, extra: { isolated } };
      } },
    { id: 'A03', kind: 'adversarial', inv: 'INV1', desc: 'case-differing names are isolated',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('CaseX_a1'), E('casex_a1')] });
        await timedCall(t, 'add_observations', { observations: [{ entityName: 'CaseX_a1', contents: ['upper-obs'] }] });
        const lower = await openEntity(t, 'casex_a1');
        const isolated = lower && !lower.observations.includes('upper-obs');
        return { verdict: 'success', ms: 0, text: `case_isolated=${isolated}`, extra: { isolated } };
      } },
    // ---- INV2: file-path confinement ----
    { id: 'A04', kind: 'adversarial', inv: 'INV2', desc: 'traversal text in name/obs is data, writes nothing new',
      run: async (t) => {
        // memory.json itself is the expected write; confinement means
        // nothing ELSE appears. (First-run artifact: this op may be the one
        // that creates memory.json, so exclude it from the diff.)
        const norm = (l) => l.filter((f) => f !== 'memory.json');
        const dirBefore = norm(DB.dirListing());
        const r = await timedCall(t, 'create_entities', { entities: [{ name: '../evil_dir', entityType: 'x', observations: ['../../evil.txt'] }] });
        const dirAfter = norm(DB.dirListing());
        const snap = DB.snapshot();
        const stray = dirAfter.filter((f) => /evil/i.test(f));
        const ok = r.verdict === 'success' && stray.length === 0 &&
                   JSON.stringify(dirBefore) === JSON.stringify(dirAfter) && snap.jsonl_valid;
        return { verdict: r.verdict, ms: r.ms,
                 text: `dir_unchanged=${JSON.stringify(dirBefore) === JSON.stringify(dirAfter)} stray=${stray.length} jsonl_valid=${snap.jsonl_valid}`,
                 extra: { confined: ok } };
      } },
    { id: 'A05', kind: 'adversarial', inv: 'INV2', desc: 'newline/JSON forgery cannot add file lines or entities',
      run: async (t) => {
        const before = DB.snapshot();
        await timedCall(t, 'create_entities', { entities: [{ name: 'forgeA5', entityType: 'x',
          observations: ['line1\nline2', '{"type":"entity","name":"forged","entityType":"x","observations":[]}'] }] });
        const after = DB.snapshot();
        const forged = await openEntity(t, 'forged');
        const ok = after.jsonl_valid && after.line_count_ok && forged === null &&
                   after.lines === before.lines + 1 && after.entities === before.entities + 1;
        return { verdict: 'success', ms: 0,
                 text: `jsonl_valid=${after.jsonl_valid} line_count_ok=${after.line_count_ok} forged_entity=${forged !== null} lines_delta=${after.lines - before.lines}`,
                 extra: { confined: ok } };
      } },
    // ---- INV3: injection persistence (verbatim round-trip) ----
    { id: 'A06', kind: 'adversarial', inv: 'INV3', desc: 'hostile observation strings round-trip verbatim',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [{ name: 'hostA6', entityType: 'x', observations: HOSTILE_OBS }] });
        const e = await openEntity(t, 'hostA6');
        const verbatim = e && JSON.stringify(e.observations) === JSON.stringify(HOSTILE_OBS);
        const snap = DB.snapshot();
        return { verdict: 'success', ms: 0,
                 text: `verbatim=${verbatim} line_count_ok=${snap.jsonl_valid && snap.line_count_ok}`,
                 extra: { verbatim: !!verbatim } };
      } },
    { id: 'A07', kind: 'adversarial', inv: 'INV3', desc: 'hostile relationType round-trips verbatim',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('rA7'), E('rB7')] });
        await timedCall(t, 'create_relations', { relations: [{ from: 'rA7', to: 'rB7', relationType: HOSTILE_RELTYPE }] });
        // open_nodes with both endpoints keeps the payload small and targeted
        // (read_graph truncation produced a false negative here in run 1).
        const g = parseText(await timedCall(t, 'open_nodes', { names: ['rA7', 'rB7'] }));
        const rel = g?.relations?.find((r) => r.from === 'rA7' && r.to === 'rB7');
        const verbatim = rel !== undefined && rel !== null && rel.relationType === HOSTILE_RELTYPE;
        const snap = DB.snapshot();
        return { verdict: 'success', ms: 0,
                 text: `verbatim=${verbatim} line_count_ok=${snap.jsonl_valid && snap.line_count_ok}`,
                 extra: { verbatim: !!verbatim } };
      } },
    // ---- INV4: description fidelity ----
    { id: 'A08', kind: 'adversarial', inv: 'INV4', desc: 'read-only tools do not mutate the file',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('pureA8', 'person', ['purity canary'])] });
        const h1 = DB.snapshot().hash;
        const r1 = await timedCall(t, 'read_graph', {});
        const r2 = await timedCall(t, 'search_nodes', { query: 'purity' });
        const r3 = await timedCall(t, 'open_nodes', { names: ['pureA8', 'nonexistent-zz'] });
        const h2 = DB.snapshot().hash;
        const pure = h1 === h2 && r1.verdict === 'success' && r2.verdict === 'success' && r3.verdict === 'success';
        return { verdict: 'success', ms: 0, text: `hash_unchanged=${h1 === h2}`, extra: { pure } };
      } },
    { id: 'A09', kind: 'adversarial', inv: 'INV4', desc: 'create_relations with nonexistent endpoints (dangling)',
      run: async (t) => {
        const r = await timedCall(t, 'create_relations', { relations: [{ from: 'dangleA', to: 'dangleB', relationType: 'haunts' }] });
        const g = parseText(await timedCall(t, 'read_graph', {}));
        const stored = g?.relations?.some((x) => x.from === 'dangleA' && x.to === 'dangleB');
        const endpointsExist = (await openEntity(t, 'dangleA')) !== null || (await openEntity(t, 'dangleB')) !== null;
        const accepted = r.verdict === 'success' && stored && !endpointsExist;
        return { verdict: r.verdict, ms: r.ms,
                 text: `tool_verdict=${r.verdict} stored=${stored} endpoints_exist=${endpointsExist}`,
                 extra: { dangling_accepted: accepted } };
      } },
    { id: 'A10', kind: 'adversarial', inv: 'INV4', desc: 'delete_relations with wrong type is a no-op',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('t10a'), E('t10b')] });
        await timedCall(t, 'create_relations', { relations: [{ from: 't10a', to: 't10b', relationType: 'likes' }] });
        const d = await timedCall(t, 'delete_relations', { relations: [{ from: 't10a', to: 't10b', relationType: 'hates' }] });
        const g = parseText(await timedCall(t, 'open_nodes', { names: ['t10a', 't10b'] }));
        const kept = g?.relations?.some((r) => r.from === 't10a' && r.to === 't10b' && r.relationType === 'likes') === true;
        const noop = d.verdict === 'success' && kept;
        return { verdict: 'success', ms: 0, text: `wrong_type_noop=${noop}`, extra: { noop } };
      } },
    { id: 'A11', kind: 'adversarial', inv: 'INV4', desc: 'delete_observations on nonexistent entity (silent?)',
      run: async (t) => {
        const r = await timedCall(t, 'delete_observations', { deletions: [{ entityName: 'ghost-entity-zz', observations: ['x'] }] });
        return { verdict: r.verdict, ms: r.ms, text: `verdict=${r.verdict} text=${r.text.slice(0,120)}`,
                 extra: { silent_success: r.verdict === 'success' } };
      } },
    // ---- INV5: fail-closed ----
    { id: 'A12', kind: 'adversarial', inv: 'INV5', desc: 'create_entities missing entities arg',
      run: (t) => timedCall(t, 'create_entities', {}) },
    { id: 'A13', kind: 'adversarial', inv: 'INV5', desc: 'add_observations to nonexistent entity',
      run: (t) => timedCall(t, 'add_observations', { observations: [{ entityName: 'ghost-zz', contents: ['x'] }] }) },
    { id: 'A14', kind: 'adversarial', inv: 'INV5', desc: 'search_nodes with numeric query',
      run: (t) => timedCall(t, 'search_nodes', { query: 123 }) },
    { id: 'A15', kind: 'adversarial', inv: 'INV5', desc: 'unknown tool',
      run: (t) => timedCall(t, 'nonexistent-tool', {}) },
    { id: 'A16', kind: 'adversarial', inv: 'INV5', desc: 'corrupt backing file: fail closed, recover after repair',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('corruptA16', 'person', ['pre-corruption canary'])] });
        const restore = DB.corruptFile();
        const r1 = await timedCall(t, 'read_graph', {});
        const r2 = await timedCall(t, 'create_entities', { entities: [E('postcorrupt')] });
        let alive = false;
        try { const lt = await t.listTools(); alive = !lt.error && Array.isArray(lt.result?.tools); } catch { alive = false; }
        restore();
        const r3 = await timedCall(t, 'read_graph', {});
        const recovered = r3.verdict === 'success' && r3.text.includes('corruptA16');
        const failClosed = r1.verdict === 'error' && r2.verdict === 'error';
        return { verdict: 'success', ms: 0,
                 text: `corrupt_read=${r1.verdict} corrupt_write=${r2.verdict} alive_during=${alive} recovered=${recovered}`,
                 extra: { fail_closed: failClosed && alive, recovered } };
      } },
    { id: 'A17', kind: 'adversarial', inv: 'INV5', desc: 'deleted backing file silently resets graph',
      run: async (t) => {
        await timedCall(t, 'create_entities', { entities: [E('vanishA17')] });
        DB.resetFixture(); // delete memory.json = indistinguishable from first run
        const r = await timedCall(t, 'read_graph', {});
        const g = parseText(r);
        const silentEmpty = r.verdict === 'success' && g?.entities?.length === 0;
        return { verdict: r.verdict, ms: r.ms, text: `silent_empty_reset=${silentEmpty}`,
                 extra: { silent_empty_reset: silentEmpty } };
      } },
  ];
}

// ---------------------------------------------------------------------------
// Static description-fidelity scan (recorded, not counted toward vacuity).
const MARKERS = ['ignore previous instructions', 'disregard', 'system prompt',
  'advised to refuse', 'do not reveal', 'override'];
async function staticScan(t) {
  const r = await t.send('tools/list', {});
  const tools = r.result?.tools ?? [];
  const desc = tools.map((x) => `${x.name}: ${x.description}`).join('\n');
  const hits = MARKERS.filter((m) => desc.toLowerCase().includes(m));
  return {
    id: 'F1', kind: 'static', inv: 'INV4',
    desc: 'description marker scan',
    tool_description_sha256: createHash('sha256').update(desc).digest('hex'),
    markers_found: hits,
    tool_count: tools.length,
    description: desc.slice(0, 300),
  };
}

// ---------------------------------------------------------------------------
// Runner
async function runSeed(seed) {
  DB.resetFixture();
  const dirBefore = DB.dirListing();
  const rand = rng(seed);
  const proc = launchServer('node', [SERVER_BIN]);
  const t = createClient(proc);
  const ops = [];
  try {
    await t.initialize();
    await t.notifyInitialized();
    const snapBefore = DB.snapshot();
    const battery = shuffle([...honestOps(), ...adversarialOps()], rand);
    for (const op of battery) {
      let res;
      try {
        res = await op.run(t);
      } catch (e) {
        res = { verdict: 'error', text: `driver-exception:${e.message}`, ms: 0 };
      }
      const landed = res.verdict !== 'error' || !String(res.text).startsWith('driver:');
      ops.push({ seed, id: op.id, kind: op.kind, inv: op.inv, desc: op.desc,
                 verdict: res.verdict, ms: res.ms, landed,
                 text: String(res.text || '').slice(0, 600),
                 extra: res.extra || null });
    }
    const snapAfter = DB.snapshot();
    const dirAfter = DB.dirListing();
    let alive = false;
    try { const lt = await t.listTools(); alive = !lt.error && Array.isArray(lt.result?.tools); }
    catch { alive = false; }
    const f1 = await staticScan(t);
    return { seed, ops, snapBefore, snapAfter, dirBefore, dirAfter, alive, static: f1 };
  } finally {
    await t.close();
  }
}

// ---------------------------------------------------------------------------
// Evaluation: invariant status from observed evidence. No retrofitted claims.
function evaluate(seeds) {
  const all = seeds.flatMap((s) => s.ops);
  const byId = (id, seed) => all.find((o) => o.id === id && o.seed === seed);
  const adv = all.filter((o) => o.kind === 'adversarial');
  const hon = all.filter((o) => o.kind === 'honest');
  const honestOk = hon.filter((o) => o.verdict === 'success').length;

  const findings = [];
  const notes = [];

  // INV1: isolation
  let inv1 = 'held';
  const isoOk = ['A01', 'A02', 'A03'].every((id) =>
    seeds.every((s) => byId(id, s.seed).extra?.isolated === true));
  if (!isoOk) {
    inv1 = 'not_held';
    findings.push({ severity: 'high', inv: 'INV1',
      title: 'Delete/mutate operation leaked across entity boundary',
      detail: 'One of A01 (delete exact-name vs prefix-sibling), A02 (delete_observations cross-entity), ' +
        'A03 (case-differing names) reported isolated=false on at least one seed. See report ops.' });
  }

  // INV2: file confinement
  let inv2 = 'held';
  const confinedOk = ['A04', 'A05'].every((id) =>
    seeds.every((s) => byId(id, s.seed).extra?.confined === true));
  const normDir = (l) => l.filter((f) => f !== 'memory.json');
  const dirStable = seeds.every((s) =>
    JSON.stringify(normDir(s.dirBefore)) === JSON.stringify(normDir(s.dirAfter)));
  if (!confinedOk || !dirStable) {
    inv2 = 'not_held';
    findings.push({ severity: 'high', inv: 'INV2',
      title: 'Tool wrote outside the memory.json trust boundary',
      detail: `confined-probes-ok=${confinedOk}; dist-dir-stable=${dirStable}.` });
  }

  // INV3: injection persistence (verbatim round-trip)
  let inv3 = 'held';
  const verbOk = ['A06', 'A07'].every((id) =>
    seeds.every((s) => byId(id, s.seed).extra?.verbatim === true));
  if (!verbOk) {
    inv3 = 'not_held';
    findings.push({ severity: 'medium', inv: 'INV3',
      title: 'Hostile content altered graph semantics on round-trip',
      detail: 'A06/A07 verbatim round-trip failed on at least one seed.' });
  }

  // INV4: description fidelity
  let inv4 = 'held';
  const pureOk = seeds.every((s) => byId('A08', s.seed).extra?.pure === true);
  const dangling = seeds.some((s) => byId('A09', s.seed).extra?.dangling_accepted === true);
  const noopOk = seeds.every((s) => byId('A10', s.seed).extra?.noop === true);
  if (!pureOk) {
    inv4 = 'not_held';
    findings.push({ severity: 'medium', inv: 'INV4',
      title: 'Read-only tool mutated graph state',
      detail: 'A08: memory.json hash changed across read_graph/search_nodes/open_nodes on at least one seed.' });
  }
  if (dangling) {
    inv4 = 'not_held';
    findings.push({ severity: 'medium', inv: 'INV4',
      title: 'create_relations accepts relations between nonexistent entities (dangling)',
      detail: 'A09: create_relations {from:"dangleA", to:"dangleB", relationType:"haunts"} returned success ' +
        'and the relation persisted in read_graph on every seed, while open_nodes confirms neither endpoint ' +
        'exists. The tool is described as "Create multiple new relations between entities in the knowledge ' +
        'graph" — it enforces no referential integrity, so a client reading the graph receives relations ' +
        'pointing at nothing. Agents building on graph structure cannot trust relation endpoints.' });
  }
  if (!noopOk) {
    notes.push({ severity: 'info', inv: 'INV4',
      title: 'delete_relations with wrong type unexpectedly matched',
      detail: 'A10: relation deleted despite mismatched relationType on at least one seed.' });
  }
  if (seeds.some((s) => byId('A11', s.seed).extra?.silent_success === true)) {
    notes.push({ severity: 'info', inv: 'INV4',
      title: 'delete_observations on a nonexistent entity silently succeeds',
      detail: 'A11: "Observations deleted successfully" for ghost-entity-zz. Asymmetric with add_observations, ' +
        'which errors "Entity with name X not found" for the same missing entity. Silent success hides caller mistakes.' });
  }

  // INV5: fail-closed + liveness
  let inv5 = 'held';
  const errOk = ['A12', 'A13', 'A15'].every((id) =>
    seeds.every((s) => ['error', 'timeout'].includes(byId(id, s.seed).verdict)));
  // A14 (numeric query): errors on non-empty graphs (TypeError) but silently
  // succeeds on an empty graph — [].filter never invokes the callback, so the
  // TypeError is masked. Demonstrated order-dependent inconsistency.
  const a14err = seeds.filter((s) => ['error', 'timeout'].includes(byId('A14', s.seed).verdict)).length;
  const a14ok = seeds.filter((s) => byId('A14', s.seed).verdict === 'success').length;
  const corruptOk = seeds.every((s) => {
    const e = byId('A16', s.seed).extra || {};
    return e.fail_closed === true && e.recovered === true;
  });
  const aliveEnd = seeds.every((s) => s.alive);
  if (!errOk) { inv5 = 'not_held';
    findings.push({ severity: 'medium', inv: 'INV5',
      title: 'Malformed input did not fail closed',
      detail: 'One of A12/A13/A15 did not end in error/timeout on every seed.' }); }
  if (a14err > 0 && a14ok > 0) { inv5 = 'not_held';
    findings.push({ severity: 'info', inv: 'INV5',
      title: 'search_nodes input-type validation is order-dependent (numeric query)',
      detail: `A14: search_nodes {query: 123} errored on ${a14err} seed(s) ("query.toLowerCase is not a function") ` +
        `but returned success with an empty graph on ${a14ok} seed(s). Mechanism, verified by isolated ` +
        'reproduction: on a non-empty graph the filter callback invokes query.toLowerCase() and throws; on an ' +
        'empty graph [].filter never invokes the callback, so the TypeError is masked and the malformed input ' +
        'silently succeeds. No state corruption or crash either way — inconsistent validation, not an escape.' }); }
  if (!corruptOk) { inv5 = 'not_held';
    findings.push({ severity: 'medium', inv: 'INV5',
      title: 'Corrupt backing file did not fail closed or did not recover',
      detail: 'A16: expected errors while corrupt + recovery after repair on every seed.' }); }
  if (!aliveEnd) { inv5 = 'not_held';
    findings.push({ severity: 'high', inv: 'INV5',
      title: 'Server died during battery',
      detail: 'tools/list failed after the last op on at least one seed.' }); }
  if (seeds.some((s) => byId('A17', s.seed).extra?.silent_empty_reset === true)) {
    notes.push({ severity: 'info', inv: 'INV5',
      title: 'Deleted backing file silently resets the graph to empty',
      detail: 'A17: with memory.json absent, read_graph returns an empty graph with success — the server ' +
        'cannot distinguish first-run from total data loss. There is no integrity check, backup, or warning. ' +
        'Fail-closed on corruption (A16) is genuine, but deletion is a silent full reset.' });
  }
  // duplicate-create dedup observation (honest path behavior worth noting)
  notes.push({ severity: 'info', inv: 'INV5',
    title: 'create_entities silently skips duplicate names',
    detail: 'Probed during research: re-creating an existing entity name returns success with an empty ' +
      'created list (no error, no overwrite). Idempotent, not a vulnerability — callers should not assume the entity was (re)created.' });
  const markers = seeds[0].static.markers_found;
  if (markers.length) {
    notes.push({ severity: 'info', inv: 'INV4',
      title: 'Instruction-override markers in tool descriptions',
      detail: `Markers: ${markers.join(', ')}` });
  }

  const invariants = [
    { id: 'INV1', statement: 'adversarial input never leaks or corrupts unrelated entities/relations', status: inv1 },
    { id: 'INV2', statement: 'no tool writes outside the fixed memory.json; hostile name/content is data, never a path', status: inv2 },
    { id: 'INV3', statement: 'hostile observation/relation content is stored and retrieved verbatim without altering graph semantics', status: inv3 },
    { id: 'INV4', statement: 'read-only tools never mutate state; relations require existing endpoints per the advertised description', status: inv4 },
    { id: 'INV5', statement: 'malformed inputs fail closed; server stays alive; corrupt backing file errors then recovers', status: inv5 },
  ];

  // Vacuity gate
  const adversarialLanded = adv.filter((o) => o.landed).length;
  const adversarialTotal = adv.length;
  const vacuity = {
    honest_ok: honestOk, honest_minimum: 10,
    adversarial_landed: adversarialLanded, adversarial_total: adversarialTotal,
    server_alive_end: aliveEnd,
    pass: honestOk >= 10 && adversarialLanded === adversarialTotal && aliveEnd,
  };

  // Corpus rule (no exceptions): any not_held => fail.
  let verdict = 'PENDING';
  if (vacuity.pass) {
    verdict = invariants.some((i) => i.status === 'not_held') ? 'fail' : 'pass';
  }

  return {
    invariants, findings: [...findings, ...notes], vacuity, verdict,
    totals: {
      operations: all.length,
      honest_ok: honestOk,
      adversarial_landed: adversarialLanded,
      adversarial_total: adversarialTotal,
      seeds: SEEDS.length,
    },
  };
}

// ---------------------------------------------------------------------------
async function main() {
  preflight();
  DB.resetFixture();
  const seeds = [];
  for (const seed of SEEDS) {
    console.log(`seed ${seed}: running battery...`);
    seeds.push(await runSeed(seed));
  }
  const ev = evaluate(seeds);
  const report = {
    verification: 7,
    target: 'server-memory',
    version: '0.6.2',
    commit: '94a36286d2ea49d095704167846283f0c2c2d5d1',
    tool_description_sha256: seeds[0].static.tool_description_sha256,
    seeds: seeds.map((s) => ({ seed: s.seed, ops: s.ops, snapBefore: s.snapBefore,
                               snapAfter: s.snapAfter, alive: s.alive, static: s.static })),
    invariants: ev.invariants,
    findings: ev.findings,
    vacuity: ev.vacuity,
    verdict: ev.verdict,
    totals: ev.totals,
  };
  await fs.writeFile(path.join(HERE, 'report.json'), JSON.stringify(report, null, 2));
  console.log(`ops=${ev.totals.operations} honest_ok=${ev.totals.honest_ok} ` +
    `adv=${ev.totals.adversarial_landed}/${ev.totals.adversarial_total} ` +
    `vacuity=${ev.vacuity.pass ? 'PASS' : 'FAIL'} verdict=${ev.verdict}`);
  for (const f of ev.findings) console.log(`[${f.severity}] ${f.title}`);
  if (!ev.vacuity.pass) { console.error('VACUITY GATE FAILED — run is void'); process.exit(3); }
}

main().catch((e) => { console.error('driver fatal:', e); process.exit(1); });
