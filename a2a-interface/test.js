#!/usr/bin/env node
/**
 * End-to-end test for the SkillProof A2A reference server.
 * Spawns server.js, exercises every endpoint, asserts the quote math.
 * Exit 0 = all green.
 */
'use strict';
const { spawn } = require('node:child_process');
const path = require('node:path');

const PORT = 18787;
const BASE = `http://localhost:${PORT}`;
let failures = 0;

function check(name, cond, detail) {
  if (cond) { console.log(`  ok   ${name}`); }
  else { failures++; console.error(`  FAIL ${name}${detail ? ' — ' + detail : ''}`); }
}
async function req(method, p, body) {
  const r = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try { json = await r.json(); } catch { /* ignore */ }
  return { status: r.status, json };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(BASE + '/.well-known/skillproof.json');
      if (r.ok) return;
    } catch { /* not up yet */ }
    await sleep(250);
  }
  throw new Error('server did not start in time');
}

(async () => {
  const srv = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), SKILLPROOF_DEMO: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  srv.on('error', (e) => { console.error('spawn failed:', e.message); process.exit(2); });

  try {
    await waitForServer();

    console.log('1. DISCOVER — GET /.well-known/skillproof.json');
    {
      const { status, json } = await req('GET', '/.well-known/skillproof.json');
      check('descriptor 200', status === 200);
      check('service = skillproof', json && json.service === 'skillproof');
      check('4 tiers listed', json && json.tiers && json.tiers.length === 4);
      const fees = Object.fromEntries(json.tiers.map((t) => [t.id, t.fee_usd]));
      check('tier fees sprint=500 standard=1500 rush=2500 continuous=300',
        fees.sprint === 500 && fees.standard === 1500 && fees.rush === 2500 && fees.continuous === 300,
        JSON.stringify(fees));
      check('manifest schema URL present', typeof json.manifest_schema_url === 'string');
      check('revocation endpoint present', typeof json.revocation_endpoint === 'string');
    }

    console.log('2. QUOTE — POST /v1/quote (math assertions)');
    const mkReq = (tier) => ({
      target: { package: 'mcp-server-fetch', version: '0.6.3', transport: 'stdio', repo_url: 'https://github.com/modelcontextprotocol/servers' },
      tier,
      contact: { agent_id: 'agent:test-harness' },
      callback: { webhook_url: 'https://example.test/skillproof-hook' },
    });
    const expectations = {
      sprint:     { fee: 500,  sla: '48h',            recurring: false },
      standard:   { fee: 1500, sla: '5d',             recurring: false },
      rush:       { fee: 2500, sla: '24h',            recurring: false },
      continuous: { fee: 300,  sla: 'per_version_bump', recurring: 'monthly' },
    };
    let sprintQuote = null;
    for (const [tier, exp] of Object.entries(expectations)) {
      const { status, json } = await req('POST', '/v1/quote', mkReq(tier));
      check(`quote/${tier} 200`, status === 200, `got ${status}`);
      check(`quote/${tier} fee_usd=${exp.fee}`, json && json.fee_usd === exp.fee, JSON.stringify(json));
      check(`quote/${tier} sla=${exp.sla}`, json && json.sla === exp.sla, json && json.sla);
      check(`quote/${tier} recurring=${exp.recurring}`, json && json.recurring === exp.recurring);
      check(`quote/${tier} currency USD`, json && json.currency === 'USD');
      check(`quote/${tier} expires_at in future`, json && new Date(json.expires_at).getTime() > Date.now());
      check(`quote/${tier} has quote_id`, json && typeof json.quote_id === 'string');
      if (tier === 'sprint') sprintQuote = json;
    }
    {
      const { status, json } = await req('POST', '/v1/quote', mkReq('platinum'));
      check('unknown tier -> 400', status === 400, `got ${status}`);
      check('400 names the problem', json && JSON.stringify(json).includes('tier'));
    }
    {
      const { status } = await req('POST', '/v1/quote', { tier: 'sprint' });
      check('missing target/contact -> 400', status === 400, `got ${status}`);
    }
    {
      const { status } = await req('POST', '/v1/quote', 'not json{');
      check('malformed JSON -> 400', status === 400, `got ${status}`);
    }

    console.log('3. REQUEST — POST /v1/request');
    let jobId = null, statusUrl = null;
    {
      const { status, json } = await req('POST', '/v1/request', { quote_id: sprintQuote.quote_id });
      check('request 201', status === 201, `got ${status}`);
      check('job starts queued', json && json.status === 'queued');
      check('status_url returned', json && typeof json.status_url === 'string');
      jobId = json.job_id; statusUrl = json.status_url;
    }
    {
      const { status } = await req('POST', '/v1/request', { quote_id: 'q_nope' });
      check('unknown quote -> 404', status === 404, `got ${status}`);
    }

    console.log('4. JOB STATUS — GET /v1/jobs/:id (+ demo lifecycle)');
    {
      const { status, json } = await req('GET', `/v1/jobs/${jobId}`);
      check('job fetch 200', status === 200);
      check('job is queued', json && json.status === 'queued');
      check('manifest_url null while queued', json && json.manifest_url === null);
      check('job carries target pin', json && json.target && json.target.package === 'mcp-server-fetch' && json.target.version === '0.6.3');
    }
    {
      const { status } = await req('GET', '/v1/jobs/job_nope');
      check('unknown job -> 404', status === 404, `got ${status}`);
    }
    {
      const a = await req('POST', `/v1/jobs/${jobId}/advance`, { to: 'running' });
      check('advance queued->running', a.status === 200 && a.json.status === 'running', `got ${a.status}`);
      const b = await req('POST', `/v1/jobs/${jobId}/advance`, { to: 'complete' });
      check('advance running->complete', b.status === 200 && b.json.status === 'complete');
      check('complete carries manifest_url', b.json && typeof b.json.manifest_url === 'string', JSON.stringify(b.json));
      const c = await req('POST', `/v1/jobs/${jobId}/advance`, { to: 'queued' });
      check('illegal transition -> 400', c.status === 400, `got ${c.status}`);
    }
    check('status_url matches', statusUrl === `${BASE}/v1/jobs/${jobId}`);
  } catch (e) {
    failures++;
    console.error('  FAIL harness —', e.message);
  } finally {
    srv.kill('SIGTERM');
    await sleep(300);
  }

  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})();
