#!/usr/bin/env node
/**
 * mcp-stdio.js — generic MCP stdio client.
 * Reusable across ALL SkillProof verifications (file-backed, db-backed,
 * api-backed). Target-specific logic lives in harness/adapters/*.
 */
import { spawn } from 'node:child_process';

export function launchServer(command, args, env = {}) {
  const proc = spawn(command, args, {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return proc;
}

export function createClient(proc) {
  let nextId = 1;
  const pending = new Map();
  let buf = '';
  let stderrText = '';
  proc.stdout.on('data', (d) => {
    buf += d.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id !== undefined && pending.has(msg.id)) {
          pending.get(msg.id).resolve(msg);
          pending.delete(msg.id);
        }
      } catch { /* non-JSON stdout noise */ }
    }
  });
  proc.stderr.on('data', (d) => { stderrText += d.toString(); });

  function send(method, params, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        const err = new Error(`mcp-timeout:${method}`);
        err.code = 'MCP_TIMEOUT';
        reject(err);
      }, timeoutMs);
      pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); } });
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  return {
    proc,
    send,
    stderr: () => stderrText,
    async initialize() {
      return send('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'skillproof-driver', version: '1.0' },
      });
    },
    async notifyInitialized() {
      proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    },
    async listTools() { return send('tools/list', {}); },
    async listResources() { return send('resources/list', {}); },
    async readResource(uri) { return send('resources/read', { uri }); },
    async callTool(name, args, timeoutMs = 20000) {
      const res = await send('tools/call', { name, arguments: args }, timeoutMs);
      if (res.error) {
        return { verdict: 'error', text: res.error.message || String(res.error.code), code: res.error.code, ms: 0 };
      }
      const c = res.result?.content?.[0];
      const text = c?.text ?? JSON.stringify(res.result);
      return { verdict: res.result?.isError === true ? 'error' : 'success', text, ms: 0 };
    },
    async close() {
      try { proc.kill('SIGTERM'); } catch { /* already dead */ }
    },
  };
}

/** Classify a tool-call outcome for invariant evaluation. */
export function classifyCall(res) {
  const t = (res.text || '').toLowerCase();
  if (res.verdict === 'timeout') return 'timeout';
  if (res.verdict === 'success') return 'success';
  if (/read.only|25006/i.test(t)) return 'refusal-readonly';
  if (/permission denied|42501/i.test(t)) return 'refusal-permission';
  if (/syntax error|42601|invalid/i.test(t)) return 'refusal-syntax';
  return 'error';
}
