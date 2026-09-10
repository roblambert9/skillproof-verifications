#!/usr/bin/env node
/**
 * db-memory.js — fixture lifecycle + snapshot helpers for the memory-server
 * verification. The server is file-backed at a FIXED path:
 *   <dist>/memory.json   (MEMORY_FILE_PATH = path.join(__dirname,'memory.json'))
 * No tool accepts a path, so the file itself is the trust boundary under test.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';

const DIST = process.env.SKILLPROOF_MEMORY_DIST ||
  '/tmp/mcp-target-memory/src/memory/dist';
export const MEMORY_FILE = `${DIST}/memory.json`;

export function resetFixture() {
  try { fs.unlinkSync(MEMORY_FILE); } catch { /* ENOENT = fresh graph */ }
}

/** Byte-hash of memory.json (null when absent), plus entity/relation counts. */
export function snapshot() {
  let bytes = null, lines = 0, entities = 0, relations = 0, valid = true;
  try {
    bytes = fs.readFileSync(MEMORY_FILE);
    const ls = bytes.toString('utf8').split('\n').filter((l) => l.trim() !== '');
    lines = ls.length;
    for (const l of ls) {
      try {
        const o = JSON.parse(l);
        if (o.type === 'entity') entities++;
        else if (o.type === 'relation') relations++;
        else valid = false;
      } catch { valid = false; }
    }
  } catch { /* absent */ }
  return {
    hash: bytes ? createHash('sha256').update(bytes).digest('hex') : null,
    lines, entities, relations, jsonl_valid: valid,
    // line-count invariant: every entity/relation is exactly one JSON line
    line_count_ok: lines === entities + relations,
  };
}

/** File names directly under dist/ (memory.json's directory). */
export function dirListing() {
  try { return fs.readdirSync(DIST).sort(); } catch { return []; }
}

/** Replace memory.json with garbage; returns a restore closure. */
export function corruptFile() {
  let backup = null;
  try { backup = fs.readFileSync(MEMORY_FILE); } catch { /* absent */ }
  fs.writeFileSync(MEMORY_FILE, 'CORRUPT{{{ not json');
  return () => {
    if (backup === null) { try { fs.unlinkSync(MEMORY_FILE); } catch {} }
    else fs.writeFileSync(MEMORY_FILE, backup);
  };
}
