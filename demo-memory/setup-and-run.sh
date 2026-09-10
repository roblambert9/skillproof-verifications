#!/usr/bin/env bash
# SkillProof verification #07 — @modelcontextprotocol/server-memory v0.6.2 (official, TypeScript).
# Fresh-machine flow: fetch pinned commit -> npm install+build -> battery -> manifest.
# No sudo required. No credentials needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
COMMIT="94a36286d2ea49d095704167846283f0c2c2d5d1"
TARGET_PARENT="${SKILLPROOF_MEMORY_SRC_PARENT:-/tmp/mcp-target-memory-07}"
export MCP_MEMORY_DIR="$TARGET_PARENT/src/memory"
DIST="$MCP_MEMORY_DIR/dist"
export SKILLPROOF_MEMORY_BIN="$DIST/index.js"
export SKILLPROOF_MEMORY_DIST="$DIST"

echo "==> 1/5 fetching pinned server source ($COMMIT)"
if [ ! -f "$MCP_MEMORY_DIR/package.json" ]; then
  mkdir -p "$TARGET_PARENT" && cd "$TARGET_PARENT"
  git init -q 2>/dev/null || true
  git remote add origin https://github.com/modelcontextprotocol/servers.git 2>/dev/null || true
  git fetch -q --depth 1 origin tag typescript-servers-0.6.2
  # src/memory/tsconfig.json extends the repo-root tsconfig.json, so both are needed
  git sparse-checkout set --no-cone src/memory /tsconfig.json
  git checkout -q FETCH_HEAD
  test "$(git rev-parse HEAD)" = "$COMMIT"
else
  echo "    (source already present, skipping)"
fi

echo "==> 2/5 installing dependencies and building (tsc)"
if [ ! -x "$SKILLPROOF_MEMORY_BIN" ]; then
  cd "$MCP_MEMORY_DIR"
  # --ignore-scripts: the package 'prepare' hook runs the same build; run it
  # explicitly after install for a deterministic build on sparse checkouts.
  npm install -q --ignore-scripts
  npm run -s build
else
  echo "    (build already present, skipping)"
fi
test -x "$SKILLPROOF_MEMORY_BIN"

echo "==> 3/5 running the adversarial battery (3 seeds x 27 ops)"
node "$ROOT/harness/driver.mjs"

echo "==> 4/5 issuing the signed Trust Manifest"
node "$ROOT/harness/issue-manifest.mjs"

echo "==> 5/5 standalone signature verification"
node "$ROOT/harness/verify-manifest.mjs"
echo "DONE: $ROOT/trust-manifest.json"
