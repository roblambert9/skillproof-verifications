#!/usr/bin/env bash
# SkillProof demo — first public Trust Manifest verification.
# Fresh-machine flow: fetch target -> build -> run battery -> issue signed manifest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET_PARENT="${SKILLPROOF_TARGET_PARENT:-/tmp/mcp-target}"
export MCP_SERVER_DIR="$TARGET_PARENT/servers/src/filesystem"
export MCP_CLONE_DIR="$TARGET_PARENT/servers"
export SKILLPROOF_FIXTURE="${SKILLPROOF_FIXTURE:-/tmp/skillproof}"

echo "==> 1/4 fetching @modelcontextprotocol/server-filesystem (pinned commit d73f99e)"
PINNED_COMMIT="d73f99efbfd40c3aa1b61e88728b3d49fb52608f"   # commit actually verified (see trust-manifest.json)
if [ ! -d "$MCP_CLONE_DIR/.git" ]; then
  mkdir -p "$TARGET_PARENT"
  git init -q "$MCP_CLONE_DIR"
  git -C "$MCP_CLONE_DIR" remote add origin https://github.com/modelcontextprotocol/servers.git
  git -C "$MCP_CLONE_DIR" config core.sparseCheckout true
  echo "src/filesystem/" > "$MCP_CLONE_DIR/.git/info/sparse-checkout"
  git -C "$MCP_CLONE_DIR" fetch --depth 1 origin "$PINNED_COMMIT"
  git -C "$MCP_CLONE_DIR" checkout -q "$PINNED_COMMIT"
  git -C "$MCP_CLONE_DIR" show "$PINNED_COMMIT":tsconfig.json > "$MCP_CLONE_DIR/tsconfig.json"
else
  echo "    (already present, skipping fetch)"
fi

echo "==> 2/4 building the server"
cd "$MCP_SERVER_DIR"
if [ ! -d node_modules ]; then
  npm install --no-audit --no-fund --legacy-peer-deps -q
fi
npm run build -q

echo "==> 3/4 running the adversarial battery (3 seeds)"
node "$ROOT/harness/driver.mjs"

echo "==> 4/4 issuing the signed Trust Manifest"
node "$ROOT/harness/issue-manifest.mjs"

echo ""
echo "Done. See RESULTS.md, trust-manifest.json, harness/report.json."
