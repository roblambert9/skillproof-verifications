#!/usr/bin/env bash
# SkillProof demo #02 — mcp-server-fetch verification.
# Fresh-machine flow: fetch target -> venv -> install -> run battery -> issue manifest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET_PARENT="${SKILLPROOF_TARGET_PARENT:-/tmp/mcp-target}"
PINNED_COMMIT="d73f99efbfd40c3aa1b61e88728b3d49fb52608f"   # commit actually verified (see trust-manifest.json)
export MCP_CLONE_DIR="$TARGET_PARENT/servers"
export MCP_FETCH_DIR="$TARGET_PARENT/servers/src/fetch"
export SKILLPROOF_FETCH_PY="${SKILLPROOF_FETCH_PY:-$TARGET_PARENT/fetch-venv/bin/python}"

echo "==> 1/5 fetching mcp-server-fetch (pinned commit ${PINNED_COMMIT:0:7})"
if [ ! -d "$MCP_CLONE_DIR/.git" ]; then
  mkdir -p "$TARGET_PARENT"
  git init -q "$MCP_CLONE_DIR"
  git -C "$MCP_CLONE_DIR" remote add origin https://github.com/modelcontextprotocol/servers.git
  git -C "$MCP_CLONE_DIR" config core.sparseCheckout true
  printf 'src/fetch/\n' > "$MCP_CLONE_DIR/.git/info/sparse-checkout"
  git -C "$MCP_CLONE_DIR" fetch --depth 1 origin "$PINNED_COMMIT"
  git -C "$MCP_CLONE_DIR" checkout -q "$PINNED_COMMIT"
else
  echo "    (already present, skipping fetch)"
fi

echo "==> 2/5 creating venv and installing the server"
if [ ! -x "$SKILLPROOF_FETCH_PY" ]; then
  python3 -m venv "$TARGET_PARENT/fetch-venv"
  "$TARGET_PARENT/fetch-venv/bin/pip" install -q "$MCP_FETCH_DIR"
else
  echo "    (venv already present, skipping install)"
fi

echo "==> 3/5 running the adversarial battery (3 seeds x 21 ops)"
node "$ROOT/harness/driver.mjs"

echo "==> 4/5 issuing the signed Trust Manifest"
node "$ROOT/harness/issue-manifest.mjs"

echo ""
echo "Done. See RESULTS.md, trust-manifest.json, harness/report.json."
