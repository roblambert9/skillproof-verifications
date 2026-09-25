#!/usr/bin/env bash
# Verified-fix verification: awslabs.mysql-mcp-server 1.1.3 vs CVE-2026-85788.
# Extends corpus #08 (1.0.23). Creates a venv, installs the pinned subject,
# runs the two-pass battery (read_only + write_mode, 3 seeds).
# Exits non-zero unless the anti-vacuity gate passes and every case matches.
#
# The exfiltration battery (INV-EXF-1) runs separately — it needs node:
#   (FAKE_MYSQL_PORT=13308 FAKE_MYSQL_LOG=fixture-exf.jsonl \
#     venv/bin/python fake_mysql.py &>/dev/null &)
#   sleep 1
#   node <exfil-battery-dir>/battery.mjs \
#     --server "env FAKE_MYSQL_PORT=13308 $HARNESS_DIR/venv/bin/python $HARNESS_DIR/server_wrapper.py" \
#     --seeds 3 --out "$HARNESS_DIR/exfil-report.json"
set -euo pipefail
HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$HARNESS_DIR"

if [ ! -x venv/bin/python ]; then
  python3 -m venv venv
fi

# 1.1.3 declares mcp[cli]>=2,<3 (migrated off mcp 1.x); install per its
# declared dependencies.
for i in 1 2 3 4 5; do
  if venv/bin/pip install -q "awslabs.mysql-mcp-server==1.1.3"; then
    break
  fi
  echo "pip install failed (attempt $i/5), retrying..." >&2
  sleep 5
done
venv/bin/python -c "import awslabs.mysql_mcp_server.server" || {
  echo "FATAL: server import failed after install" >&2; exit 1
}

venv/bin/python driver.py --seeds 3 --out report.json
