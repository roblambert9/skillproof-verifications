#!/usr/bin/env python3
"""Verified-fix battery: awslabs.mysql-mcp-server 1.1.3 vs CVE-2026-85788.

Extends corpus #08 (1.0.23, 2026-09-21). The 1.1.x line adds a second
hardening wave (CWE-184 follow-up) to the read-only gate that #08 never
tested: statement-anchored mutating verbs, #-comment stripping, rejection
of side-effecting functions and security-sensitive session variables in
BOTH read and write mode. This battery covers both waves.

Two passes:
  read_only  - default server mode; full honest + adversarial set.
  write_mode - server launched with --allow_write_query; honest reads must
               still execute, and the both-mode rejections (side-effecting
               functions, security-sensitive SET) must still block.

INVARIANTS (defined before execution, from code + CHANGELOG reading):
  INV-RO-1 (authorization): CVE-2026-85788 regression — read-only mode
      blocks mutating statements obfuscated with SQL inline comments
      (versioned /*!...*/, /**/ fragmentation, leading/trailing) — the
      exact 1.0.23 fix must still hold on 1.1.3.
  INV-RO-2 (authorization): statement-leading mutating verbs blocked —
      DO, REPLACE-leading, BEGIN/START/COMMIT/ROLLBACK/SAVEPOINT/RELEASE/XA,
      CHANGE/PURGE/STOP/BINLOG, CLONE/RESTART/SHUTDOWN, USE, CACHE/LOAD INDEX,
      IMPORT (the CWE-184 follow-up; new in 1.1.x).
  INV-RO-3 (authorization): comment-hidden leading verbs blocked — no-space
      `#` line comments, `/* */`, `--` prefixes hiding a leading verb.
  INV-RO-4 (authorization): side-effecting functions rejected even in
      read-shaped queries — GET_LOCK/RELEASE_LOCK/SYS_EXEC/MASTER_POS_WAIT/
      SLEEP in SELECT form, LAST_INSERT_ID(expr).
  INV-RO-5 (authorization): security-sensitive session variables rejected —
      SET sql_log_bin/foreign_key_checks/unique_checks = 0 and variants.
  INV-RO-6 (authorization): plain (non-obfuscated) mutating statements are
      blocked in read-only mode and never reach the database (regression).
  INV-READ-1 (data_flow): honest read-only statements execute and return rows.
  INV-READ-2 (data_flow): no false-positive over-blocking — benign reads the
      vendor explicitly designed the anchored scan to allow (SELECT start..,
      SELECT REPLACE(..), USE INDEX hint, 'things to do' literal, get_lock
      column, LAST_INSERT_ID()) must execute.
  INV-INJ-1 (authorization): injection-shaped queries rejected, never reach DB.
  INV-EXF-1 (data_flow): exfiltration battery EXF1-EXF5 (run separately via
      battery.mjs; results merged into report.json).

Anti-vacuity (per pass): >=10 honest successes per seed on average, every
adversarial case produces an observed server verdict, server alive at end.
"""
import argparse
import asyncio
import json
import os
import random
import socket
import subprocess
import sys
import time

SCR = os.path.dirname(os.path.abspath(__file__))
RO_PORT = 13306
WM_PORT = 13307

# Queries the asyncmy connection pool emits itself on session setup in
# read-only mode (observed 2026-09-25). Excluded from the reached_db check
# by exact match: attack payloads use lowercase for the transaction-control
# verbs (the gate is case-insensitive), so a real bypass would still show
# up as a lowercase log entry.
PROTOCOL_QUERIES = frozenset({
    "START TRANSACTION",
    "SET TRANSACTION READ ONLY",
    "SET AUTOCOMMIT = 0",
    "ROLLBACK",
})

# (case_id, sql, expect, invariant, marker)
# expect: 'exec' (rows returned) | 'block' (error dict returned)
# marker: distinctive substring used to check the fixture query log
HONEST = [
    ("H-01", "SELECT 1", "exec", "INV-READ-1", "SELECT 1"),
    ("H-02", "SELECT * FROM users WHERE id = 1", "exec", "INV-READ-1", "FROM users WHERE id = 1"),
    ("H-03", "SELECT name, email FROM customers ORDER BY name LIMIT 10", "exec", "INV-READ-1", "FROM customers"),
    ("H-04", "SHOW TABLES", "exec", "INV-READ-1", "SHOW TABLES"),
    ("H-05", "SELECT COUNT(*) AS n FROM orders", "exec", "INV-READ-1", "FROM orders"),
    ("H-06", "DESCRIBE users", "exec", "INV-READ-1", "DESCRIBE users"),
    ("H-07", "select id from t", "exec", "INV-READ-1", "select id from t"),
    ("H-08", "SELECT 1 /* benign read-only note */", "exec", "INV-READ-1", "SELECT 1"),
    ("H-09", "EXPLAIN SELECT * FROM users", "exec", "INV-READ-1", "EXPLAIN SELECT"),
    ("H-10", "SELECT * FROM users WHERE name = 'O''Brien'", "exec", "INV-READ-1", "O''Brien"),
    ("H-12", "WITH cte AS (SELECT 1 AS x) SELECT * FROM cte", "exec", "INV-READ-1", "WITH cte"),
    # INV-READ-2: no-false-positive cases (vendor's anchored-scan design)
    ("H-13", "SELECT start FROM schedule", "exec", "INV-READ-2", "FROM schedule"),
    ("H-14", "SELECT REPLACE(name, 'a', 'b') FROM users", "exec", "INV-READ-2", "REPLACE(name"),
    ("H-15", "SELECT * FROM users USE INDEX (idx_name)", "exec", "INV-READ-2", "USE INDEX"),
    ("H-16", "SELECT * FROM users WHERE note = 'things to do'", "exec", "INV-READ-2", "things to do"),
    ("H-17", "SELECT get_lock FROM advisory_locks", "exec", "INV-READ-2", "FROM advisory_locks"),
    ("H-18", "SELECT LAST_INSERT_ID()", "exec", "INV-READ-2", "LAST_INSERT_ID()"),
    # H-11 retired 2026-09-21 (carried over): `SELECT * FROM t WHERE x = 1;
    # -- trailing comment` is stacked-query-shaped AFTER comment stripping,
    # so the injection filter correctly blocks it. Lives in INV-INJ-1 as J-11.
]

# Read-only pass adversarial cases.
ADV_RO = [
    # INV-RO-1: CVE-2026-85788 regression (comment-obfuscated mutations)
    ("R1-01", "/*!50000DROP TABLE users*/", "block", "INV-RO-1", "DROP TABLE users"),
    ("R1-02", "SELECT * FROM users WHERE id = 1 /*!50000UNION SELECT password FROM admins*/", "block", "INV-RO-1", "UNION SELECT password"),
    ("R1-03", "INSERT/**/INTO users VALUES (1, 'x')", "block", "INV-RO-1", "INTO users VALUES"),
    ("R1-05", "DROP/**/TABLE users", "block", "INV-RO-1", "TABLE users"),
    ("R1-06", "UP/**/DATE users SET name='x'", "block", "INV-RO-1", "DATE users SET"),
    ("R1-07", "/* lead */ DELETE FROM users", "block", "INV-RO-1", "DELETE FROM users"),
    ("R1-08", "DELETE FROM users -- trailing", "block", "INV-RO-1", "DELETE FROM users --"),
    ("R1-09", "/**/TRUNCATE TABLE users/**/", "block", "INV-RO-1", "TRUNCATE TABLE users"),
    ("R1-10", "/*!40101 SET sql_log_bin=0 */", "block", "INV-RO-1", "sql_log_bin=0"),
    ("R1-11", "CREATE/**/TABLE evil (id INT)", "block", "INV-RO-1", "TABLE evil"),
    # INV-RO-2: statement-leading mutating verbs (CWE-184 follow-up)
    ("D-01", "DO GET_LOCK('probe', 1)", "block", "INV-RO-2", "DO GET_LOCK"),
    ("D-02", "DO SLEEP(1)", "block", "INV-RO-2", "DO SLEEP"),
    ("D-03", "BEGIN", "block", "INV-RO-2", "BEGIN"),
    # Lowercase: the asyncmy pool emits uppercase START TRANSACTION / COMMIT /
    # ROLLBACK on session setup; lowercase payloads stay distinguishable in
    # the fixture log (gate regexes are all case-insensitive).
    ("D-04", "start transaction", "block", "INV-RO-2", "start transaction"),
    ("D-05", "commit", "block", "INV-RO-2", "commit"),
    ("D-06", "rollback", "block", "INV-RO-2", "rollback"),
    ("D-07", "USE information_schema", "block", "INV-RO-2", "USE information_schema"),
    ("D-08", "REPLACE users SET name='x'", "block", "INV-RO-2", "REPLACE users SET"),
    ("D-09", "SHUTDOWN", "block", "INV-RO-2", "SHUTDOWN"),
    ("D-10", "SELECT 1; commit", "block", "INV-RO-2", "; commit"),
    ("D-11", "SAVEPOINT sp1", "block", "INV-RO-2", "SAVEPOINT sp1"),
    ("D-12", "XA START 'xid1'", "block", "INV-RO-2", "XA START"),
    ("D-13", "PURGE BINARY LOGS", "block", "INV-RO-2", "PURGE BINARY LOGS"),
    ("D-14", "IMPORT TABLE FROM '/tmp/x.ibd'", "block", "INV-RO-2", "IMPORT TABLE"),
    ("D-15", "CLONE LOCAL DATA DIRECTORY = '/tmp/clone'", "block", "INV-RO-2", "CLONE LOCAL"),
    # INV-RO-3: comment-hidden leading verbs
    ("C-01", "#x\nDO GET_LOCK('probe', 1)", "block", "INV-RO-3", "#x"),
    ("C-02", "#c\nSHUTDOWN", "block", "INV-RO-3", "#c"),
    ("C-03", "/* hidden */ DO SLEEP(1)", "block", "INV-RO-3", "hidden */ DO"),
    ("C-04", "-- hidden\nBEGIN", "block", "INV-RO-3", "hidden"),
    # INV-RO-4: side-effecting functions in read-shaped queries
    ("F-01", "SELECT GET_LOCK('probe', 1)", "block", "INV-RO-4", "SELECT GET_LOCK"),
    ("F-02", "SELECT RELEASE_LOCK('probe')", "block", "INV-RO-4", "RELEASE_LOCK('probe')"),
    ("F-03", "SELECT SYS_EXEC('id')", "block", "INV-RO-4", "SYS_EXEC"),
    ("F-04", "SELECT MASTER_POS_WAIT('binlog.000001', 107)", "block", "INV-RO-4", "MASTER_POS_WAIT"),
    ("F-05", "SELECT LAST_INSERT_ID(5)", "block", "INV-RO-4", "LAST_INSERT_ID(5)"),
    ("F-06", "SELECT * FROM users WHERE SLEEP(1)", "block", "INV-RO-4", "WHERE SLEEP"),
    # INV-RO-5: security-sensitive session variables (read-only pass)
    ("V-01", "SET sql_log_bin = 0", "block", "INV-RO-5", "sql_log_bin = 0"),
    ("V-02", "SET SESSION sql_log_bin = 0", "block", "INV-RO-5", "SESSION sql_log_bin"),
    ("V-03", "SET @@session.foreign_key_checks = 0", "block", "INV-RO-5", "foreign_key_checks"),
    ("V-04", "SET @x = 1, unique_checks = 0", "block", "INV-RO-5", "unique_checks = 0"),
    ("V-05", "SET GLOBAL sql_log_bin = 0", "block", "INV-RO-5", "GLOBAL sql_log_bin"),
    # INV-RO-6: plain mutations (regression)
    ("R2-01", "INSERT INTO users VALUES (1, 'x')", "block", "INV-RO-6", "INSERT INTO users"),
    ("R2-02", "UPDATE users SET name='x'", "block", "INV-RO-6", "UPDATE users SET"),
    ("R2-03", "DELETE FROM users", "block", "INV-RO-6", "DELETE FROM users"),
    ("R2-04", "DROP TABLE users", "block", "INV-RO-6", "DROP TABLE users"),
    ("R2-05", "CREATE TABLE evil (id INT)", "block", "INV-RO-6", "CREATE TABLE evil"),
    ("R2-06", "ALTER TABLE users ADD COLUMN x INT", "block", "INV-RO-6", "ALTER TABLE users"),
    ("R2-07", "TRUNCATE TABLE users", "block", "INV-RO-6", "TRUNCATE TABLE users"),
    ("R2-08", "GRANT SELECT ON *.* TO 'u'@'%'", "block", "INV-RO-6", "GRANT SELECT"),
    ("R2-09", "SET sql_mode = 'TRADITIONAL'", "block", "INV-RO-6", "sql_mode"),
    ("R2-10", "CALL update_stats()", "block", "INV-RO-6", "CALL update_stats"),
    ("R2-11", "REPLACE INTO users VALUES (1)", "block", "INV-RO-6", "REPLACE INTO users"),
    ("R2-12", "LOAD DATA INFILE '/tmp/f.csv' INTO TABLE t", "block", "INV-RO-6", "LOAD DATA INFILE"),
    # INV-INJ-1: injection shapes
    ("J-01", "SELECT * FROM users WHERE name = '' OR '1'='1'", "block", "INV-INJ-1", "OR '1'='1'"),
    ("J-02", "SELECT * FROM users WHERE id = 1 OR 1=1", "block", "INV-INJ-1", "OR 1=1"),
    ("J-03", "SELECT * FROM t UNION SELECT password FROM admins", "block", "INV-INJ-1", "UNION SELECT password"),
    ("J-04", "SELECT 1; DROP TABLE users", "block", "INV-INJ-1", "DROP TABLE users"),
    ("J-05", "SELECT * FROM users INTO OUTFILE '/tmp/out.txt'", "block", "INV-INJ-1", "INTO OUTFILE"),
    ("J-06", "SELECT LOAD_FILE('/etc/passwd')", "block", "INV-INJ-1", "LOAD_FILE"),
    ("J-07", "SELECT SLEEP(5)", "block", "INV-INJ-1", "SLEEP(5)"),
    ("J-08", "SELECT BENCHMARK(100000, MD5('x'))", "block", "INV-INJ-1", "BENCHMARK("),
    ("J-09", "SELECT * FROM users INTO DUMPFILE '/tmp/d'", "block", "INV-INJ-1", "INTO DUMPFILE"),
    ("J-10", "SELECT * FR/**/OM users INTO OUTFILE '/tmp/x'", "block", "INV-INJ-1", "INTO OUTFILE"),
    ("J-11", "SELECT * FROM t WHERE x = 1; -- trailing comment\nSELECT 2", "block", "INV-INJ-1", "trailing comment"),
]

# Write-mode pass: honest reads + both-mode rejections only.
# (Plain mutations are ALLOWED in write mode by design — excluded here.)
ADV_WM = [c for c in ADV_RO if c[3] in ("INV-RO-4", "INV-RO-5")]

# DEBUNKED (not violations — see debunk log in RESULTS.md):
DEBUNKED = [
    {"case": "R1-04", "sql": "DEL/**/ETE FROM users",
     "classification": "harness_artifact_not_finding",
     "reason": "Gate passes it (correctly: not a valid DELETE on MySQL); "
               "fixture 'executes' anything; real MySQL returns syntax error. "
               "Three-source oracle: mysql lex_one_token source, independent "
               "lexer lecture, sqlglot MySQL tokenizer -> two tokens. "
               "Carried over from corpus #08 (2026-09-21)."},
    {"case": "D-04/D-05/D-06/D-10 (first run)",
     "sql": "START TRANSACTION / COMMIT / ROLLBACK / SELECT 1; COMMIT",
     "classification": "harness_artifact_not_finding",
     "reason": "All four were correctly blocked by the readonly_gate; the "
               "'reached_db=True' signal came from the asyncmy pool's own "
               "session-setup queries (START TRANSACTION, SET TRANSACTION "
               "READ ONLY, SET AUTOCOMMIT = 0, ROLLBACK — 52x each in the "
               "fixture log), which collided with the uppercase markers. "
               "Harness fixed: protocol queries excluded by exact match; "
               "transaction-control payloads lowercased (gate is "
               "case-insensitive). Re-run: 0 unexpected."},
]

INVARIANTS = {
    "INV-RO-1": "CVE-2026-85788 regression: read-only mode blocks mutating statements obfuscated with SQL inline comments (versioned /*!...*/, /**/ fragmentation, leading/trailing comments) — the 1.0.23 fix still holds on 1.1.3.",
    "INV-RO-2": "Statement-leading mutating verbs are blocked in read-only mode (CWE-184 follow-up, new in 1.1.x): DO, REPLACE-leading, BEGIN/START/COMMIT/ROLLBACK/SAVEPOINT/RELEASE/XA, CHANGE/PURGE/STOP/BINLOG, CLONE/RESTART/SHUTDOWN, USE, CACHE/LOAD INDEX, IMPORT.",
    "INV-RO-3": "Comment-hidden leading verbs are blocked: no-space `#` line comments, `/* */`, `--` prefixes hiding a statement-leading verb (the _strip_mysql_hash_comments fix).",
    "INV-RO-4": "Side-effecting functions are rejected even in read-shaped queries: GET_LOCK/RELEASE_LOCK/SYS_EXEC/MASTER_POS_WAIT/SLEEP in SELECT form, LAST_INSERT_ID(expr) — in both read and write mode.",
    "INV-RO-5": "Security-sensitive session variables are rejected (SET sql_log_bin/foreign_key_checks/unique_checks = 0 and variants) — in both read and write mode.",
    "INV-RO-6": "Plain (non-obfuscated) mutating statements are blocked in read-only mode and never reach the database (regression from #08).",
    "INV-READ-1": "Honest read-only statements execute correctly and return rows through the database.",
    "INV-READ-2": "No false-positive over-blocking: benign reads the anchored scan was designed to allow (SELECT start.., SELECT REPLACE(..), USE INDEX hint, 'things to do' literal, get_lock column, LAST_INSERT_ID()) execute.",
    "INV-INJ-1": "Injection-shaped queries (tautologies, UNION exfil, stacked statements, INTO OUTFILE/DUMPFILE, LOAD_FILE, time probes) are rejected and never reach the database.",
    "INV-EXF-1": "Exfiltration battery EXF1-EXF5: tool metadata and results contain no exfiltration directives; canary values do not leave the trust boundary.",
}


def wait_port(port, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def fixture_queries(log_path):
    out = []
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return [q.get("sql", "") for q in out
            if q.get("cmd") == "QUERY" and q.get("sql", "") not in PROTOCOL_QUERIES]


async def run_pass(seeds, log_path, port, write_mode, pass_name):
    from mcp.client.stdio import stdio_client
    from mcp import ClientSession, StdioServerParameters

    env = {**os.environ, "FAKE_MYSQL_PORT": str(port)}
    if write_mode:
        env["ALLOW_WRITE_QUERY"] = "1"
    params = StdioServerParameters(
        command=os.path.join(SCR, "venv", "bin", "python"),
        args=[os.path.join(SCR, "server_wrapper.py")],
        env=env,
    )
    base = {"connection_method": "mysqlwire", "cluster_identifier": "",
            "db_endpoint": "127.0.0.1", "database": "app"}
    adversarial = ADV_WM if write_mode else ADV_RO
    report = {"pass": pass_name, "write_mode": write_mode,
              "invariants": {k: {"statement": v, "cases": []} for k, v in INVARIANTS.items()
                             if k != "INV-EXF-1" or not write_mode},
              "seeds": [], "totals": {}}
    # In write mode, invariants INV-RO-1/2/3/6 and INV-INJ-1 are not exercised
    # by design (plain mutations are allowed there); only F/V series run.
    totals = {"operations": 0, "honest_ok": 0, "adversarial_landed": 0,
              "adversarial_blocked": 0, "unexpected": 0}

    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            report["tools"] = tools
            for req in ("run_query", "connect_to_database", "is_database_connected",
                        "get_table_schema"):
                assert req in tools, f"missing tool {req}"
            conn = await s.call_tool("connect_to_database", {
                "region": "us-east-1", "database_type": "mysql",
                "port": port, **base})
            assert "connection_method" in conn.content[0].text, "connect failed"

            for seed in range(seeds):
                rng = random.Random(1000 + seed)
                cases = HONEST + adversarial
                order = list(range(len(cases)))
                rng.shuffle(order)
                seed_rec = {"seed": seed, "results": []}
                for idx in order:
                    cid, sql, expect, inv, marker = cases[idx]
                    try:
                        res = await s.call_tool("run_query", {"sql": sql, **base})
                        if res.content:
                            text = res.content[0].text
                            payload = json.loads(text)
                        else:
                            sc = getattr(res, "structuredContent", None) or {}
                            payload = sc.get("result", [])
                            text = json.dumps(payload)
                    except Exception as e:
                        print(f"CASE-FAIL pass={pass_name} seed={seed} case={cid} sql={sql!r} err={e!r}", flush=True)
                        raise
                    is_error = isinstance(payload, dict) and "error" in payload
                    rows = (not is_error) and isinstance(payload, (list, dict))
                    err_text = json.dumps(payload) if is_error else ""
                    gate = None
                    if is_error:
                        if "only allows readonly" in err_text:
                            gate = "readonly_gate"
                        elif "suspicious" in err_text or "injection" in err_text.lower():
                            gate = "injection_filter"
                        else:
                            gate = "other_error"
                    seen = any(marker in q for q in fixture_queries(log_path))
                    if expect == "exec":
                        ok = rows and seen
                    else:
                        ok = is_error and not seen
                    if expect == "exec" and ok:
                        totals["honest_ok"] += 1
                    if expect == "block":
                        totals["adversarial_landed"] += 1  # observed server verdict
                        if ok:
                            totals["adversarial_blocked"] += 1
                    totals["operations"] += 1
                    if not ok:
                        totals["unexpected"] += 1
                    rec = {"case": cid, "invariant": inv, "expect": expect,
                           "observed": "blocked" if is_error else "executed",
                           "gate": gate, "reached_db": seen, "as_expected": ok,
                           "payload_repr": repr(payload)[:300],
                           "sql": sql}
                    seed_rec["results"].append(rec)
                    if inv in report["invariants"]:
                        report["invariants"][inv]["cases"].append(rec)
                report["seeds"].append(seed_rec)

            live = await s.call_tool("run_query", {"sql": "SELECT 1", **base})
            report["server_alive_at_end"] = '"c"' in live.content[0].text or "'c'" in live.content[0].text

    for inv, data in report["invariants"].items():
        bad = [c for c in data["cases"] if not c["as_expected"]]
        data["status"] = "held" if not bad else "violated"
        data["operations_tested"] = len(data["cases"])
        data["failures"] = [{"case": c["case"], "sql": c["sql"],
                             "observed": c["observed"], "gate": c["gate"],
                             "reached_db": c["reached_db"]} for c in bad]

    report["totals"] = totals
    report["anti_vacuity"] = {
        "honest_minimum": 10,
        "honest_ok_min_across_seeds": totals["honest_ok"] // seeds,
        "adversarial_all_landed": totals["adversarial_landed"] == len(adversarial) * seeds,
        "server_alive_at_end": report["server_alive_at_end"],
    }
    report["anti_vacuity"]["pass"] = (
        report["anti_vacuity"]["honest_ok_min_across_seeds"] >= 10
        and report["anti_vacuity"]["adversarial_all_landed"]
        and report["anti_vacuity"]["server_alive_at_end"]
    )
    return report


def run_one_pass(seeds, log_path, port, write_mode, pass_name):
    if os.path.exists(log_path):
        os.remove(log_path)
    try:
        probe = socket.create_connection(("127.0.0.1", port), timeout=1)
        probe.close()
        raise SystemExit(f"FATAL: port {port} already in use (stale fixture?) — refusing to run")
    except OSError:
        pass
    env = {**os.environ, "FAKE_MYSQL_PORT": str(port), "FAKE_MYSQL_LOG": log_path}
    fx = subprocess.Popen([sys.executable, os.path.join(SCR, "fake_mysql.py")], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_port(port), "fixture did not start"
        assert fx.poll() is None, "fixture process died (bind failed?)"
        report = asyncio.run(run_pass(seeds, log_path, port, write_mode, pass_name))
    finally:
        fx.terminate()
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    full = {"passes": {}, "debunked": DEBUNKED}
    ro = run_one_pass(args.seeds, os.path.join(SCR, "fixture-ro.jsonl"), RO_PORT, False, "read_only")
    full["passes"]["read_only"] = ro
    wm = run_one_pass(args.seeds, os.path.join(SCR, "fixture-wm.jsonl"), WM_PORT, True, "write_mode")
    full["passes"]["write_mode"] = wm

    # EXF-1 merged later from the exfil battery run.
    full["passes"]["read_only"]["invariants"]["INV-EXF-1"] = {"status": "pending_exfil_battery"}

    failed = False
    for pname, pr in full["passes"].items():
        t = pr["totals"]
        print(f"[{pname}] ops={t['operations']} honest_ok={t['honest_ok']} "
              f"adversarial_landed={t['adversarial_landed']} blocked={t['adversarial_blocked']} "
              f"unexpected={t['unexpected']}")
        print(f"[{pname}] vacuity:", "PASS" if pr["anti_vacuity"]["pass"] else "FAIL")
        for inv, d in pr["invariants"].items():
            if inv != "INV-EXF-1":
                print(f"  {inv}: {d['status']} ({d['operations_tested']} ops)")
        if t["unexpected"] or not pr["anti_vacuity"]["pass"]:
            failed = True

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(full, f, indent=2)
    if failed:
        sys.exit(2)


if __name__ == "__main__":
    main()
