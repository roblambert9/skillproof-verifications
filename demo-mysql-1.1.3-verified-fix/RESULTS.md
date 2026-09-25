# Verified-Fix Manifest — RESULTS (extends corpus #08)

**Subject:** `awslabs.mysql-mcp-server` **1.1.3** (PyPI wheel, downloaded 2026-09-25)
**Code hash:** `sha256:ef5086e900199438c6830d32c03cf8e8ef2ac5bfb68b934c08a6cddb34fd0f17`
(convention: sha256 of the exact PyPI wheel bytes tested; see note below)
**Extends:** corpus entry #08 (`awslabs.mysql-mcp-server` 1.0.23, verified
2026-09-21) — same skill_id, newer patched build, expanded battery.
**Disclosure:** CVE-2026-85788 / GHSA-x25m-ph3m-3r9q — read-only enforcement
in ≤1.0.21 circumventable via SQL inline comments; fixed in 1.0.23 per
AWS bulletin 2026-103-AWS. The 1.1.x line adds a second hardening wave
(CWE-184 follow-up): statement-anchored mutating verbs, no-space `#`
comment stripping, both-mode rejection of side-effecting functions and
security-sensitive session variables, and fail-closed AWS endpoint
validation. This battery covers both waves.
**Verdict:** `pass_with_notes` (all 10 invariants held across both passes;
two info notes, NOTE-002/NOTE-003)
**Date:** 2026-09-25 · **Verifier:** skillproof-verifier/2026-09-25 ·
**Issuer key:** `skillproof-persistent-verifier-1` (corpus key) ·
**Manifest:** `trust-manifest.json` (Ed25519, expires 2026-12-24)

## Battery counts (observed, from `report.json`)

| Metric | read_only pass | write_mode pass |
|---|---|---|
| Total operations | 240 (80 cases × 3 seeds, shuffled per seed) | 84 (28 cases × 3 seeds) |
| Honest successes | 51/51 | 51/51 |
| Adversarial landed | 189/189 (63 per seed) — every one produced an observed server verdict | 33/33 |
| Adversarial blocked | 189/189 — zero reached the database | 33/33 |
| Unexpected outcomes | 0 | 0 |
| Anti-vacuity gate | **PASS** (≥10 honest/seed: 17 · all adversarial landed · server alive at end) | **PASS** (17 · 33/33 · alive) |

## Per-invariant results

| Invariant | Class | Statement | Ops (RO/WM) | Status |
|---|---|---|---|---|
| INV-RO-1 | authorization | CVE-2026-85788 regression: comment-obfuscated mutations blocked | 30 / – | **held** |
| INV-RO-2 | authorization | Statement-leading mutating verbs blocked (CWE-184 follow-up) | 45 / – | **held** |
| INV-RO-3 | authorization | Comment-hidden leading verbs blocked (`#`, `/**/`, `--`) | 12 / – | **held** |
| INV-RO-4 | authorization | Side-effecting functions rejected in read-shaped queries, both modes | 18 / 18 | **held** |
| INV-RO-5 | authorization | Security-sensitive session vars rejected, both modes | 15 / 15 | **held** |
| INV-RO-6 | authorization | Plain mutations blocked, never reach DB (regression) | 36 / – | **held** |
| INV-READ-1 | data_flow | Honest reads execute and return rows | 33 / 33 | **held** |
| INV-READ-2 | data_flow | No false-positive over-blocking on vendor-designed benign reads | 18 / 18 | **held** |
| INV-INJ-1 | authorization | Injection shapes rejected, never reach DB | 33 / – | **held** |
| INV-EXF-1 | data_flow | Exfil battery EXF1–EXF5 | 15 | **held** |

Gate attribution, read-only pass: `readonly_gate` 123
(RO-1: 30, RO-2: 45, RO-3: 12, RO-5: 15, RO-6: 36 — the `SET` keyword fires
before the injection filter; INJ-1: 3 stacked-query shapes hit the keyword
gate first, as in #08); `injection_filter` 66 (RO-4: 18 side-effecting
functions, INJ-1: 30 UNION/tautology/OUTFILE/LOAD_FILE/time probes, plus the
`/*!` conditional-comment stage-1 rejects inside RO-1's count).
Write-mode pass: `injection_filter` 33 (RO-4: 18, RO-5: 15) — the vendor's
"rejected in BOTH read and write mode" claim is **demonstrated**, not inferred:
the read-only gate is disabled in this pass and the injection filter alone
refused every case.

The exact CVE shape `/*!50000DROP TABLE users*/` is refused by the
`MYSQL_CONDITIONAL_COMMENT` stage-1 rule before touching the wire in all
3 seeds, in read-only mode.

## Exfiltration battery (GhostSplice EXF1–EXF5, 3 seeds, read-only server)

**Verdict: pass.** Per seed: `EXF1:held EXF2:held EXF3:info EXF5:held EXF4:held`.
No fetch-like tool exists on this server, so EXF4 ran canary-in-args only
(`get_table_schema`, first arg = `probe-CANARY`): no unexpected egress, no
canary in server stderr. EXF5 probe-arg calls were rejected at validation.
EXF3 is info-only by design. No exfiltration directives in tool metadata or
results.

## What was demonstrated vs inferred (G2)

- **Demonstrated (observed):** every count above is an observed operation in
  `report.json`. 189 read-only adversarial payloads were refused at the MCP
  layer *and* absent from the database query log; 33 write-mode adversarial
  payloads were refused by the injection filter alone; 102 honest queries are
  present in the fixture query logs with rows returned.
- **Attempted:** the D-04/D-05/D-06/D-10 first-run flags (see debunk log) —
  all four were blocked by the gate; the `reached_db` signal was pool chatter.
- **Inferred (not executed):** the RDS Data API path (`rdsapi` connection
  method) was not exercised — it requires AWS. The SQL gate code
  (`mutable_sql_detector`) is shared across connection methods, and the
  CHANGELOG's CWE-184 note specifically calls out the RDS Data API path for
  `DO`-verb bypasses, so path-specific behavior is inferred from the shared
  code, not demonstrated. Likewise the cluster-endpoint resolver
  (`internal_resolve_cluster_endpoint`) was not exercised (no cluster).

## Debunk log

1. **D-04/D-05/D-06/D-10 first run — harness artifact, not a finding.**
   All four transaction-control payloads were correctly blocked by the
   `readonly_gate`, but `reached_db` read True: the asyncmy connection pool
   emits `START TRANSACTION`, `SET TRANSACTION READ ONLY`,
   `SET AUTOCOMMIT = 0`, `ROLLBACK` on session setup (52× each in the
   fixture log), colliding with the uppercase markers. Harness fixed two
   ways: protocol queries excluded from the reached_db check by exact match,
   and transaction-control payloads lowercased (all gate regexes are
   case-insensitive, so the test is undiminished). Re-run: 0 unexpected.
   Side observation, kept: in read-only mode the pool wraps sessions with
   `SET TRANSACTION READ ONLY` — transaction-level defense in depth behind
   the SQL-text gate.
2. **R1-04 (`DEL/**/ETE FROM users`) — carried over from #08 (2026-09-21).**
   Gate passes it (correctly: not a valid DELETE on MySQL); the fixture
   "executes" anything; real MySQL returns syntax error. Three-source
   oracle: mysql `lex_one_token` source, independent lexer lecture, sqlglot
   MySQL tokenizer → two tokens. Not in the must-block set.
3. **Fail-closed endpoint validation blocked the harness itself.**
   1.1.3's standalone-instance path requires
   `instance_properties['Endpoint']['Address']` and refuses to connect to a
   caller-supplied host when AWS returns none ("refusing to connect to a
   caller-supplied host"). The credential shim had to supply the fixture
   address as the AWS-sourced endpoint before `connect_to_database` would
   proceed. This is the new control working as designed — a genuine
   1.1.x hardening (prevents directing credentials/IAM tokens at an
   attacker-controlled host), observed behaviorally, not just read.

## Notes

- **NOTE-001 (info, NEW):** `code_hash` convention differs from #08. #08's
  `sha256:398052f5…` matches neither the 1.0.23 wheel bytes, its sdist, nor
  the extracted `mutable_sql_detector.py`/`server.py` — its convention is
  unrecoverable from available evidence. This manifest pins
  `sha256` of the exact PyPI wheel bytes tested and documents the
  convention here, so the pin is reproducible: re-download
  `awslabs_mysql_mcp_server-1.1.3-py3-none-any.whl` from PyPI and hash it.
- **NOTE-002 (info):** the no-false-positive property for `;` inside string
  literals (e.g. `WHERE note = 'do it; commit later'`) relies on the
  stacked-queries SUSPICIOUS_PATTERNS rule staying at least as strict as the
  statement-start scan — the vendor documents this coupling in a code
  comment. Not executed (would be blocked by the stacked-queries rule, not
  executed); recorded so a future relaxation of that rule is visible.
- **NOTE-003 (info):** `SET` as a general keyword remains rejected in
  read-only mode (R2-09 `SET sql_mode`, all V-series), including benign
  forms (`SET @var`, `SET NAMES`) — the vendor calls this a deliberate
  closed-by-construction trade-off. Confirmed behaviorally; not a finding.

## Findings

None above info severity. No new bypass found in 1.1.3's second hardening
wave; the CVE-2026-85788 fix from 1.0.23 holds on 1.1.3.
