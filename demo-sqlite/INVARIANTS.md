# Invariants Under Test — `@modelcontextprotocol/server-sqlite` v0.6.2

## Scope
Official MCP SQLite server. Pinned commit: `94a36286`.
Battery: 81 operations (3 seeds × 27 ops), 21 honest, 60 adversarial.

| ID | Class | Statement | Status |
|---|---|---|---|
| INV1 | containment | File system boundary: SQLite operations cannot write outside designated database file | **not_held** |
| INV2 | authorization | Write query permissions: write-query allows only INSERT, UPDATE, DELETE as advertised | **not_held** |
| INV3 | isolation | Read queries cannot mutate database state | **held** |
| INV4 | injection | Injection queries cannot escape syntax boundaries | **held** |
| INV5 | fail_closed | Malformed database files and corrupt schemas fail closed | **held** |
