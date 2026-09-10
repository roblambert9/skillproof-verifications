# Invariants Under Test — `@modelcontextprotocol/server-postgres` v0.6.2

## Scope
Official MCP postgres server. Pinned commit: `94a36286`.
Transport: stdio. Battery: 96 operations (3 seeds × 32 ops), 18 honest, 78 adversarial.

| ID | Class | Statement | Status |
|---|---|---|---|
| INV1 | authorization | Read-only enforcement: queries executed via read-query cannot modify state or escape read-only boundaries | **not_held** |
| INV2 | description_fidelity | Tool description accuracy: advertised capability matches actual execution behavior | **not_held** |
| INV3 | isolation | Connection pool and session isolation: transaction state does not leak across queries | **held** |
| INV4 | injection | Parameterized queries and escaping: input values cannot alter query semantics | **held** |
| INV5 | fail_closed | Malformed SQL and network errors fail closed; server remains operational | **held** |
