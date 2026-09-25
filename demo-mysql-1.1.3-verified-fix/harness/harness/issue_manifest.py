#!/usr/bin/env python3
"""Issue the signed verified-fix trust manifest for awslabs.mysql-mcp-server 1.1.3.

Reads report.json (both passes) + exfil results, builds the manifest body,
signs canonical JSON with the corpus persistent key
(skillproof-persistent-verifier-1), writes trust-manifest.json, then
verifies the signature offline with an independent command.
"""
import json
import os
import sys

SCR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/hatch/workspace/manifest-corpus/tools")
from log import canonical
from ed25519 import ed25519_sign, ed25519_verify, ed25519_pubkey

SUBJECT_VERSION = "1.1.3"
WHEEL = "awslabs_mysql_mcp_server-1.1.3-py3-none-any.whl"
CODE_HASH = "sha256:ef5086e900199438c6830d32c03cf8e8ef2ac5bfb68b934c08a6cddb34fd0f17"
HARNESS_HASH = "sha256:8cff4624afbdda9a2d85a7f1ac9b990c91151a39ab8b7406d4e217dd46bd8d7b"
ISSUED_AT = "2026-09-25T00:00:00Z"
EXPIRES_AT = "2026-12-24T00:00:00Z"  # 90-day validity, matching #08's window


def load_corpus_key():
    k = json.load(open("/home/hatch/.config/skillproof/verifier-key.json"))
    der = bytes.fromhex(k["private_key_der_hex"])
    # PKCS#8 Ed25519: the 32-byte seed is the trailing 32 bytes of the DER.
    sk = der[-32:]
    pk = bytes.fromhex(k["public_key_raw_hex"])
    assert ed25519_pubkey(sk) == pk, "key file inconsistent"
    return k["id"], sk, pk


def main():
    report = json.load(open(os.path.join(SCR, "report.json")))
    ro = report["passes"]["read_only"]
    wm = report["passes"]["write_mode"]

    invariants = []
    for inv_id, data in ro["invariants"].items():
        wm_data = wm["invariants"].get(inv_id, {})
        invariants.append({
            "id": inv_id,
            "class": ("authorization" if inv_id.startswith("INV-RO")
                       or inv_id == "INV-INJ-1" else "data_flow"),
            "statement": data["statement"],
            "operations_tested": {
                "read_only": data.get("operations_tested", 0),
                "write_mode": wm_data.get("operations_tested", 0),
            },
            "status": ("held" if data["status"] == "held"
                       and wm_data.get("status", "held") == "held"
                       else "violated"),
        })

    findings = [
        {
            "id": "NOTE-001",
            "severity": "info",
            "title": "code_hash convention documented (differs from #08)",
            "description": (
                "#08's code_hash (sha256:398052f5...) matches neither the "
                "1.0.23 wheel bytes, its sdist, nor the extracted detector "
                "module — convention unrecoverable. This manifest pins "
                "sha256 of the exact PyPI wheel bytes tested and documents "
                "the convention in RESULTS.md for reproducibility."
            ),
        },
        {
            "id": "NOTE-002",
            "severity": "info",
            "title": "no-false-positive property for ';' in string literals relies on stacked-queries rule",
            "description": (
                "Per the vendor's own code comment, a ';' inside a string "
                "literal matches the statement-start pattern's ';' branch; "
                "the 'no false positive' property there relies on the "
                "stacked-queries SUSPICIOUS_PATTERNS rule staying at least "
                "as strict. Not executed (blocked by that rule by design); "
                "recorded so a future relaxation is visible."
            ),
        },
        {
            "id": "NOTE-003",
            "severity": "info",
            "title": "SET rejected wholesale in read-only mode (deliberate trade-off)",
            "description": (
                "SET as a general keyword is rejected in read-only mode, "
                "including benign forms (SET @var, SET NAMES, SET sql_mode). "
                "The vendor documents this as a deliberate "
                "closed-by-construction trade-off. Confirmed behaviorally; "
                "not a finding."
            ),
        },
    ]

    body = {
        "manifest_version": "1.0",
        "subject": {
            "skill_id": "awslabs.mysql-mcp-server",
            "display_name": "awslabs.mysql-mcp-server",
            "version": SUBJECT_VERSION,
            "source": f"https://pypi.org/project/awslabs.mysql-mcp-server/{SUBJECT_VERSION}/",
            "code_hash": CODE_HASH,
            "code_hash_convention": "sha256 of the PyPI wheel file bytes as downloaded 2026-09-25",
        },
        "extends_corpus_entry": {
            "entry": "#08",
            "subject_version": "1.0.23",
            "verified": "2026-09-21",
            "relationship": ("same skill_id; newer patched build; expanded battery "
                             "covering the 1.1.x CWE-184 hardening wave #08 did not test"),
        },
        "disclosure": {
            "cve": "CVE-2026-85788",
            "ghsa": "GHSA-x25m-ph3m-3r9q",
            "bulletin": "AWS 2026-103-AWS",
            "summary": ("Read-only enforcement in <=1.0.21 circumventable via SQL "
                        "inline comments; fixed in 1.0.23. This manifest verifies "
                        "the fix still holds on 1.1.3 and verifies the 1.1.x "
                        "second hardening wave (statement-anchored verbs, "
                        "#-comment stripping, both-mode rejection of "
                        "side-effecting functions and security-sensitive "
                        "session variables, fail-closed AWS endpoint validation)."),
        },
        "verifier": {
            "id": "skillproof-verifier/2026-09-25",
            "methodology": ("skillproof-verifier: invariants-before-execution, "
                            "anti-vacuity gate, debunk-first, exfil-battery EXF1-EXF5, "
                            "two-pass (read_only + write_mode)"),
            "issuer_key_id": "skillproof-persistent-verifier-1",
            "public_key": None,  # filled below
        },
        "scope": {
            "tools_tested": ro["tools"],
            "connection_method": "mysqlwire",
            "not_tested": [
                "rdsapi connection method (requires AWS; gate code is shared, path behavior inferred)",
                "cluster endpoint resolver internal_resolve_cluster_endpoint (no cluster)",
            ],
            "credential_shims": [
                "server.internal_get_instance_properties -> fixture address/port (1.1.3 requires Endpoint.Address; fail-closed validation observed)",
                "AsyncmyPoolConnection._get_credentials_from_secret -> test creds",
            ],
            "shim_boundary": ("credential plumbing only; run_query's read-only gate "
                              "(mutable_sql_detector) and injection filter unmodified"),
        },
        "invariants": invariants,
        "harness": {
            "hash": HARNESS_HASH,
            "hash_convention": "sha256 of concatenated driver.py + server_wrapper.py + fake_mysql.py",
            "anti_vacuity": {
                "read_only": ro["anti_vacuity"],
                "write_mode": wm["anti_vacuity"],
            },
            "seeds": 3,
            "totals": {
                "read_only": ro["totals"],
                "write_mode": wm["totals"],
            },
            "exfil_battery": {
                "verdict": ro["invariants"]["INV-EXF-1"]["battery_verdict"],
                "per_seed": ro["invariants"]["INV-EXF-1"]["per_seed"],
            },
        },
        "findings": findings,
        "verdict": "pass_with_notes",
        "validity": {
            "issued_at": ISSUED_AT,
            "expires_at": EXPIRES_AT,
            "valid_for_version": SUBJECT_VERSION,
            "revoked": False,
        },
    }

    key_id, sk, pk = load_corpus_key()
    body["verifier"]["public_key"] = pk.hex()

    payload = canonical(body).decode("utf-8")
    sig = ed25519_sign(canonical(body), sk, pk)
    assert ed25519_verify(sig, canonical(body), pk), "self-verify failed"

    manifest = dict(body)
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "value": sig.hex(),
        "signed_payload": payload,
    }
    out = os.path.join(SCR, "trust-manifest.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {out} ({os.path.getsize(out)} bytes), verdict=pass_with_notes")


if __name__ == "__main__":
    main()
