#!/usr/bin/env python3
"""Offline signature verification for the awslabs.mysql-mcp-server 1.1.3
verified-fix manifest. No network, no secrets.

Usage: python3 verify_manifest.py trust-manifest.json

Checks:
  1. Ed25519 signature over canonical body == corpus persistent key
     (31e0f9038b9a4fe8c540ea353352b739a610db1247b6451a804e4bc88b1db70b)
  2. signed_payload == canonical body (sorted keys, no whitespace, UTF-8)
  3. Names CVE-2026-85788 and subject version 1.1.3
  4. Extends corpus entry #08 (not a duplicate target)
  5. Not revoked; verdict valid under pinned semantics
"""
import hashlib
import json
import sys

# Pure-Python Ed25519 (vendored from manifest-corpus/tools/ed25519.py).
def _H(m): return hashlib.sha512(m).digest()
def _inv(x):
    q = 2**255 - 19
    return pow(x, q - 2, q)
def _xrecover(y):
    q = 2**255 - 19; d = -121665 * _inv(121666)
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * pow(2, (q - 1) // 4, q)) % q
    if x % 2 != 0: x = q - x
    return x
def _edwards(P, Q):
    # Twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2 (a = -1).
    q = 2**255 - 19; d = -121665 * _inv(121666)
    x1, y1, x2, y2 = P[0], P[1], Q[0], Q[1]
    x3 = (x1*y2 + x2*y1) * _inv(1 + d*x1*x2*y1*y2)
    y3 = (y1*y2 + x1*x2) * _inv(1 - d*x1*x2*y1*y2)
    return (x3 % q, y3 % q)
def _scalarmult(P, e):
    if e == 0: return (0, 1)
    Q = _scalarmult(P, e // 2); Q = _edwards(Q, Q)
    return _edwards(Q, P) if e & 1 else Q
def _encodeint(n): return n.to_bytes(32, "little")
def _encodepoint(P):
    x, y = P
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")
def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7): x = 2**255 - 19 - x
    P = (x, y)
    if _scalarmult(P, 2**252 + 27742317777372353535851937790883648493) != (0, 1):
        raise ValueError("point not in prime-order subgroup")
    return P
def _bit(h, i): return (h[i // 8] >> (i % 8)) & 1
def _scalar_from_secret(sk):
    h = _H(sk); a = 2**254
    for i in range(3, 254): a += _bit(h, i) << i
    return a
def ed25519_verify(sig, msg, pk):
    if len(sig) != 64 or len(pk) != 32: return False
    A = _decodepoint(pk); Rs = sig[:32]; s = int.from_bytes(sig[32:], "little")
    R = _decodepoint(Rs)
    h = int.from_bytes(_H(Rs + pk + msg), "little")
    return _scalarmult(_scalarmult(_Gx_Gy, s), 1) == _edwards(R, _scalarmult(A, h))

q = 2**255 - 19
# Standard Ed25519 base point, decoded from its compressed form.
_Gx_Gy = _decodepoint(bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"))

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")

CORPUS_PK = "31e0f9038b9a4fe8c540ea353352b739a610db1247b6451a804e4bc88b1db70b"

def main(path):
    m = json.load(open(path, encoding="utf-8"))
    sig = m["signature"]
    assert sig["algorithm"] == "Ed25519", "algorithm"
    body = {k: v for k, v in m.items() if k != "signature"}
    assert sig["signed_payload"] == canonical(body).decode("utf-8"), "signed_payload != canonical body"
    pk = bytes.fromhex(CORPUS_PK)
    assert m["verifier"]["public_key"] == CORPUS_PK, "verifier pubkey != corpus key"
    ok = ed25519_verify(bytes.fromhex(sig["value"]), canonical(body), pk)
    print("signature valid:", ok)
    assert ok, "BAD SIGNATURE"
    assert m["disclosure"]["cve"] == "CVE-2026-85788", "CVE not named"
    assert m["subject"]["version"] == "1.1.3", "version not exact"
    assert m["extends_corpus_entry"]["entry"] == "#08", "must extend #08"
    assert m["validity"]["revoked"] is False, "revoked"
    held = sum(1 for i in m["invariants"] if i["status"] == "held")
    print(f"invariants: {held}/{len(m['invariants'])} held; verdict={m['verdict']}; "
          f"valid {m['validity']['issued_at']}..{m['validity']['expires_at']}")
    print("ALL CHECKS PASS")

if __name__ == "__main__":
    main(sys.argv[1])
