#!/usr/bin/env python3
"""Fake MySQL wire-protocol server (test fixture).

Speaks just enough of the MySQL 4.1+ client protocol for asyncmy to
connect and run COM_QUERY: handshake with mysql_native_password (accepts
any credentials), COM_INIT_DB, COM_PING, COM_QUIT, and COM_QUERY with
canned responses. Every received query is appended to a JSONL log so the
battery can prove which statements reached the database and which were
blocked by the MCP server's read-only gate before touching the wire.

Not a database. No parsing, no storage, no auth enforcement — by design.
"""
import json
import os
import socket
import socketserver
import struct
import sys
import time

PORT = int(os.environ.get("FAKE_MYSQL_PORT", "13306"))
LOG = os.environ.get("FAKE_MYSQL_LOG", "/tmp/fake-mysql-queries.jsonl")

CAPS = 0x00000001 | 0x00000004 | 0x00000008 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000
CLIENT_DEPRECATE_EOF = 0x01000000


def log(obj):
    obj["ts"] = time.time()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def lenenc(n):
    if n < 0xFB:
        return bytes([n])
    if n < 0x10000:
        return b"\xfc" + struct.pack("<H", n)
    if n < 0x1000000:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def lenstr(b):
    return lenenc(len(b)) + b


class Conn:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.seq = 0
        self.client_caps = 0

    def read_packet(self):
        while len(self.buf) < 4:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        ln = struct.unpack("<I", self.buf[:3] + b"\x00")[0]
        self.seq = self.buf[3]
        while len(self.buf) < 4 + ln:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        payload = self.buf[4 : 4 + ln]
        self.buf = self.buf[4 + ln :]
        # Server sequence for the reply is always the client's sequence + 1;
        # sequence numbers run continuously for the life of the connection.
        self.seq = (self.seq + 1) & 0xFF
        return payload

    def send(self, payload):
        header = struct.pack("<I", len(payload))[:3] + bytes([self.seq])
        self.seq = (self.seq + 1) & 0xFF
        self.sock.sendall(header + payload)

    def ok(self, affected=0, last_id=0, status=0x0002, warnings=0):
        self.send(b"\x00" + lenenc(affected) + lenenc(last_id) + struct.pack("<HH", status, warnings))

    def eof(self):
        self.send(b"\xfe" + struct.pack("<HH", 0, 0x0002))

    def handshake(self):
        scramble1 = b"abcdefgh"
        scramble2 = b"ijklmnopqrst"
        payload = (
            b"\x0a"
            + b"8.0.99-fake\x00"
            + struct.pack("<I", 7)
            + scramble1
            + b"\x00"
            + struct.pack("<H", CAPS & 0xFFFF)
            + bytes([33])
            + struct.pack("<H", 0x0002)
            + struct.pack("<H", (CAPS >> 16) & 0xFFFF)
            + bytes([21])
            + b"\x00" * 10
            + scramble2
            + b"\x00"
            + b"mysql_native_password\x00"
        )
        self.seq = 0
        self.send(payload)
        resp = self.read_packet()  # client handshake response, seq 1
        self.client_caps = struct.unpack("<I", resp[:4])[0]
        # accept any credentials
        self.seq = 2
        self.ok()

    def result_set(self):
        # one column "c", one row "1"; self.seq already = client seq + 1
        deprecate = bool(self.client_caps & CLIENT_DEPRECATE_EOF)
        self.send(lenenc(1))
        coldef = (
            lenstr(b"def") + lenstr(b"") + lenstr(b"") + lenstr(b"")
            + lenstr(b"c") + lenstr(b"") + lenenc(0x0C)
            + struct.pack("<H", 33) + struct.pack("<I", 255)
            + bytes([0xFD]) + struct.pack("<H", 0) + bytes([0]) + b"\x00\x00"
        )
        self.send(coldef)
        if not deprecate:
            self.eof()
        self.send(lenstr(b"1"))
        if not deprecate:
            self.eof()
        else:
            self.ok()

    def serve(self):
        self.handshake()  # leaves self.seq at 3 (client's last seq was 1)
        try:
            while True:
                pkt = self.read_packet()  # sets self.seq = client seq + 1
                cmd, arg = pkt[0], pkt[1:]
                if cmd == 0x01:  # COM_QUIT
                    break
                elif cmd == 0x02:  # COM_INIT_DB
                    log({"cmd": "INIT_DB", "db": arg.decode("utf8", "replace")})
                    self.ok()
                elif cmd == 0x0E:  # COM_PING
                    self.ok()
                elif cmd == 0x03:  # COM_QUERY
                    sql = arg.decode("utf8", "replace")
                    log({"cmd": "QUERY", "sql": sql})
                    head = sql.lstrip().upper()
                    if head.startswith(("SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "WITH")):
                        self.result_set()
                    else:
                        self.ok()
                else:
                    log({"cmd": f"UNKNOWN_{cmd:#x}"})
                    self.ok()
        except ConnectionError:
            pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        log({"cmd": "CONNECT", "peer": self.client_address[0]})
        try:
            Conn(self.request).serve()
        except Exception as e:  # never let the fixture die loudly
            log({"cmd": "ERROR", "error": type(e).__name__})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    open(LOG, "w").close()
    with Server(("127.0.0.1", PORT), Handler) as srv:
        print(f"fake-mysql listening on 127.0.0.1:{PORT}, log={LOG}", flush=True)
        srv.serve_forever()
