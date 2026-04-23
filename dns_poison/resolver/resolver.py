#!/usr/bin/env python3
"""
Caching DNS Resolver.

Behaviour:
  1. Receives a query from a victim.
  2. Checks its in-memory cache.
  3. On cache miss → forwards the query (with a NEW random txid) to the auth server.
  4. Waits for the auth server's response.
  5. Validates txid and stores the result in cache.
  6. Returns the answer to the victim.

The Kaminsky attack window: between steps 3 and 5.
If the attacker races a spoofed UDP response with a matching txid back to THIS
resolver, and it arrives BEFORE the real auth-server answer, the forged IP gets
cached instead.

INTENTIONAL VULNERABILITY (for lab purposes):
  - Source port is fixed (not randomised per query) → attacker only needs to
    brute-force the 16-bit transaction ID (65535 possibilities).
  - No DNSSEC validation.
  - Cache entries are accepted from any sender claiming to be the auth server.
"""

import socket
import struct
import threading
import time
import random
import os

LISTEN_IP      = "0.0.0.0"
LISTEN_PORT    = int(os.getenv("LISTEN_PORT", 53))
AUTH_IP        = os.getenv("AUTH_IP", "10.0.0.3")
AUTH_PORT      = int(os.getenv("AUTH_PORT", 53))
UPSTREAM_PORT  = int(os.getenv("UPSTREAM_PORT", 5300))  # fixed src port — the vulnerability

cache: dict[str, tuple[str, float]] = {}   # domain → (ip, expiry_timestamp)
cache_lock = threading.Lock()

# Maps resolver-side txid → (original_txid, client_addr, domain)
pending: dict[int, tuple[int, tuple, str]] = {}
pending_lock = threading.Lock()


# ─── DNS helpers ──────────────────────────────────────────────────────────────

def build_query(domain: str, txid: int) -> bytes:
    header   = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)
    return header + question


def build_response(txid: int, domain: str, ip: str) -> bytes:
    """Build a minimal DNS A-record response."""
    header = struct.pack(">HHHHHH",
                         txid,
                         0x8180,   # QR=1, AA=0, RD=1, RA=1
                         1, 1, 0, 0)

    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)

    # Answer: name ptr (0xC00C → offset 12), A, IN, TTL=60, rdlen=4, ip
    answer = struct.pack(">HHIH", 0xC00C, 1, 1, 60)
    answer += struct.pack(">H", 4) + socket.inet_aton(ip)

    return header + question + answer


def decode_domain(data: bytes, offset: int) -> tuple[str, int]:
    """Follow compression pointers and return (domain_str, new_offset)."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 10

    while max_jumps > 0:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                original_offset = offset + 2
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset = ptr
            jumped = True
            max_jumps -= 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def parse_answer_ip(data: bytes) -> tuple[str | None, str | None]:
    """Return (domain, ip) of the first A record answer, or (None, None)."""
    if len(data) < 12:
        return None, None
    txid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if ancount == 0:
        return None, None

    offset = 12
    domain, offset = decode_domain(data, offset)
    offset += 4   # skip QTYPE + QCLASS

    # Parse answers
    for _ in range(ancount):
        _, offset = decode_domain(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntoa(data[offset:offset + 4])
            return domain, ip
        offset += rdlen

    return domain, None


# ─── Upstream socket (fixed port — intentional vulnerability) ─────────────────

upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream_sock.bind(("0.0.0.0", UPSTREAM_PORT))
upstream_sock.settimeout(0.1)


def upstream_listener():
    """
    Thread: listens on the fixed upstream port for auth-server replies.
    Also accepts spoofed replies — that's the attack surface.
    """
    print(f"[RESOLVER] Upstream listener on port {UPSTREAM_PORT} (fixed — vulnerable!)")
    while True:
        try:
            data, addr = upstream_sock.recvfrom(512)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[RESOLVER] Upstream recv error: {e}")
            continue

        if len(data) < 12:
            continue

        resp_txid = struct.unpack(">H", data[:2])[0]
        domain, ip = parse_answer_ip(data)

        with pending_lock:
            entry = pending.pop(resp_txid, None)

        if entry is None:
            print(f"[RESOLVER] Ignoring unsolicited txid=0x{resp_txid:04X} from {addr[0]}")
            continue

        orig_txid, client_addr, queried_domain = entry

        if ip is None:
            print(f"[RESOLVER] Response for {queried_domain} had no A record")
            continue

        source_tag = "AUTH" if addr[0] == AUTH_IP else "*** SPOOFED ***"
        print(f"[RESOLVER] [{source_tag}] txid=0x{resp_txid:04X}  "
              f"{queried_domain} → {ip}  (from {addr[0]})")

        # Cache it (no validation — vulnerable by design)
        with cache_lock:
            cache[queried_domain] = (ip, time.time() + 60)
            print(f"[RESOLVER] Cached: {queried_domain} → {ip}")

        # Reply to the waiting victim
        response = build_response(orig_txid, queried_domain, ip)
        main_sock.sendto(response, client_addr)
        print(f"[RESOLVER] Sent answer to victim {client_addr[0]}: {queried_domain} → {ip}")


# ─── Main listener ─────────────────────────────────────────────────────────────

main_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
main_sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"[RESOLVER] Listening for victim queries on {LISTEN_IP}:{LISTEN_PORT}")
print(f"[RESOLVER] Will forward cache-misses to auth server {AUTH_IP}:{AUTH_PORT}")
print(f"[RESOLVER] Fixed upstream source port: {UPSTREAM_PORT}  ← VULNERABLE")


def handle_victim_query(data: bytes, client_addr: tuple):
    if len(data) < 12:
        return

    orig_txid = struct.unpack(">H", data[:2])[0]
    domain, _ = decode_domain(data, 12)

    print(f"[RESOLVER] Query from {client_addr[0]}  txid=0x{orig_txid:04X}  domain={domain}")

    # Cache hit?
    with cache_lock:
        entry = cache.get(domain)
        if entry and entry[1] > time.time():
            ip, _ = entry
            print(f"[RESOLVER] Cache HIT: {domain} → {ip}")
            resp = build_response(orig_txid, domain, ip)
            main_sock.sendto(resp, client_addr)
            return

    print(f"[RESOLVER] Cache MISS — forwarding to auth server")

    # Pick a new random txid for the upstream query
    new_txid = random.randint(1, 0xFFFF)
    with pending_lock:
        pending[new_txid] = (orig_txid, client_addr, domain)

    query = build_query(domain, new_txid)
    upstream_sock.sendto(query, (AUTH_IP, AUTH_PORT))
    print(f"[RESOLVER] Forwarded to auth  txid=0x{new_txid:04X}  domain={domain}")
    print(f"[RESOLVER] >>> ATTACK WINDOW OPEN — waiting for auth response <<<")


def main():
    t = threading.Thread(target=upstream_listener, daemon=True)
    t.start()

    while True:
        data, client_addr = main_sock.recvfrom(512)
        threading.Thread(target=handle_victim_query,
                         args=(data, client_addr),
                         daemon=True).start()


if __name__ == "__main__":
    main()
