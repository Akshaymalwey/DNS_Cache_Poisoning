#!/usr/bin/env python3
"""
Authoritative DNS Server.

Responds to A-record queries with the legitimate IPs defined in ZONE_DATA.
Simulates real-world latency via ARTIFICIAL_DELAY_MS so the attacker has a
window to race its spoofed response to the resolver first.
"""

import socket
import struct
import time
import os

LISTEN_IP           = "0.0.0.0"
LISTEN_PORT         = int(os.getenv("LISTEN_PORT", 53))
ARTIFICIAL_DELAY_MS = int(os.getenv("ARTIFICIAL_DELAY_MS", 200))  # ms, simulates real RTT

# Zone data: domain → legitimate IP
ZONE_DATA: dict[str, str] = {
    "evil.example.com":  "93.184.216.34",   # real (legitimate) IP
    "bank.example.com":  "203.0.113.10",
    "mail.example.com":  "203.0.113.20",
}


def decode_domain(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sub, _ = decode_domain(data, ptr)
            labels.append(sub)
            break
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(labels), offset


def build_response(txid: int, domain: str, ip: str) -> bytes:
    header = struct.pack(">HHHHHH",
                         txid,
                         0x8480,   # QR=1, AA=1 (authoritative), RD=0, RA=0
                         1, 1, 0, 0)
    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)

    answer = struct.pack(">HHIH", 0xC00C, 1, 1, 300)   # TTL = 300s
    answer += struct.pack(">H", 4) + socket.inet_aton(ip)

    return header + question + answer


def build_nxdomain(txid: int, domain: str) -> bytes:
    """Return NXDOMAIN for unknown domains."""
    header = struct.pack(">HHHHHH",
                         txid,
                         0x8483,   # QR=1, AA=1, RCODE=3 (NXDOMAIN)
                         1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)
    return header + question


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[AUTH_SERVER] Authoritative DNS listening on {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[AUTH_SERVER] Zone records: {ZONE_DATA}")
    print(f"[AUTH_SERVER] Artificial response delay: {ARTIFICIAL_DELAY_MS} ms")

    while True:
        data, addr = sock.recvfrom(512)
        if len(data) < 12:
            continue

        txid = struct.unpack(">H", data[:2])[0]
        domain, _ = decode_domain(data, 12)

        ip = ZONE_DATA.get(domain)
        print(f"[AUTH_SERVER] Query from {addr[0]}  txid=0x{txid:04X}  domain={domain}  "
              f"→ {'FOUND: ' + ip if ip else 'NXDOMAIN'}")

        # Simulate network latency — gives attacker a race window
        time.sleep(ARTIFICIAL_DELAY_MS / 1000.0)

        if ip:
            response = build_response(txid, domain, ip)
        else:
            response = build_nxdomain(txid, domain)

        sock.sendto(response, addr)
        print(f"[AUTH_SERVER] Replied to {addr[0]}:{addr[1]}  txid=0x{txid:04X}  ip={ip}")


if __name__ == "__main__":
    main()
