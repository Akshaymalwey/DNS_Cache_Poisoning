#!/usr/bin/env python3
"""
Victim node.
Sends a DNS query for TARGET_DOMAIN to the resolver and prints the IP it gets back.
In a real attack, the IP returned would be the attacker's spoofed address.
"""

import socket
import struct
import time
import os

RESOLVER_IP   = os.getenv("RESOLVER_IP", "10.0.0.2")
RESOLVER_PORT = int(os.getenv("RESOLVER_PORT", 53))
TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "evil.example.com")
QUERY_INTERVAL = int(os.getenv("QUERY_INTERVAL", 5))   # seconds between queries


def build_dns_query(domain: str, txid: int) -> bytes:
    """Build a minimal DNS A-record query packet."""
    # Header: ID, flags(recursion desired), 1 question, 0 answers
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)

    # Encode domain name: split by '.', each label = len_byte + label_bytes, end with 0x00
    question = b""
    for label in domain.split("."):
        encoded = label.encode()
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    question += struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN

    return header + question


def parse_dns_response(data: bytes) -> str | None:
    """Extract the first A-record IP from a DNS response."""
    if len(data) < 12:
        return None

    txid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if ancount == 0:
        return None

    # Skip the header (12 bytes) and the question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            if label_len & 0xC0 == 0xC0:   # compression pointer
                offset += 2
                break
            offset += 1 + label_len
        else:
            offset += 1  # null terminator
        offset += 4      # QTYPE + QCLASS

    # Parse first answer
    if offset + 2 > len(data):
        return None

    # Handle possible name compression in answer
    if data[offset] & 0xC0 == 0xC0:
        offset += 2
    else:
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1

    if offset + 10 > len(data):
        return None

    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
    offset += 10

    if rtype == 1 and rdlength == 4:   # A record
        return socket.inet_ntoa(data[offset:offset+4])

    return None


def main():
    print(f"[VICTIM] Starting — will query resolver {RESOLVER_IP}:{RESOLVER_PORT} "
          f"for '{TARGET_DOMAIN}' every {QUERY_INTERVAL}s")

    txid = 1
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        query = build_dns_query(TARGET_DOMAIN, txid & 0xFFFF)
        print(f"[VICTIM] Sending query  txid=0x{txid & 0xFFFF:04X}  domain={TARGET_DOMAIN}")

        try:
            sock.sendto(query, (RESOLVER_IP, RESOLVER_PORT))
            data, addr = sock.recvfrom(512)
            ip = parse_dns_response(data)
            if ip:
                print(f"[VICTIM] *** Got answer: {TARGET_DOMAIN} → {ip} (from {addr[0]}) ***")
            else:
                print(f"[VICTIM] Got response but no A-record found")
        except socket.timeout:
            print(f"[VICTIM] Timeout — no response from resolver")
        except Exception as e:
            print(f"[VICTIM] Error: {e}")
        finally:
            sock.close()

        txid += 1
        time.sleep(QUERY_INTERVAL)


if __name__ == "__main__":
    main()
