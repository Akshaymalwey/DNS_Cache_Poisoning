# DNS Cache Poisoning Lab — Classic Kaminsky Attack

A fully self-contained Docker lab simulating the **Kaminsky DNS cache poisoning attack** using Python raw sockets.

---

## Architecture

```
10.0.0.0/24 (dns_lab bridge network)

  [victim 10.0.0.4]
        │  DNS query: evil.example.com? (every 5s)
        ▼
  [resolver 10.0.0.2:53]
        │  cache miss → forward query  (fixed src port 5300 ← VULN)
        │────────────────────────────────────────────▶ [auth_server 10.0.0.3:53]
        │                                                     │ (200ms delay)
        │◀── spoofed response (src=10.0.0.3, random txid) ───│
  [attacker 10.0.0.5]                                        │
        └─── raw socket flood ──────────────────────────────▶│ (races real response)
```

---

## How the Attack Works (Step by Step)

### Why is the resolver vulnerable?

Real Kaminsky (2008) exploited two weaknesses simultaneously:
1. **Predictable source port** — resolver always uses the same UDP source port for upstream queries. Eliminates one dimension of entropy.
2. **16-bit transaction ID** — only 65,535 possible values, brute-forceable in milliseconds with modern hardware.

Modern resolvers use **random source ports** (adding ~16 bits of entropy), making the combined space ~2^32 — impractical to brute-force. This lab intentionally uses a fixed port to demonstrate the original attack.

### Attack loop

1. **Trigger cache miss** — attacker sends a DNS query for `evil.example.com` to the resolver. Resolver doesn't have it cached → forwards to auth server.

2. **Attack window opens** — resolver is now waiting on port `5300` for a UDP reply from auth server (`10.0.0.3:53`). It will accept the **first** valid-looking reply with a matching txid.

3. **Flood** — attacker sends 65,535 crafted UDP packets to `10.0.0.2:5300`, each with:
   - Source IP spoofed as `10.0.0.3` (auth server)
   - Source port 53
   - A different transaction ID (0x0001 → 0xFFFF)
   - DNS A-record response: `evil.example.com → 6.6.6.6`

4. **Race** — if any spoofed packet with the correct txid arrives at the resolver **before** the real auth-server reply (which is delayed by 200ms), the forged IP gets cached.

5. **Poison confirmed** — resolver now returns `6.6.6.6` for `evil.example.com`. The victim gets the malicious IP. Attack succeeded.

---

## File Structure

```
dns_poison/
├── docker-compose.yml
├── victim/
│   ├── Dockerfile
│   └── victim.py
├── resolver/
│   ├── Dockerfile
│   └── resolver.py
├── auth_server/
│   ├── Dockerfile
│   └── auth_server.py
└── attacker/
    ├── Dockerfile
    └── attacker.py
```

---

## Running the Lab

### Prerequisites
- Docker + Docker Compose installed
- Linux host (raw sockets work best on Linux; macOS/Windows may need a Linux VM)

### Start everything

```bash
cd dns_poison
docker compose up --build
```

You'll see interleaved logs from all 4 containers. Watch for:

```
[RESOLVER] *** SPOOFED ***  txid=0xABCD  evil.example.com → 6.6.6.6  (from 10.0.0.5)
[RESOLVER] Cached: evil.example.com → 6.6.6.6
[VICTIM]   *** Got answer: evil.example.com → 6.6.6.6 (from 10.0.0.2) ***
[ATTACKER] *** CACHE POISONED SUCCESSFULLY ***
```

### Watch individual containers

```bash
docker logs -f resolver
docker logs -f attacker
docker logs -f victim
```

### Reset cache and re-run attacker

```bash
docker restart resolver
docker start attacker
```

### Stop everything

```bash
docker compose down
```

---

## Tuning Knobs

| Variable | Where | Default | Effect |
|---|---|---|---|
| `ARTIFICIAL_DELAY_MS` | auth_server | 200 | Increase to give attacker more time |
| `FLOOD_THREADS` | attacker | 4 | More threads = faster brute-force |
| `MAX_ROUNDS` | attacker | 50 | Rounds before giving up |
| `UPSTREAM_PORT` | resolver + attacker | 5300 | Must match on both sides |
| `MALICIOUS_IP` | attacker | 6.6.6.6 | The forged IP |
| `QUERY_INTERVAL` | victim | 5s | How often victim queries |

---

## Defences (What Would Stop This)

| Defence | How it helps |
|---|---|
| **Randomised source port** (RFC 5452) | Attacker now needs to guess 16-bit port + 16-bit txid = ~2^32 combinations |
| **0x20 bit encoding** | Domain labels randomly capitalised; resolver only accepts matching capitalisation — adds ~10–20 bits of entropy |
| **DNSSEC** | Cryptographic signatures on DNS records; spoofed response fails signature check |
| **Response Rate Limiting** | Limits flood effectiveness at the resolver level |

---

## Important Notes

- **For educational/lab use only.** All traffic is confined to the `10.0.0.0/24` Docker network.
- The attacker container requires `--privileged` / `CAP_NET_RAW` for raw socket access. Never use this in production or on shared infrastructure.
- The resolver's fixed port and lack of DNSSEC are **intentional vulnerabilities** for demonstration purposes only.
