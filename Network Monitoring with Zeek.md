# TryHackMe — Detection Engineering with Zeek
### Full Walkthrough & Investigative Writeup

> **Room context:** Snort rules have started firing on the Finance subnet, catching beacons from `WKST-FINANCE-04` to AS44477 infrastructure. The detection layer only caught up *after* rules were loaded — everything before that point lives in Zeek logs. This room teaches how to reconstruct the full attack timeline from structured network logs without ever opening a packet capture.

---

## Table of Contents

1. [Lab Setup](#lab-setup)
2. [Task 1 — conn.log: The Index of Every Connection](#task-1--connlog-the-index-of-every-connection)
3. [Task 2 — dns.log: Where Connections Were Going](#task-2--dnslog-where-connections-were-going)
4. [Task 3 — http.log and ssl.log: Inside the Protocol](#task-3--httplog-and-ssllog-inside-the-protocol)
5. [Task 4 — files.log: What Crossed the Wire](#task-4--fileslog-what-crossed-the-wire)
6. [Task 5 — Cross-Log Correlation via uid](#task-5--cross-log-correlation-via-uid)
7. [Task 6 — Zeek Detection Scripting](#task-6--zeek-detection-scripting)
8. [Full Attack Timeline](#full-attack-timeline)
9. [Indicators of Compromise](#indicators-of-compromise)
10. [Key Takeaways](#key-takeaways)

---

## Lab Setup

All artefacts live under `/home/ubuntu`:

```
logs/
├── conn.log
├── dns.log
├── http.log
├── ssl.log
├── files.log
└── notice.log
pcaps/
└── finance-sensor.pcap
scripts/
└── dns_notice.zeek
threat-feed.csv
```

Every command runs from `/home/ubuntu`. Zeek logs are tab-separated with a `#fields` header — use `zeek-cut` to extract columns by name rather than by position.

---

## Task 1 — conn.log: The Index of Every Connection

### What conn.log tells us

Every TCP, UDP, and ICMP session observed by Zeek produces one row in `conn.log`. Key columns:

| Field | Meaning |
|-------|---------|
| `ts` | Session start timestamp (Unix epoch) |
| `uid` | Unique session identifier — the pivot key across all logs |
| `id.orig_h` / `id.orig_p` | Source IP and port |
| `id.resp_h` / `id.resp_p` | Destination IP and port |
| `proto` | Transport protocol |
| `duration` | Session length in seconds |
| `orig_bytes` | Bytes sent by the originator |
| `resp_bytes` | Bytes sent by the responder |
| `conn_state` | How the session ended |

### conn_state Quick Reference

| State | Meaning | Analyst significance |
|-------|---------|---------------------|
| `S0` | SYN sent, no response | Port scan / firewall drop |
| `SF` | Established and cleanly closed | Normal completed session |
| `REJ` | RST in response to SYN | Firewall block / ACL deny |
| `OTH` | No SYN observed | Asymmetric capture — byte counts unreliable |
| `S1` | Established, close not observed | Possibly still active |
| `RSTO` | Originator RST after established | Client-side abort |

### Inspect the header

```bash
head -8 logs/conn.log
```

### Rank connection pairs by count — hunting beacons

```bash
zeek-cut id.orig_h id.resp_h id.resp_p < logs/conn.log | sort | uniq -c | sort -rn | head -5
```

**Output:**
```
196 10.14.22.88   10.0.0.53      53
 82 10.14.22.88   194.165.16.56  443
 15 10.0.0.53     1.1.1.1        53
  1 10.14.22.88   185.220.101.45  80
  1 10.14.22.88   185.213.154.201 80
```

**Finding:** 82 sessions from `10.14.22.88` to `194.165.16.56` on TCP/443. No legitimate workstation makes 82 connections to a single external IP in a 90-minute window — this is beaconing.

### Confirm beacon timing

```bash
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < logs/conn.log \
  | awk -F'\t' '$3=="194.165.16.56" && $4=="443"' | sort -k1 | head -5
```

**Output:**
```
1763087880.000000   10.14.22.88   194.165.16.56   443   0.044000   308
1763087942.388062   10.14.22.88   194.165.16.56   443   0.044000   308
1763088002.918872   10.14.22.88   194.165.16.56   443   0.043999   308
1763088062.344944   10.14.22.88   194.165.16.56   443   0.043999   308
1763088117.959790   10.14.22.88   194.165.16.56   443   0.043999   308
```

**Finding:** ~60-second interval with small jitter, identical duration (0.044s) and byte count (308) every time — classic Cobalt Strike check-in beacon.

### Confirm connection state

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log \
  | awk -F'\t' '$2=="194.165.16.56" && $3=="443"' | sort -u
```

**Output:** `10.14.22.88   194.165.16.56   443   SF`

All 82 beacons close cleanly (SF). The malware hides inside dozens of look-alike short HTTPS sessions.

### Internal SMB scan

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log \
  | awk -F'\t' '$1=="10.14.22.88" && $3=="445" && $4=="S0"' | wc -l
```

**Output:** `23`

23 TCP/445 (SMB) probes to internal hosts, all in S0 state (no response). Classic post-exploitation lateral movement recon.

### Find the largest outbound transfer

```bash
zeek-cut ts uid id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < logs/conn.log \
  | awk -F'\t' '$3=="10.14.22.88" && $4!~/^10\.14\./ {print $0}' \
  | sort -t$'\t' -k6 -rn | head -3
```

**Output:**
```
1763090107.000000   CmQW1d3iuUHHDgqYe7   10.14.22.88   185.213.154.201   80   5348913   110
1763092746.812696   ChyYnO1kLVeL7Ux5ik   10.14.22.88   194.165.16.56     443  308       419
1763092690.911542   CVZ29lQ1Xk6opzli6    10.14.22.88   194.165.16.56     443  308       419
```

**Finding:** ~5.3 MB sent outbound to `185.213.154.201` on TCP/80 in a single HTTP session — exfiltration.

### Questions & Answers

| Question | Answer |
|----------|--------|
| First internal host `10.14.22.88` reaches on TCP/445 with conn_state S0? | `10.14.22.10` |
| Last timestamp for TCP/443 sessions to `194.165.16.56`? | `1763092746.812696` |

**Commands used:**
```bash
# Q1
zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log \
  | awk -F'\t' '$2=="10.14.22.88" && $4=="445" && $5=="S0"' | sort -k1 | head -1

# Q2
zeek-cut ts id.orig_h id.resp_h id.resp_p < logs/conn.log \
  | awk -F'\t' '$2=="10.14.22.88" && $3=="194.165.16.56" && $4=="443"' | sort -k1 | tail -1
```

---

## Task 2 — dns.log: Where Connections Were Going

### What dns.log tells us

Before any TCP connection opens, the host resolves a name. `dns.log` records every DNS query and answer, letting us map IP addresses back to the domains the attacker used.

Key columns: `ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, `answers`

### First look

```bash
zeek-cut ts id.orig_h query qtype_name rcode_name answers < logs/dns.log | head -10
```

### Resolve the C2 IP to its domain

```bash
zeek-cut id.orig_h query answers < logs/dns.log | grep "194.165.16.56"
```

**Output:** `10.14.22.88   update.softpatch-cdn.com   194.165.16.56`

The malware used `update.softpatch-cdn.com` — picked to look like a legitimate software update CDN.

### Hunt for DNS tunnelling — long label queries

DNS tunnelling encodes data inside subdomain labels (up to 63 chars each). The signature is long, base32-style labels repeated to the same second-level domain.

```bash
zeek-cut id.orig_h query < logs/dns.log \
  | awk -F'\t' 'length($2) > 60' | sort | uniq -c | sort -rn | head -10
```

**Output (sample):**
```
1 10.14.22.88   z6s5vtgvxm7vpdfdirfbjuef56w4b7uv2lqguwxhj3vpejguvx.exfil-channel.net
1 10.14.22.88   vbxvvsds46dsuw7qq6nypnx5n2xh7fxsaxi7uehq27clq.exfil-channel.net
...
```

All 18 long-label queries go to `exfil-channel.net` — iodine/dnscat2-style DNS tunnelling running in parallel with the HTTPS beaconing.

### Confirm tunnel source

```bash
zeek-cut id.orig_h query < logs/dns.log \
  | awk -F'\t' '$1!="10.0.0.53" && length($2) > 60 {count[$1]++} END {for(h in count) print count[h], h}' \
  | sort -rn
```

**Output:** `18 10.14.22.88`

Only `10.14.22.88` is tunnelling. The internal DNS server `10.0.0.53` produces similar-looking long queries for DNSSEC validation — but those have a different source, SLD (`dnssec-validation.local`), and record type (`DS` vs `TXT`).

### Resolve the exfil destination

```bash
zeek-cut ts id.orig_h query answers < logs/dns.log | grep "185.213.154.201"
```

**Output:** `1763090096.000000   10.14.22.88   backup.corpfiles-sync.com   185.213.154.201`

The domain `backup.corpfiles-sync.com` was resolved at 03:14:56 UTC — exactly 11 seconds before the HTTP POST began.

### Questions & Answers

| Question | Answer |
|----------|--------|
| DNS record type used by exfil-channel.net queries? | `TXT` |
| Full domain queried before the 03:15 UTC POST? | `backup.corpfiles-sync.com` |
| Domain that resolved to `194.165.16.56`? | `update.softpatch-cdn.com` |

---

## Task 3 — http.log and ssl.log: Inside the Protocol

### http.log — the exfil POST

```bash
zeek-cut ts uid id.orig_h id.resp_h method host uri user_agent request_body_len status_code \
  < logs/http.log
```

**Output:**
```
1763088600.061000   CIEtDD4xl1OB8efmf   10.14.22.88   185.220.101.45    GET   fileshare.corp-helpdesk.net   /downloads/invoice_march.pdf   \x2d   0         200
1763090107.081000   CmQW1d3iuUHHDgqYe7  10.14.22.88   185.213.154.201   POST  185.213.154.201              /upload/data                   -       5348721   200
```

Three red flags on the POST row:
- **Method is POST with 5.3 MB body** — data going out, not in
- **Host header is a bare IP** — no pretence of a named service
- **User-Agent is missing (`-`)** — custom client, not a browser

### Hunt for missing User-Agents

```bash
zeek-cut id.orig_h id.resp_h method uri user_agent request_body_len < logs/http.log \
  | awk -F'\t' '$5=="-"'
```

The exfil POST is the only row with no User-Agent — a reliable triage filter in production.

### ssl.log — C2 beacon TLS handshakes

```bash
zeek-cut ts id.orig_h id.resp_h version server_name < logs/ssl.log | head -5
```

**Output:**
```
1763087880.041000   10.14.22.88   194.165.16.56   TLSv12   -
1763087942.429062   10.14.22.88   194.165.16.56   TLSv12   -
...
```

`server_name` is `-` on every beacon — no SNI in the TLS Client Hello. Legitimate browsers almost always send SNI. Repeated TLS to a bare IP with no SNI = automated tooling.

### Count empty-SNI sessions

```bash
zeek-cut id.orig_h id.resp_h server_name < logs/ssl.log \
  | awk -F'\t' '$2=="194.165.16.56" && $3=="-" {c++} END{print c+0}'
```

**Output:** `82` — matches the beacon count from conn.log exactly.

### Questions & Answers

| Question | Answer |
|----------|--------|
| URI in http.log for the POST to `185.213.154.201`? | `/upload/data` |
| TLS sessions to `194.165.16.56` with empty server_name? | `82` |

---

## Task 4 — files.log: What Crossed the Wire

### What files.log tells us

Zeek's file analysis framework extracts file objects from HTTP, TLS, FTP, and SMTP sessions and identifies their type from **magic bytes** — not from server-claimed Content-Type headers. This distinction catches disguised malware.

Key columns: `uid`, `source`, `mime_type`, `filename`, `total_bytes`, `sha256`

### First look

```bash
zeek-cut ts uid source mime_type filename total_bytes sha256 < logs/files.log
```

**Output:**
```
1763088600.062000   CIEtDD4xl1OB8efmf   HTTP   application/x-dosexec   invoice_march.pdf   92160    7fbfa8adcb61123d10b8bc5b146308bbaf3a680dcc7ebf7d8bfadd6b9356d805
1763090107.081000   CmQW1d3iuUHHDgqYe7  HTTP   application/zip          backup_archive.zip  5348721  459b0165d7f2e5577d60cd8c1244daded93f4457ed4a89983e5e36c490402bec
1763090109.469327   CmQW1d3iuUHHDgqYe7  HTTP   -                        -                   7        cb0a78950e0d967dbce55cf8f4217d02d87c7f35fc0144af39fe7ffa5a3dc933
```

### MIME mismatch — the hidden executable

```bash
zeek-cut filename mime_type total_bytes < logs/files.log | awk -F'\t' '$1~/\.(pdf|jpg|png|doc)$/'
```

**Output:** `invoice_march.pdf   application/x-dosexec   92160`

`invoice_march.pdf` is **not a PDF**. Zeek read the first bytes and found `4D 5A` (MZ header) — a Windows PE executable. This is the dropper, delivered disguised as a finance document from `185.220.101.45` before the beacon intensified.

### Hash correlation against the threat feed

```bash
HASH=$(grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/files.log \
  | zeek-cut sha256 filename total_bytes \
  | awk -F'\t' '$2~/backup.*\.zip/ {print $1; exit}')
grep "$HASH" threat-feed.csv
```

**Output:** `459b0165d7f2e5577d60cd8c1244daded93f4457ed4a89983e5e36c490402bec,CobaltStrikeStager,2025-11-10,high`

The exfil archive's SHA256 matches **CobaltStrikeStager** in the threat feed with a high-confidence rating, first seen 2025-11-10 — four days before this incident.

### Questions & Answers

| Question | Answer |
|----------|--------|
| Filename of the file in the 5.3 MB POST? | `backup_archive.zip` |
| MIME type Zeek reports for `invoice_march.pdf`? | `application/x-dosexec` |
| Malware family from threat-feed.csv? | `CobaltStrikeStager` |

---

## Task 5 — Cross-Log Correlation via uid

### The uid as a pivot key

Every Zeek log row for the same network session shares a `uid`. Following that value across log types reconstructs the full session without touching the packet capture.

### Start in conn.log

```bash
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state \
  < logs/conn.log | awk -F'\t' '$5=="185.213.154.201"'
```

**Output:**
```
1763090107.000000   CmQW1d3iuUHHDgqYe7   10.14.22.88   54891   185.213.154.201   80   tcp   http   2.471327   5348913   110   SF
```

Take uid `CmQW1d3iuUHHDgqYe7` into the other logs.

### Pivot to http.log

```bash
grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/http.log \
  | zeek-cut method host uri user_agent request_body_len
```

**Output:** `POST   185.213.154.201   /upload/data   -   5348721`

### Pivot to files.log

```bash
grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/files.log \
  | zeek-cut source mime_type filename total_bytes
```

**Output:**
```
HTTP   application/zip   backup_archive.zip   5348721
HTTP   -                 -                    7
```

### Backward DNS correlation (IP → domain)

DNS uses a separate session/uid, so we pivot by IP instead:

```bash
zeek-cut ts id.orig_h query answers < logs/dns.log | grep "185.213.154.201"
```

**Output:** `1763090096.000000   10.14.22.88   backup.corpfiles-sync.com   185.213.154.201`

### The full session reconstructed

| Log | Finding |
|-----|---------|
| `conn.log` | `10.14.22.88 → 185.213.154.201:80`, 5,348,913 bytes, 2.47s, SF |
| `dns.log` | `backup.corpfiles-sync.com` resolved 11s before the POST |
| `http.log` | POST `/upload/data`, no User-Agent, 5,348,721-byte body |
| `files.log` | `backup_archive.zip`, application/zip, SHA256 confirmed |
| `threat-feed` | SHA256 = CobaltStrikeStager, high confidence |

### Questions & Answers

| Question | Answer |
|----------|--------|
| Difference between `orig_bytes` (conn.log) and `request_body_len` (http.log)? | `192` bytes (HTTP request header overhead) |
| Bytes the responder returned as file body in files.log? | `7` |
| Domain that resolved to `185.213.154.201`? | `backup.corpfiles-sync.com` |

---

## Task 6 — Zeek Detection Scripting

### The Notice framework

Zeek scripts subscribe to protocol events and call `NOTICE()` to write alerts to `notice.log` — the equivalent of a Snort alert log, but driven by full programming logic.

### The starter script

```zeek
@load base/frameworks/notice

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Exfil_LongQuery
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 60 )
    {
        NOTICE([$note=DNS_Exfil_LongQuery,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h),
                $suppress_for=5min]);
    }
}
```

**Problem:** fires on both the malicious tunnel from `10.14.22.88` and the legitimate DNSSEC validation queries from `10.0.0.53`.

### Run the starter — confirm false positives

```bash
mkdir -p /tmp/zeek-task7 && cd /tmp/zeek-task7
zeek -r ~/pcaps/finance-sensor.pcap ~/scripts/dns_notice.zeek
zeek-cut id.orig_h < notice.log | wc -l
```

**Output:** `23` — includes both legitimate DNSSEC and genuine tunnel activity.

### The fix — suppress the internal resolver

Add a single early-return condition at the top of the event handler:

```zeek
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( c$id$orig_h == 10.0.0.53 )
        return;

    if ( |query| > 60 )
    {
        NOTICE([$note=DNS_Exfil_LongQuery,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h),
                $suppress_for=5min]);
    }
}
```

### Apply and rerun

```bash
cat > dns_notice_modified.zeek << 'EOF'
@load base/frameworks/notice

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Exfil_LongQuery
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( c$id$orig_h == 10.0.0.53 )
        return;

    if ( |query| > 60 )
    {
        NOTICE([$note=DNS_Exfil_LongQuery,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h),
                $suppress_for=5min]);
    }
}
EOF

rm -f *.log
zeek -r ~/pcaps/finance-sensor.pcap dns_notice_modified.zeek
zeek-cut id.orig_h < notice.log | wc -l
```

**Output:** `10` — only genuine tunnel activity from `10.14.22.88` remains.

### How `$suppress_for` works

`$identifier=cat(c$id$orig_h)` sets the deduplication key to the source IP. `$suppress_for=5min` means Zeek emits at most one notice per source IP per five minutes. The underlying DNS activity is still visible in `dns.log` — notice.log stays readable.

### Questions & Answers

| Question | Answer |
|----------|--------|
| Total notices from the untuned starter script? | `23` |
| Notices remaining after suppressing `10.0.0.53`? | `10` |

---

## Full Attack Timeline

| UTC Time | Event | Log Source |
|----------|-------|-----------|
| 02:30 | `invoice_march.pdf` (PE executable) downloaded from `185.220.101.45` | files.log |
| 02:38 | Cobalt Strike beacon begins to `update.softpatch-cdn.com` → `194.165.16.56:443` | conn.log, dns.log, ssl.log |
| ~02:38+ | DNS tunnelling begins to `exfil-channel.net` (18 TXT queries) | dns.log |
| ~02:38+ | Internal SMB scan — 23 S0 probes to `10.14.22.x:445` | conn.log |
| 03:14:56 | DNS resolution of `backup.corpfiles-sync.com` → `185.213.154.201` | dns.log |
| 03:15:07 | 5.3 MB HTTP POST of `backup_archive.zip` to `185.213.154.201:80` | conn.log, http.log, files.log |
| 03:15:09 | Server returns 7-byte acknowledgement | files.log |
| ~05:12 | Last C2 beacon observed (`1763092746`) | conn.log |

---

## Indicators of Compromise

### Network

| Type | Value | Context |
|------|-------|---------|
| IP | `194.165.16.56` | Cobalt Strike C2 (AS44477) |
| IP | `185.213.154.201` | Exfiltration endpoint (AS44477) |
| IP | `185.220.101.45` | Dropper delivery server |
| Domain | `update.softpatch-cdn.com` | C2 hostname |
| Domain | `backup.corpfiles-sync.com` | Exfil endpoint hostname |
| Domain | `exfil-channel.net` | DNS tunnel SLD |

### Files

| Type | Value | Context |
|------|-------|---------|
| SHA256 | `459b0165d7f2e5577d60cd8c1244daded93f4457ed4a89983e5e36c490402bec` | `backup_archive.zip` — CobaltStrikeStager |
| SHA256 | `7fbfa8adcb61123d10b8bc5b146308bbaf3a680dcc7ebf7d8bfadd6b9356d805` | `invoice_march.pdf` — PE executable dropper |

### Behavioural

- Cobalt Strike beacon: ~60s interval, 308 bytes, 0.044s duration, TCP/443, no SNI
- DNS tunnel: TXT queries to `exfil-channel.net`, labels >60 chars
- SMB scan: 23 S0 connections to `10.14.22.x:445`
- HTTP POST: bare-IP Host header, missing User-Agent, 5.3 MB body

---

## Key Takeaways

**1. conn.log is always the first stop.**
It gives you the connection map — sources, destinations, byte volumes, and state codes — before you open any other log. Beacon patterns and exfil spikes are visible here.

**2. uid is the pivot key.**
One uid ties conn.log, http.log, ssl.log, and files.log together for the same session. Follow it instead of guessing across logs.

**3. DNS backward-correlation turns IPs into names.**
Searching `dns.log` by the destination IP from `conn.log` reveals the C2 domain the malware used, even when you started with only a bare IP.

**4. MIME type ≠ filename extension.**
`files.log` reads magic bytes, not headers. A `.pdf` that Zeek calls `application/x-dosexec` is a PE executable — escalate immediately.

**5. Tuned rules beat noisy ones.**
The starter Zeek script fired 23 times (DNSSEC + tunnel). One `return` condition dropped it to 10 — only the genuine signal. Signal-to-noise ratio is a detection engineering metric, not just a preference.

**6. Cobalt Strike leaves a clear Zeek fingerprint:**
- `conn.log`: repeated SF sessions, ~60s interval, identical byte count, single external IP
- `ssl.log`: TLSv12, no SNI (`server_name = -`)
- `files.log`: SHA256 matching known stager families

---

