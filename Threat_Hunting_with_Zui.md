# Threat Hunting with Zui

**Room:** [Threat Hunting with Zui](https://tryhackme.com/room/threathuntingwithzui)  
**Difficulty:** Medium  
**Time:** 90 min  


---

## Table of Contents

- [Overview](#overview)
- [Tool Introduction — What is Zui?](#tool-introduction--what-is-zui)
- [Task 2 — Zui: An Overview](#task-2--zui-an-overview)
- [Task 3 — The Zed Query Language](#task-3--the-zed-query-language)
- [Task 4 — Hunting for Beaconing Patterns](#task-4--hunting-for-beaconing-patterns)
- [Task 5 — Hunting Data Staging and Exfiltration](#task-5--hunting-data-staging-and-exfiltration)
- [Task 6 — Hunting for Lateral Movement](#task-6--hunting-for-lateral-movement)
- [Task 7 — Building a Saved Query Library](#task-7--building-a-saved-query-library)
- [Indicators of Compromise](#indicators-of-compromise)


---

## Overview

This room walks through threat hunting against a PCAP-derived dataset using **Zui** — a desktop application built on the Zed data lake. It bundles Zeek, the Zed CLI tools (`zq` and `zed`), and a powerful query engine. The investigation PCAP is at `/home/ubuntu/artefacts/investigation.pcap`, with a pre-processed ZNG export at `/home/ubuntu/artefacts/investigation.zng`.

The room covers three core hunting scenarios:
1. **Beaconing** — C2 communication at regular intervals
2. **Data Exfiltration** — Asymmetric outbound transfers
3. **Lateral Movement** — Internal admin port activity and pivots

---

## Task 2 — Zui: An Overview

### Interface Components

| Component | Function |
|---|---|
| Pools panel (left) | Lists loaded datasets; select which pool to query |
| Query bar | Write Zed queries to filter, transform, and aggregate |
| Results panel | Displays matching logs in tabular or raw record format |
| Histogram | Timeline of event frequency; click and drag to zoom |
| Field list | Lists active fields; clicking appends to query |
| Saved queries | Bookmarked queries for reuse |

### First Query — Counting Records by Log Type

```zed
count() by _path | sort -r count
```

**Output:**

| _path | count |
|---|---|
| analyzer | 692 |
| conn | 560 |
| weird | 338 |
| ssl | 202 |
| dns | 9 |
| files | 4 |
| http | 1 |
| packet_filter | 1 |

**Total rows: 1807**

> **Q: How many rows of results are captured in Investigation-Data in Zui?**  
> **A: `1807`**

---

## Task 3 — The Zed Query Language

### Pipeline Model

Zed is pipeline-based — each `|` passes output of the preceding operation to the next. Queries are built left to right: filter → group → aggregate → sort → limit.

**Top 10 External Destinations:**
```zed
_path == "conn" | not (id.resp_h in [10.0.0.0/8]) | count() by id.resp_h | sort -r count | head 10
```

`194.165.16.56` stands out with 202 connections — well ahead of CDN/resolver IPs.

**Longest Running Connections:**
```zed
_path == "conn" | sort -r duration | head 20
```

Results show a 738s RDP session and a 492s SMB session between internal hosts.

**Traffic Volume Per Source IP:**
```zed
_path == "conn" | conns := count(), bytes_out := sum(orig_bytes), bytes_in := sum(resp_bytes) by id.orig_h | sort -r bytes_out
```

**DNS Substring Search:**
```zed
_path == "dns" | grep("corpfiles-sync", query)
```

**DNS Tunnelling Detection (queries > 60 chars):**
```zed
_path == "dns" | len(query) > 60
```

**Beaconing Hunt Query (step-by-step build):**
```zed
_path == "conn" | id.resp_p == 443 | not (id.resp_h in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]) | sessions := count(), bytes_out := sum(orig_bytes) by id.orig_h, id.resp_h | sessions >= 20 | sort -r sessions
```

---

## Task 4 — Hunting for Beaconing Patterns

**Hypothesis:** An endpoint is compromised and running malware communicating with a C2 server at regular intervals. Standard signature rules did not fire because each connection is small and encrypted.

### What Beaconing Looks Like

- Multiple connections from same source to same destination
- Consistent or near-consistent intervals (60s, 300s, 3600s with 10–30% jitter)
- Short duration per connection (typically under 10 seconds)
- Low data volume per connection (few hundred bytes each direction)
- High reliability (hundreds per day)

### Step 1 — Identify High-Frequency External Connections

```zed
_path == "conn" |
not (id.resp_h in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]) |
count() by id.orig_h, id.resp_h, id.resp_p |
sort -r count |
count > 20
```

**Output:** 202 connections from `10.14.22.88` → `194.165.16.56:443`

> **Q: What is the source IP of the host with the highest external connection count to a single destination?**  
> **A: `10.14.22.88`**

### Step 2 — Examine the Interval Pattern

```zed
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 | sort ts | cut ts
```

Connections land roughly 60 seconds apart with slight jitter — the signature of a **Cobalt Strike C2 beacon**.

### Step 3 — Examine Connection Characteristics

```zed
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 |
cut ts, duration, orig_bytes, resp_bytes, conn_state
```

Every session carries **412 bytes outbound / 1,284 bytes inbound** — identical byte counts confirm a fixed beacon protocol. Single repeated `conn_state` confirms structured (non-user) traffic.

### Step 4 — Correlate With TLS Logs

```zed
_path == "ssl" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 |
cut ts, server_name, ja4, validation_status, subject
```

**Output:**

| Field | Value |
|---|---|
| server_name | `update.softpatch-cdn.com` |
| ja4 | `t13d1516h2_8daaf6152771_e6bea0d95778` |
| subject | `CN=localhost` |
| validation_status | self-signed |

Three high-confidence C2 indicators:
- **SNI** `update.softpatch-cdn.com` — typosquat masquerading as a CDN update domain
- **`CN=localhost`** — default Cobalt Strike certificate profile
- **JA4 fingerprint** — matches Cobalt Strike default profile in the public JA4 catalogue

> **Q: What TLS server name is associated with the beaconing destination?**  
> **A: `update.softpatch-cdn.com`**

---

## Task 5 — Hunting Data Staging and Exfiltration

**Hypothesis:** Attacker has achieved foothold and is preparing to exfiltrate data. Unlike beaconing, exfiltration produces a small number of sessions with unusually high outbound volume.

### Step 1 — Find Asymmetric External Transfers

```zed
_path == "conn" |
not (cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
orig_bytes > 1000000 |
orig_bytes / (resp_bytes + 1) > 10 |
sort -r orig_bytes
```

**Output (top row):**

| orig_h | resp_h | proto | service | orig_bytes |
|---|---|---|---|---|
| 10.14.22.88 | 185.213.154.201 | tcp | http | **5348854** |

> **Q: What is the orig_bytes value for the largest external upload?**  
> **A: `5348854`**

### Step 2 — Check the Timing

```zed
_path == "conn" |
orig_bytes > 1000000 |
(ts < 2025-11-14T07:00:00Z or ts > 2025-11-14T20:00:00Z)
```

The large transfer occurred **off-hours** — additional suspicion indicator (though backup jobs can also run overnight).

### Step 3 — Pivot into HTTP Evidence

```zed
_path == "http" |
id.resp_h == 185.213.154.201 |
sort -r request_body_len |
cut ts, id.orig_h, id.resp_h, method, host, uri, request_body_len, orig_mime_types, user_agent
```

**Output:**

| Field | Value |
|---|---|
| method | POST |
| host | `backup.corpfiles-sync.com` |
| uri | `/upload/data` |
| request_body_len | 5348721 |
| orig_mime_types | `application/zip` |
| user_agent | *(empty)* |

Missing User-Agent is unusual for a browser — points to a script or custom client.

> **Q: What URI was used for the HTTP POST to the exfiltration endpoint?**  
> **A: `/upload/data`**

### Step 4 — Confirm DNS Resolution

```zed
_path == "dns" |
query == "backup.corpfiles-sync.com" |
cut ts, id.orig_h, query, answers, rcode_name
```

DNS lookup occurred less than a minute before the HTTP POST — clean chain: resolve → connect → upload.

### Step 5 — File Extraction and Hashing

```zed
_path == "files" |
10.14.22.88 in tx_hosts |
185.213.154.201 in rx_hosts |
cut ts, tx_hosts, rx_hosts, conn_uids, source, analyzers, mime_type, filename, total_bytes, md5, sha1
```

**Output:**

| Field | Value |
|---|---|
| filename | `backup_archive.zip` |
| total_bytes | 5348721 |
| md5 | `03237a4102d830519fa0dfb47c88c467` |
| sha1 | `c70b25e06280b5e3c00edff8d35c67997c023293` |

> **Q: What is the filename of the archive POSTed to 185.213.154.201?**  
> **A: `backup_archive.zip`**

> **Q: What is the MD5 hash value of the ZIP file?**  
> **A: `03237a4102d830519fa0dfb47c88c467`**

### Internal SMB Staging (Two-Hop Pattern)

```zed
_path == "conn" |
(cidr_match(10.0.0.0/8, id.orig_h) or cidr_match(172.16.0.0/12, id.orig_h) or cidr_match(192.168.0.0/16, id.orig_h)) |
(cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
id.resp_p == 445 |
resp_bytes > 10000000 |
sort -r resp_bytes
```

Shows an internal SMB transfer into `10.14.22.88` (IT admin workstation) before the outbound upload — classic stage-then-exfil pattern.

---

## Task 6 — Hunting for Lateral Movement

**Hypothesis:** Compromised Finance workstation (`10.14.22.88`) expanded access toward higher-value targets. Finance workstations should never initiate connections on administrative ports.

### Observable Patterns

- Admin port connections: SMB (445), RDP (3389), WinRM (5985/5986), SSH (22)
- Scanning signatures: many S0 (SYN-only) connections from one source to many destinations
- Authenticated sessions with data movement
- Sequential pivots: A → B → C chain reconstruction

### Step 1 — Unexpected Internal Admin Connections

```zed
_path == "conn" |
(cidr_match(10.0.0.0/8, id.orig_h) or cidr_match(172.16.0.0/12, id.orig_h) or cidr_match(192.168.0.0/16, id.orig_h)) |
(cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
id.resp_p in [445, 3389, 5985, 22, 135, 389] |
not id.orig_h == id.resp_h |
count() by id.orig_h, id.resp_p |
sort -r count
```

`10.14.22.88` shows 20+ SMB attempts — highly anomalous for a Finance workstation.

### Step 2 — Detect the Scan

```zed
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_p == 445 | conn_state == "S0" | count()
```

**Output: `23`**

23 unanswered SYN attempts (S0 state) = internal port scan against 23 hosts on port 445.

> **Q: How many unanswered SMB SYN attempts did 10.14.22.88 generate?**  
> **A: `23`**

### Step 3 — First Pivot via RDP

```zed
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_p == 3389 | sort ts |
cut ts, id.resp_h, duration, orig_bytes, resp_bytes
```

Single RDP connection: `10.14.22.88` → `10.14.10.15`, duration **738 seconds (~12 minutes)**. Transfer of ~3 MB outbound / 28 MB inbound — consistent with interactive GUI session (keyboard/mouse out, screen frames in).

### Step 4 — Second-Hop Pivot to Domain Controller

```zed
_path == "conn" |
id.orig_h == 10.14.10.15 |
id.resp_p in [389, 445] |
count() by id.resp_h, id.resp_p |
sort id.resp_h
```

**Output:**

| resp_h | resp_p | count |
|---|---|---|
| 10.14.0.5 | 389 (LDAP) | 3 |
| 10.14.0.5 | 445 (SMB) | 1 |

IT admin workstation reached `10.14.0.5` (Domain Controller) over LDAP (AD recon) and SMB (follow-on access).

> **Q: What destination IP did 10.14.10.15 reach over LDAP and SMB during the second hop?**  
> **A: `10.14.0.5`**

### Lateral Movement Map

| Hop | Time (UTC) | Source | Destination | Protocol | ATT&CK |
|---|---|---|---|---|---|
| 1 | 02:48 | WKST-FINANCE-04 (`10.14.22.88`) | 23 hosts | SMB scan | T1046 |
| 2 | 02:52 | WKST-FINANCE-04 (`10.14.22.88`) | WKST-IT-ADMIN-02 (`10.14.10.15`) | RDP | T1021.001 |
| 3 | 03:05 | WKST-IT-ADMIN-02 (`10.14.10.15`) | SRV-DC-01 (`10.14.0.5`) | LDAP + SMB | T1018, T1021.002 |

---

## Task 7 — Building a Saved Query Library

Eight pre-staged `.zed` files at `/home/ubuntu/artefacts/starter-queries/`:

```bash
ls /home/ubuntu/artefacts/starter-queries/
# beaconing-conn-highcount.zed  dns-nxdomain-volume.zed    longconn-external.zed
# dns-longquery.zed             exfil-conn-asymmetric.zed  offhours-largetransfer.zed
# lateralmov-smb-internal.zed   tls-badcert.zed
```

| Query Name | What It Hunts |
|---|---|
| Beaconing-conn-highcount | High-frequency external connections (beacon candidates) |
| Exfil-conn-asymmetric | Large outbound transfers with high send-to-receive ratio |
| LongConn-external | External sessions sustained for more than one hour |
| DNS-LongQuery | DNS query names longer than 60 characters (tunnel candidates) |
| DNS-NXDOMAIN-volume | Hosts generating high NXDOMAIN rates (DGA candidates) |
| TLS-BadCert | Connections with self-signed or invalid certificates |
| LateralMov-SMB-internal | Internal SMB connections across hosts |
| OffHours-largetransfer | Large data transfers outside business hours |

### False Positive Handling — Fastly CDN

```zed
_path == "conn" | id.resp_h == 151.101.1.140 | count()
```

**Output: `55`**

Fastly CDN (`151.101.0.0/16`) generates 55 connections — known good. Exclude from beaconing query:

```zed
... | not cidr_match(151.101.0.0/16, id.resp_h) | ...
```

> **Q: How many connections go to the Fastly CDN IP that appears as a false positive?**  
> **A: `55`**

> **Note:** Document exclusions. An attacker routing C2 through Cloudflare/Fastly would disappear behind this filter.

---

## Indicators of Compromise

| Type | Value | Role |
|---|---|---|
| Source IP | `10.14.22.88` (WKST-FINANCE-04) | Beacon source, exfil source, lateral movement origin |
| Source IP | `10.14.10.15` (WKST-IT-ADMIN-02) | RDP target, second-hop pivot |
| Destination IP | `194.165.16.56` (AS44477) | Cobalt Strike C2 |
| Destination IP | `185.213.154.201` (AS44477) | Exfiltration endpoint |
| Domain | `update.softpatch-cdn.com` | C2 SNI (typosquat) |
| Domain | `backup.corpfiles-sync.com` | Exfiltration host header |
| File | `backup_archive.zip` | Staged exfiltration archive (5.3 MB) |
| MD5 | `03237a4102d830519fa0dfb47c88c467` | Hash of backup_archive.zip |
| SHA1 | `c70b25e06280b5e3c00edff8d35c67997c023293` | Hash of backup_archive.zip |
| SHA256 | `ad73da1e040200e23b2ee98e134b924f5f23e47a45207b6b304416d5aa65bdfe` | Hash of backup_archive.zip |
| TLS fingerprint | `t13d1516h2_8daaf6152771_e6bea0d95778` | Cobalt Strike JA4 fingerprint |

---



*Writeup by [gopalakrishnsak](https://github.com/gopalakrishnsak)*
