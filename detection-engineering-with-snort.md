# Detection Engineering With Snort — TryHackMe Writeup

**Room:** Detection Engineering With Snort (Premium)  
**Platform:** TryHackMe  
**Difficulty:** Medium  
**Author:** gopalakrishnsak  
**Tags:** `snort` `IDS` `detection-engineering` `blue-team` `network-security` `threat-intelligence`

---

## Overview

This room walks through building production-ready Snort 3 detections from scratch — covering rule anatomy, behaviour-based detection, suppression tuning, threat intelligence integration, false positive elimination, and a full capstone challenge modelled on a real intrusion scenario called **Operation SILENT TRANSFER**.

---

## Task 1 — Introduction

No lab work. Covers Snort 3 architecture concepts: inspectors, IPS policy, Lua config, and the difference between signature-based and behaviour-based detection.

---

## Task 2 — Advanced Rule Options

### Lab Files
- `task-02-rule-anatomy.pcap` — Mixed Finance subnet traffic (HTTP GET, POST, HTTPS, DNS)
- `task-02-starter.rules` — Broken rule to fix

### Step 1 — Inspect Starter Rule

```bash
cd /home/ubuntu/lab/task-02
cat task-02-starter.rules
```

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 ( \
  msg:"L2-SNORT Outbound HTTP GET from Finance subnet"; \
  flow:from_server,established; \
  pkt_data; content:"GET"; \
  sid:1000101; \
  rev:1; \
)
```

**Bug 1:** `flow:from_server,established` — wrong direction. HTTP GET travels client→server, not server→client.  
**Bug 2:** `content:"GET"` — no depth anchor. Matches "GET" anywhere in payload, including inside POST bodies (e.g. `op=GET_STATUS_REPORT`).

### Step 2 — First Run (No Alerts)

```bash
sudo snort -c /etc/snort/snort.lua -R task-02-starter.rules -r task-02-rule-anatomy.pcap -A alert_fast -q
```

Output: *(empty — rule never fires due to wrong flow direction)*

### Step 3 — Fix Flow Direction

Change `flow:from_server,established` → `flow:to_server,established`

```bash
nano task-02-starter.rules
```

Re-run with source grouping:

```bash
sudo snort -c /etc/snort/snort.lua -R task-02-starter.rules -r task-02-rule-anatomy.pcap -A alert_fast -q | grep -oE '10\.14\.22\.[0-9]+' | sort | uniq -c
```

```
  5 10.14.22.156
 80 10.14.22.202   ← FALSE POSITIVE (POST-only host)
  5 10.14.22.45
 20 10.14.22.88
```

**Total: 110 alerts** — `10.14.22.202` fires 80 times despite never making a GET request. It's a POST-only host whose form data contains the string "GET" in field values.

### Step 4 — Tighten Content Match

Change `content:"GET";` → `content:"GET ", depth 4;`

- `depth 4` restricts the content match to the first 4 bytes of the payload
- A real HTTP GET starts with `GET ` at offset 0
- POST payloads start with `POST`, so `depth 4` eliminates all false positives

```bash
nano task-02-starter.rules
```

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 ( \
  msg:"L2-SNORT Outbound HTTP GET from Finance subnet"; \
  flow:to_server,established; \
  pkt_data; content:"GET ", depth 4; \
  sid:1000101; \
  rev:1; \
)
```

```bash
sudo cp task-02-starter.rules task-02-answer.rules
sudo snort -c /etc/snort/snort.lua -R task-02-answer.rules -r task-02-rule-anatomy.pcap -A alert_fast -q | wc -l
```

```
30
```

### Final Rule

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 ( \
  msg:"L2-SNORT Outbound HTTP GET from Finance subnet"; \
  flow:to_server,established; \
  pkt_data; content:"GET ", depth 4; \
  metadata:mitre_attack T1071.001, author "saqib", ticket "NFG-2145"; \
  sid:1000101; \
  rev:2; \
)
```

### Answers

| Question | Answer |
|---|---|
| Workstation firing rule despite no GET requests? | `10.14.22.202` |
| Alert count after tightening content match? | `30` |

---

## Task 3 — Behaviour-Based Beacon Detection

### Lab Files
- `task-03-beaconing.pcap` — 30-min Finance subnet capture, WKST-FINANCE-04 beaconing to `194.165.16.56:443` every 60s ±5s jitter
- `task-03-starter.rules` — IP-based signature rule (brittle)
- `task-03-answer.rules` — behaviour-based rule (built here)

### Starter Rule (Signature-Based — Brittle)

```
alert tcp $HOME_NET any -> 194.165.16.56 any ( \
  msg:"L2-SNORT SILENT TRANSFER C2 IP match (signature-only)"; \
  flow:to_server,established; \
  sid:1000001; \
  rev:1; \
)
```

**Problem:** Fires only on this specific C2 IP. One infrastructure rotation = detection gap.

### Behaviour-Based Rule

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"POSSIBLE C2 BEACON - Finance egress regularity";
  flow:to_server,established;
  dsize:<100;
  detection_filter:track by_src, count 5, seconds 360;
  metadata:mitre_attack T1071.001, author "saqib", ticket "NFG-2145";
  sid:1000002;
  rev:1;
)
```

| Option | Purpose |
|---|---|
| `dsize:<100` | Matches small TLS heartbeat/keepalive packets, filters out real browsing |
| `detection_filter:track by_src, count 5, seconds 360` | Alerts only after 5 hits from same source in 6 min — confirms automation |
| `$EXTERNAL_NET 443` | IP-agnostic, survives C2 infrastructure rotation |

### Validation

```bash
sudo snort -c /etc/snort/snort.lua -R task-03-answer.rules -r task-03-beaconing.pcap -A alert_fast -q | wc -l
```
```
25
```

```bash
sudo snort -c /etc/snort/snort.lua -R task-03-answer.rules -r task-03-beaconing.pcap -A alert_fast -q | grep -oE '10\.14\.22\.[0-9]+' | sort -u
```
```
10.14.22.88
```

Only WKST-FINANCE-04 crosses the threshold. Neighbouring workstations stay silent.

### Answers

| Question | Answer |
|---|---|
| Alert count after running behaviour rule? | `25` |
| Source IP crossing detection threshold? | `10.14.22.88` |

---

## Task 4 — Thresholds, Suppression & Tuning

### Lab Files
- `task-04-noisy-traffic.pcap` — 80MB, C2 beacon from `10.14.22.88` + vuln scanner noise from `10.14.22.199`
- `task-04-answer.rules` — beacon rule from Task 3
- `task-04-suppress.lua` — suppression file (populated here)

### Step 1 — Baseline Run (Before Suppression)

```bash
cd /home/ubuntu/lab/task-04
sudo snort -c /etc/snort/snort.lua -R task-04-answer.rules -r task-04-noisy-traffic.pcap -A alert_fast -q | wc -l
```
```
39887
```

### Step 2 — Source Breakdown

```bash
sudo snort -c /etc/snort/snort.lua -R task-04-answer.rules -r task-04-noisy-traffic.pcap -A alert_fast -q | grep -oE '10\.14\.22\.[0-9]+' | sort | uniq -c | sort -rn | head
```
```
39835 10.14.22.199   ← vuln scanner (FALSE POSITIVE)
   52 10.14.22.88    ← WKST-FINANCE-04 (TRUE POSITIVE)
```

### Step 3 — Apply Suppression

```bash
nano task-04-suppress.lua
```

```lua
suppress =
{
    { gid = 1, sid = 1000002, track = 'by_src', ip = '10.14.22.199' }
}
```

- `gid = 1` — targets text ruleset rules
- `sid = 1000002` — our beacon rule
- `track = 'by_src'` — match on source address
- `ip = '10.14.22.199'` — the scanner to silence

### Step 4 — Re-run With Suppression

```bash
sudo snort -c /etc/snort/snort.lua -R task-04-answer.rules -r task-04-noisy-traffic.pcap -A alert_fast -q --tweaks task-04-suppress | wc -l
```
```
52
```

Scanner silenced. Only WKST-FINANCE-04 remains.

### Key Concepts

| Control | Use Case |
|---|---|
| `threshold type limit` | Cap alert volume globally for high-frequency rules |
| `threshold type both` | Require N hits then fire once per window |
| `suppress` | Silence a specific known-good host without touching rule logic |
| `--tweaks` | Load Lua suppression/threshold file at runtime |

### Answers

| Question | Answer |
|---|---|
| Total alerts before suppression? | `39887` |
| Alerts after suppressing `10.14.22.199`? | `52` |

---

## Task 5 — Threat Intelligence Integration (Reputation Inspector)

### Lab Files
- `task-05-blocklist.txt` — 20-entry IP feed (abuse.ch Feodo Tracker + ET Open)
- `task-05-ti-integration.pcap` — 20MB, 10 outbound connections to blocklisted IPs
- `task-05-snort.lua` — staged config with reputation stanza

### Blocklist Sample

```bash
head -n 10 task-05-blocklist.txt
```
```
# Operation SILENT TRANSFER - internal TI, 2026-04-12
194.165.16.56      # Feodo Tracker - active C2
185.213.154.201    # ET Open - exfil infrastructure
# External feeds - abuse.ch Feodo Tracker, 2026-04-18
45.142.212.61
185.234.247.50
91.92.241.17
193.32.162.8
```

### Enable Reputation Inspector

```bash
sudo nano task-05-snort.lua
```

```lua
reputation =
{
    blocklist = '/home/ubuntu/lab/task-05/task-05-blocklist.txt',
    memcap = 500,
    priority = 'blocklist',
    nested_ip = 'inner',
}
```

| Config Option | Purpose |
|---|---|
| `blocklist` | Path to IP feed file |
| `memcap` | RAM budget in MB for loaded list |
| `priority = 'blocklist'` | Blocklist wins over allowlist on conflict |
| `nested_ip = 'inner'` | Check inner IP in tunneled protocols |

### Validation

```bash
sudo snort -c task-05-snort.lua -r task-05-ti-integration.pcap -A alert_fast -q | wc -l
```
```
20
```

Alert format — SID `136:1:1` (reputation inspector):
```
[136:1:1] "(reputation) packet from blacklisted source/destination IP"
```

- `gid 136` = reputation inspector owns this gen_id
- `sid 1` = blocklist match event

### Answer

| Question | Answer |
|---|---|
| Alerts after enabling reputation inspector? | `20` |

---

## Task 6 — Rule Validation & False Positive Elimination

### Lab Files
- `task-06-ruleset.rules` — 5 rules, one broken
- `task-06-dirty.pcap` — full Operation SILENT TRANSFER intrusion slice
- `task-06-clean.pcap` — 30min normal Finance subnet traffic
- `task-06-answer.rules` — fixed ruleset

### Three-Pass Validation Rhythm

| Pass | Goal | Expected Result |
|---|---|---|
| Positive | Run against dirty PCAP | All SIDs fire |
| Negative | Run against clean PCAP | Zero alerts |
| Performance | Rule profiling with `--lua "profiler = {}"` | Low µs/check |

### Pass 1 — Positive Test

```bash
cd /home/ubuntu/lab/task-06
sudo snort -c /etc/snort/snort.lua -R task-06-ruleset.rules -r task-06-dirty.pcap -A alert_fast -q | awk '{print $3}' | sort | uniq -c
```
```
 3 [1:1000001:1]   ← HTTP GET
10 [1:1000002:1]   ← C2 beacon
 5 [1:1000003:1]   ← DNS tunnel
 4 [1:1000004:1]   ← SMB lateral
 3 [1:1000005:1]   ← Edg user-agent
```
✅ All 5 rules fire — positive test passes

### Pass 2 — Negative Test (Finds the Problem)

```bash
sudo snort -c /etc/snort/snort.lua -R task-06-ruleset.rules -r task-06-clean.pcap -A alert_fast -q | wc -l
```
```
15
```

```bash
sudo snort -c /etc/snort/snort.lua -R task-06-ruleset.rules -r task-06-clean.pcap -A alert_fast -q | grep -oE '\[1:[0-9]+:[0-9]+\]' | sort | uniq -c
```
```
15 [1:1000005:1]   ← entire FP stream from one rule
```

### Root Cause — sid 1000005

```
content:"User-Agent|3a 20|", nocase;
content:"Edg", within 30;
```

**Problem:** `Edg` matches the legitimate Microsoft Edge browser string `Edg/123.0.0.0` sent on every single Edge request. Every Edge user on the Finance subnet trips this rule.

### Fix — Anchor to Malware-Specific Token

```
content:"EdgBot", within 30;
```

`EdgBot` is the malware's custom user-agent token. It does not appear in any legitimate Edge traffic.

### Re-Validation After Fix

```bash
# Negative test
sudo snort -c /etc/snort/snort.lua -R task-06-answer.rules -r task-06-clean.pcap -A alert_fast -q | wc -l
```
```
0   ✅
```

```bash
# Positive test — sid 1000005 still fires on C2 traffic
sudo snort -c /etc/snort/snort.lua -R task-06-answer.rules -r task-06-dirty.pcap -A alert_fast -q | grep -c 1000005
```
```
3   ✅
```

### Answers

| Question | Answer |
|---|---|
| False positives on clean PCAP? | `15` |
| sid 1000005 fires on dirty PCAP after fix? | `3` |

---

## Task 7 — Capstone Challenge (Operation SILENT TRANSFER)

### Lab Files
- `task-07-challenge.pcap` — 310MB perimeter capture, 30-min Finance subnet window
- `task-07-ti-report.md` — TLP:AMBER threat intelligence brief
- `task-07-challenge-snort.lua` — Snort config with reputation stanza primed
- `task-07-challenge-local.rules` — empty, filled here
- `task-07-challenge-blocklist.txt` — empty, populated from TI report
- `task-07-challenge-threshold.conf.lua` — empty suppression file

### Step 1 — Read the TI Report

```bash
cd /home/ubuntu/lab/task-07
cat task-07-ti-report.md
```

**Key intelligence extracted:**

| IOC Type | Value |
|---|---|
| Primary C2 | `194.165.16.56:443` |
| Exfil staging | `185.213.154.201` |
| Secondary C2 (×4) | `45.142.212.61`, `185.234.247.50`, `91.92.241.17`, `193.32.162.8` |
| Rotating relays (×4) | `103.85.24.19`, `196.251.114.11`, `89.248.165.72`, `45.95.147.206` |
| Bulletproof hosting (×2) | `5.188.10.42`, `31.184.236.17` |
| Beacon cadence | Every 30-60s ±3s jitter |
| Payload size | Under 100 bytes (37-52 byte range) |
| Payload shape | `0x17 0x03 0x03` (fake TLS application-data record) |
| MITRE ATT&CK | T1071.001, T1573.002 |
| Known noise | `10.14.22.99` (DEV-HEALTH-01) — 40-byte keepalive every 10s |

### Step 2 — Triage the Capture

```bash
sudo tcpdump -r task-07-challenge.pcap -nn 'src net 10.14.22.0/24' 2>/dev/null | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head
```
```
300 10.14.22.77   ← DNS decoy (WKST-DNS-DECOY) — noise
200 10.14.22.99   ← health prober (DEV-HEALTH-01) — known-good noise
 40 10.14.22.88   ← WKST-FINANCE-04 — TARGET
  4 10.14.22.45
  4 10.14.22.156
```

### Step 3 — Write the Beacon Rule

```bash
nano task-07-challenge-local.rules
```

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"SILENT TRANSFER - C2 beacon rhythm";
    flow:to_server,established;
    dsize:<100;
    detection_filter:track by_src, count 5, seconds 360;
    metadata:mitre_attack T1071.001, author "saqib", ticket "NFG-2145";
    sid:1000100; rev:1;)
```

### Step 4 — Run Before Suppression (Q1 & Q2)

```bash
sudo snort -c task-07-challenge-snort.lua -R task-07-challenge-local.rules -r task-07-challenge.pcap -A alert_fast -q | grep -oE '10\.14\.22\.[0-9]+' | sort | uniq -c | sort -rn
```
```
145 10.14.22.99   ← DEV-HEALTH-01 (noise — suppress this)
 25 10.14.22.88   ← WKST-FINANCE-04 (signal)
```

**Total before suppression: 170 alerts**

### Step 5 — Add Suppression (Q3)

```bash
nano task-07-challenge-threshold.conf.lua
```

```lua
suppress =
{
    { gid = 1, sid = 1000100, track = 'by_src', ip = '10.14.22.99' }
}
```

```bash
sudo snort -c task-07-challenge-snort.lua -R task-07-challenge-local.rules -r task-07-challenge.pcap -A alert_fast -q --tweaks task-07-challenge-threshold.conf.lua | grep 1000100 | wc -l
```
```
25
```

### Step 6 — Extract C2 IPs into Blocklist

```bash
grep -oE '^\|[[:space:]]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' task-07-ti-report.md \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
  > task-07-challenge-blocklist.txt

wc -l task-07-challenge-blocklist.txt
```
```
12 task-07-challenge-blocklist.txt
```

Pipeline breakdown:
1. `grep` targets only markdown table rows opening with `|` + IP — scopes to infrastructure table
2. Second `grep` strips pipe/whitespace, leaves bare IP per line
3. Third `grep -v` filters RFC 1918 ranges — excludes internal hosts tabled in the report

### Step 7 — Enable Reputation Inspector

```bash
sudo nano task-07-challenge-snort.lua
```

```lua
reputation =
{
    blocklist = '/home/ubuntu/lab/task-07/task-07-challenge-blocklist.txt',
    memcap = 500,
    priority = 'blocklist',
    nested_ip = 'inner',
}
```

### Step 8 — Final Run (Q4)

```bash
sudo snort -c task-07-challenge-snort.lua -R task-07-challenge-local.rules -r task-07-challenge.pcap -A alert_fast -q --tweaks task-07-challenge-threshold.conf.lua | grep -oE '\[[0-9]+:[0-9]+:[0-9]+\]' | sort | uniq -c
```
```
12 [136:1:1]
```

Only reputation inspector alerts appear. When `gid 136` encounters a flow to a blocklisted C2 address, it acts before the detection engine evaluates the beacon rule — so `[1:1000100:1]` does not appear in the final summary.

### Answers

| Question | Answer |
|---|---|
| Total alerts before suppression? | `170` |
| Noise source to suppress? | `10.14.22.99` (DEV-HEALTH-01) |
| sid 1000100 alerts after suppression? | `25` |
| Reputation inspector alerts after loading blocklist? | `12` |

---

## Key Takeaways

### Detection Engineering Principles

| Principle | Application |
|---|---|
| Behaviour over signature | Beacon rule targets rhythm/size, not C2 IP — survives infrastructure rotation |
| Three-pass validation | Positive → Negative → Performance before shipping any rule |
| Suppression over rule edit | Silence known-good sources at sensor level, keep rule text stable for sharing |
| TI-driven blocklists age | Timestamp entries, validate regularly, pair with behaviour rules for coverage gaps |

### Snort 3 Rule Options Reference

| Option | Syntax | Purpose |
|---|---|---|
| `flow` | `flow:to_server,established` | Direction + session state gating |
| `content` | `content:"GET ", depth 4` | Payload match with position anchor |
| `dsize` | `dsize:<100` | Packet size constraint |
| `detection_filter` | `track by_src, count 5, seconds 360` | Threshold before alerting |
| `pkt_data` | `pkt_data` | Anchor content to raw TCP payload (Snort 3) |
| `metadata` | `mitre_attack T1071.001` | Attribution and SIEM context |

### Why Encrypted Traffic Still Leaks Signal

Even with TLS, QUIC, DoH, and ECH, these properties remain visible:
- **Timing** — beacon cadence cannot be encrypted
- **Packet size** — `dsize` works regardless of payload content
- **Flow direction** — client/server roles are always observable
- **Session frequency** — connection rate patterns survive encryption

---

*Writeup by gopalakrishnsak | TryHackMe India #1 | 
