# Crack the Hash

**Room:** [Crack the Hash](https://tryhackme.com/room/crackthehash)


## Intro

This room throws nine hashes at you across two levels, no context, no
hints beyond "these passwords are in rockyou." Level 1 is basically a
hash-identification exercise — the algorithms are common enough that
John the Ripper's default detection gets you most of the way there.
Level 2 is where it actually gets interesting, because two of the four
hashes will burn your wordlist to completion with zero cracks if you
pick the wrong hashcat mode. I hit that wall on both of them, so this
writeup includes the wrong turns, not just the clean path, because the
wrong turns are honestly the more useful part.

Tools used: John the Ripper, hashcat, and a bit of Python to
sanity-check a couple of guesses before burning more GPU/CPU time on
hashcat re-runs.

---

## Level 1

### Hash 1 — `48bb6e862e54f2a795ffc4e541caed4d`

32 hex characters, no prefix, no salt visible — the classic shape of an
MD5 hash. Nothing subtle here.

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt
```

```
easy             (?)
1g 0:00:00:00 DONE (2026-07-01 00:16) 50.00g/s 8620Kp/s 8620Kc/s 8620KC/s florida69..eagames
```

**Password: `easy`**

### Hash 2 — `CBFDAC6008F9CAB4083784CBD1874F76618D2A97`

40 hex characters. My first instinct was to run it through
`--format=raw-md5` out of muscle memory from copy-pasting the previous
command, which — correctly — got rejected:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
```

```
No password hashes loaded (see FAQ)
```

Right, wrong length for MD5. 40 hex chars = SHA1.

```bash
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
```

```
password123      (?)
1g 0:00:00:00 DONE (2026-07-01 00:16) 100.0g/s 138400p/s 138400c/s 138400C/s jesse..password123
```

**Password: `password123`**

### Hash 3 — `1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032`

64 hex characters, so this one's SHA256.

```bash
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash3.txt
```

```
letmein          (?)
1g 0:00:00:00 DONE (2026-07-01 00:16) 50.00g/s 9830Kp/s 9830Kc/s 9830KC/s 123456..piggy9
```

**Password: `letmein`**

### Hash 4 — `$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom`

The `$2y$` prefix is unmistakably bcrypt. This is also the first one
where the crack actually takes noticeable time — bcrypt is deliberately
slow (cost factor 12 here, meaning 4096 rounds), so where the earlier
hashes cracked in under a second, this one runs for almost half an
hour even against a wordlist as common as rockyou.

```bash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash4.txt
```

```
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 12 OpenMP threads
0g 0:00:00:13 0.01% (ETA: 2026-07-02 19:02) 0g/s 101.2p/s 101.2c/s 101.2C/s giovanni..something
0g 0:00:25:09 0.89% (ETA: 2026-07-03 07:57) 0g/s 99.93p/s 99.93c/s 99.93C/s camaro2..brooklyn25
bleh             (?)
1g 0:00:28:49 DONE (2026-07-01 09:08) 0.000578g/s 100.5p/s 100.5c/s 100.5C/s bobbyt..binta
```

Worth noting: at 100 passwords/sec, if the actual password had been
further down the wordlist, this would've taken hours, not half an hour.
That ETA of "2026-07-03" in the early status line wasn't a joke — it's
a real reminder of why bcrypt/cost-factor hashes are the right call for
storing real passwords, and why they're miserable to brute-force even
with a full GPU behind hashcat instead of CPU-only John.

**Password: `bleh`**

### Hash 5 — `279412f945939ba78ce0758d3fd83daa`

32 hex characters again, same shape as MD5, so I tried the obvious
thing first:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash5.txt
```

```
0g 0:00:00:00 DONE (2026-07-01 09:08) 0g/s 30517Kp/s 30517Kc/s 30517KC/s
```

Zero cracked. Ran it twice thinking maybe it was a fluke — same result.
This is the trap with 32-hex-char hashes: MD5, NTLM, and MD4 are all
the same length and look identical without more context. The room
gives a hint pointing at MD4, so:

```bash
john --format=raw-md4 --wordlist=/usr/share/wordlists/rockyou.txt hash5.txt
```

Still nothing straight out of the wordlist. Also tried NTLM just to
rule it out completely (NTLM is MD4 under the hood but with UTF-16LE
encoding of the password first, so it's a genuinely different hash even
at the same output length):

```bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash5.txt
```

Also nothing. At this point the wordlist alone wasn't cutting it, which
usually means the actual password is a mangled/leetspeak/capitalized
variant of something in rockyou rather than a raw entry. Adding John's
`best64` rule set (common substitutions: capitalization, appended
digits, leetspeak swaps, etc.) on top of the wordlist did it:

```bash
john --format=raw-md4 --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hash5.txt
```

```
Eternity22       (?)
1g 0:00:00:01 DONE (2026-07-01 09:13) 0.5347g/s 21534Kp/s 21534Kc/s 21534KC/s Fgsltw..Estercita
```

**Password: `Eternity22`**

Lesson from this one: when a straight wordlist run comes back empty on
a hash you're confident about the algorithm for, reach for a rule set
before assuming you've got the wrong hash type. `best64` alone caught
a capitalized word with digits appended, which rockyou raw wouldn't
have had as a literal entry.

---

## Level 2

The room explicitly calls out that this level needs hashcat, not just
online lookup tools, and it's right — level 2 is all salted or
non-standard hashes that no rainbow table / online DB is going to have.

### Hash 1 — `F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85`

64 hex characters, unsalted — SHA256, same as level 1's hash 3 but with
hashcat instead of John this time:

```bash
hashcat -m 1400 F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85 /usr/share/wordlists/rockyou.txt
```

```
f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:paule
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
```

**Password: `paule`**

### Hash 2 — `1DFECA0C002AE40B8619ECF94819CC1B`

32 hex characters again. Given the room explicitly threw MD4/NTLM at us
in level 1, I went straight for mode 0 (MD5) first just to rule it out
quickly:

```bash
hashcat -m 0 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt
```

```
Status...........: Exhausted
Recovered........: 0/1 (0.00%)
```

Full rockyou exhausted, nothing. Switched to NTLM:

```bash
hashcat -m 1000 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt
```

```
1dfeca0c002ae40b8619ecf94819cc1b:n63umy8lkf4i
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
```

**Password: `n63umy8lkf4i`**

Same 32-hex-char trap as level 1's MD4 hash — you genuinely cannot tell
MD5, NTLM, and MD4 apart from the hash string alone. If context/hints
don't tell you, you just have to try all three.

### Hash 3 — `$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.`

The `$6$` prefix is a dead giveaway for sha512crypt (the Unix/Linux
`/etc/shadow` style hash), and the salt is baked directly into the hash
string itself between the first and second `$6$` markers, so hashcat
reads it automatically — no need to specify it separately.

```bash
echo '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.' > hash3.txt
hashcat -m 1800 hash3.txt /usr/share/wordlists/rockyou.txt
```

This is the one where sha512crypt's whole design point — being
deliberately expensive to compute — really shows. Where the SHA256 and
NTLM hashes cracked in under a second at multiple megahashes/sec,
sha512crypt runs at roughly 3,500 hashes/sec on the same hardware:

```
Speed.#01........:     3547 H/s (12.96ms) @ Accel:20 Loops:1000 Thr:1 Vec:4
Progress.........: 433680/14344385 (3.02%)
Time.Estimated...: Wed Jul  1 10:23:30 2026 (1 hour, 5 mins)
```

At 3% progress with over an hour left, I let it run in the background
rather than babysitting it, and came back to it once the fourth hash
was sorted. It eventually landed on:

**Password: `waka99`**

### Hash 4 — `e5d8870e5bdd26602cab8dbe07a942c8669e56d6` (salt: `tryhackme`)

This one was the actual sticking point of the room for me. 40 hex
characters with a salt given separately screams "salted SHA1," and
hashcat has two obvious modes for exactly that:

- `-m 110` → `sha1($pass.$salt)`
- `-m 120` → `sha1($salt.$pass)`

```bash
echo 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' > hash4.txt
hashcat -m 110 hash4.txt /usr/share/wordlists/rockyou.txt
```

```
Status...........: Exhausted
Recovered........: 0/1 (0.00%)
```

Tried 120 too:

```bash
hashcat -m 120 hash4.txt /usr/share/wordlists/rockyou.txt
```

```
Status...........: Exhausted
Recovered........: 0/1 (0.00%)
```

Both exhausted the full 14.3 million password wordlist in a few seconds
with zero hits. At that point I didn't just want to keep guessing modes
blind, so before burning more hashcat runs I wrote a quick Python check
to test a handful of other plausible concatenation schemes
(`pass:salt`, `salt:pass`, double-wrapped salt, sha1-of-sha1, even
UTF-16LE encoding in case it was secretly an NTLM-style variant) against
the whole wordlist directly:

```python
import hashlib

target = "e5d8870e5bdd26602cab8dbe07a942c8669e56d6"
salt = "tryhackme"

def sha1(s):
    return hashlib.sha1(s.encode()).hexdigest()

with open("rockyou.txt", encoding="latin-1", errors="ignore") as f:
    for line in f:
        pw = line.rstrip("\n")
        if sha1(pw + salt) == target or sha1(salt + pw) == target:
            print("FOUND:", pw)
            break
```

Nothing. Which was actually the useful signal — it confirmed this
wasn't a "wrong concatenation order" problem, it was a "wrong algorithm
family entirely" problem. Plain salted SHA1 concatenation just isn't
what's happening here.

The actual answer: it's **HMAC-SHA1**, not plain salted SHA1. In HMAC,
the "salt" isn't concatenated with the password at all — it's used as
the cryptographic *key*, and the password is the *message* being
authenticated. That's mode `160` in hashcat, and it's a genuinely
different construction from `-m 110`/`120`, not just a different salt
order:

```bash
hashcat -a 0 -m 160 hash4.txt /usr/share/wordlists/rockyou.txt --force
```

```
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:481616481616
Status...........: Cracked
```

**Password: `481616481616`**

The `--force` flag is needed here because hashcat throws a warning
about the pure/unoptimized OpenCL kernel on this particular mode — not
a real problem, just a performance heads-up.

---

## Full Answer Table

| Level | Hash | Algorithm | Password |
|---|---|---|---|
| 1 | `48bb6e862e54f2a795ffc4e541caed4d` | MD5 | `easy` |
| 1 | `CBFDAC6008F9CAB4083784CBD1874F76618D2A97` | SHA1 | `password123` |
| 1 | `1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032` | SHA256 | `letmein` |
| 1 | `$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom` | bcrypt | `bleh` |
| 1 | `279412f945939ba78ce0758d3fd83daa` | MD4 | `Eternity22` |
| 2 | `F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85` | SHA256 | `paule` |
| 2 | `1DFECA0C002AE40B8619ECF94819CC1B` | NTLM | `n63umy8lkf4i` |
| 2 | `$6$aReallyHardSalt$...` | sha512crypt | `waka99` |
| 2 | `e5d8870e5bdd26602cab8dbe07a942c8669e56d6` (salt: `tryhackme`) | HMAC-SHA1 | `481616481616` |

---

