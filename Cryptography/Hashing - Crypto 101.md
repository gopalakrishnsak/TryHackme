
# TryHackMe — Hashing - Crypto 101

**Room:** [Hashing - Crypto 101](https://tryhackme.com/room/hashingcrypto101)
**Difficulty:** Medium
**Category:** Cryptography
**Path:** Cryptography Module

## Overview

An introduction to hashing as part of TryHackMe's crypto series. Covers the difference between encoding, hashing, and encryption, hash collisions, password storage/rainbow tables, salting, hash identification (Unix prefixes, Windows NTLM), and practical hash cracking using online tools, hashcat, and John the Ripper.

---

## Task 1 — Key Terms

**Q: Is base64 encryption or encoding?**
Encoding. Base64 is a data representation format, not a cryptographic transform — it's immediately reversible with no key required.

---

## Task 2 — Hashing Basics

**Q: What's a hash function?**
A one-way function that takes input data of any size and produces a fixed-size digest. It should be computationally infeasible to reverse (go from digest back to input), and a small change in input should produce a large, unpredictable change in output (avalanche effect).

**Q: What's a hash collision?**
When two different inputs produce the same hash output. Collisions are unavoidable in principle due to the pigeonhole principle — finite output space, infinite possible inputs — but a strong algorithm makes them computationally infeasible to *engineer* intentionally. MD5 and SHA1 have both had practical collision attacks demonstrated, so neither should be trusted for security-sensitive hashing.

**Q: What is the output size in bytes of the MD5 hash function?**
`16` bytes (128 bits).

**Q: Can you avoid hash collisions?**
`Nay` — unavoidable due to the pigeonhole principle.

**Q: If you have an 8-bit hash output, how many possible hashes are there?**
`256` (2^8).

---

## Task 3 — Hashing for Password Verification

Covers why plaintext password storage is dangerous (RockYou, Adobe breaches), why encryption is unsuitable for passwords (key has to be stored somewhere), and why hashing solves this — but introduces the rainbow table problem for unsalted hashes.

**Q: Crack the hash `d0199f51d2728db6011945145a1b607a` using the rainbow table manually.**
`basketball` (found via the provided lookup table — MD5).

**Q: Crack the hash `5b31f93c09ad1d065c0491b764d04933` using online tools.**
`tryhackme` (cracked via [hashes.com](https://hashes.com)).

**Q: Should you encrypt passwords?**
`Nay` — hash with a strong, salted algorithm instead (bcrypt, sha512crypt, etc.).

---

## Task 4 — Identifying Hashes

Covers Unix-style password hash prefixes (`$1$` = md5crypt, `$2/2a/2b$` = bcrypt, `$6$` = sha512crypt), Windows NTLM (an MD4 variant), and the hashcat example-hashes page as a reference for identifying less common formats.

**Q: How many rounds does sha512crypt (`$6$`) use by default?**
`5000`

**Q: What's the hashcat example hash (from the website) for Citrix Netscaler hashes?**
`1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea`

**Q: How long is a Windows NTLM hash, in characters?**
`32`

---

## Task 5 — Cracking Hashes

Practical cracking exercise covering bcrypt, SHA-256, sha512crypt, and MD5, using a mix of online crackers, hashcat, and John the Ripper.

**Q: Crack this hash:** `$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG`
Identified via prefix `$2a$` as **bcrypt**.
```bash
hashcat -m 3200 -a 0 -o cracked.txt bcrypt.txt /usr/share/wordlists/rockyou.txt
```
Answer: `85208520`

**Q: Crack this hash:** `9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1`
64 hex chars → **SHA-256**.
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 hash.txt
```
Answer: `halloween`

**Q: Crack this hash:** `$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0`
Identified via prefix `$6$` as **sha512crypt**. rockyou alone wasn't sufficient via local tools in most public solves; cracked via online lookup (hashes.com / CrackStation).
Answer: `spaceman`

**Q: Bored of this yet? Crack this hash:** `b6b0d451bbf6fed658659a9e7e5598fe`
32 hex chars → **MD5**.
Answer: `funforyou`

> **Note:** All of the above were verified against publicly cracked values. For your own runs, identify the hash type first (`hashid`/prefix/length), then crack with hashcat or John using `rockyou.txt`. Never use `--force` with hashcat — it can produce false positives/negatives.

---

## Task 6 — Checking Integrity / HMACs

Covers using hashes to verify file integrity (downloads, deduplication) and HMACs (Hash-based Message Authentication Codes), which combine a hash function with a secret key to provide both **authenticity** and **integrity** — TryHackMe's own VPN uses HMAC-SHA512 for this.

**Q: What's the SHA1 sum for the amd64 Kali 2019.4 ISO?**
Found in the `SHA1SUMS` file at `http://old.kali.org/kali-images/kali-2019.4/`.
`186c5227e24ceb60deb711f1bdc34ad9f4718ff9`

**Q: What's the hashcat mode number for HMAC-SHA512 (key = $pass)?**
Found via the [hashcat example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes).
`1750`

---

## Key Takeaways

- Encoding ≠ encryption ≠ hashing — three fundamentally different operations with different reversibility properties.
- Never encrypt passwords; hash them with a strong, salted, slow algorithm (bcrypt, sha512crypt, argon2).
- Salting defeats precomputed rainbow tables by making every hash unique per user, even for identical passwords.
- Unix password hash prefixes (`$1$`, `$2a$`, `$6$`, etc.) are a fast, reliable way to identify hash type before cracking.
- HMACs provide authenticity + integrity by combining a hash function with a secret key — distinct from a plain hash, which only gives integrity.
- Always identify the hash type before attempting to crack it — wastes far less time than blind brute forcing with the wrong mode.

---

