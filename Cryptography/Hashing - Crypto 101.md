# Hashing - Crypto 101

**Room difficulty:** Medium | **Category:** Cryptography / Hash Cracking

This room is part of TryHackMe's crypto series, and it's basically the foundation everything else on hash cracking builds on top of. Before this room I honestly used "encoding" and "encryption" pretty loosely in my head, so having to actually sit down and separate the terminology out was more useful than I expected.

---

## Task 1: Key Terms

The room opens with jargon: plaintext, encoding, hash, brute force, cryptanalysis. Nothing to crack yet, just definitions to lock in.

**Is base64 encryption or encoding?**

Encoding. This tripped me up conceptually more than I want to admit — base64 *looks* like it's hiding something, but it's fully reversible with no key involved. Encryption needs a key to reverse it; encoding is just a different representation of the same data. `echo "hello" | base64` and `base64 -d` back and forth drove the point home.

> `Answer: Encoding`

---

## Task 2: Hashing Basics

This is where the real content starts — hash functions, collisions, why MD5/SHA1 are considered broken.

**What is the output size in bytes of the MD5 hash function?**

MD5 outputs 128 bits. 128 ÷ 8 = 16 bytes.

> `Answer: 16`

**Can you avoid hash collisions? (Yea/Nay)**

Nay. This comes straight from the pigeonhole principle explained in the task — finite output space, infinite possible inputs, so somewhere down the line two different inputs *have* to produce the same hash. You can't design that away, you can only make it computationally impractical to find one on purpose.

> `Answer: Nay`

**If you have an 8 bit hash output, how many possible hashes are there?**

2^8 = 256.

> `Answer: 256`

---

## Task 3: Hashing for Passwords

This section covers why plaintext password storage is bad (rockyou.txt origin story), why encryption isn't the answer either (key has to live somewhere), rainbow tables, and salting.

**Crack the hash `d0199f51d2728db6011945145a1b607a` using the rainbow table manually.**

This one's a lookup, not a crack — the room gives you a small hash:password table earlier in the task, and this hash is sitting right in it.

> `Answer: basketball`

**Crack the hash `5b31f93c09ad1d065c0491b764d04933` using online tools**

This one you actually have to go find. I dropped it into an online MD5 cracker (crackstation.net works fine here) and it resolved instantly. Fun detail — the answer is literally the name of the platform you're doing the room on.

> `Answer: letmein`

**Should you encrypt passwords? Yea/Nay**

Nay. The task spells out exactly why: encryption requires a key, and that key has to be stored *somewhere*. If an attacker gets the key, every password decrypts instantly. Hashing (ideally salted) has no key to steal — there's nothing to reverse, only guess-and-check.

> `Answer: Nay`

---

## Task 4: Hash Identification

This is the section that actually matters day-to-day. The room lays out the standard Unix hash prefix format (`$format$rounds$salt$hash`) and a table of common prefixes:

| Prefix | Algorithm |
|---|---|
| `$1$` | md5crypt |
| `$2$, $2a$, $2b$, $2x$, $2y$` | bcrypt |
| `$6$` | sha512crypt |

**How many rounds does sha512crypt ($6$) use by default?**

> `Answer: 5000`

**What's the hashcat example hash (from the website) for Citrix Netscaler hashes?**

Pulled straight from hashcat's example_hashes page.

> `Answer: 1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea`

**How long is a Windows NTLM hash, in characters?**

32 characters — same length as a raw MD5 hash, which is exactly why the room hammers on using context (not just automated tools) to tell hash types apart. An automated identifier will happily call an NTLM hash "MD5" and be technically correct about the length while being completely wrong about the algorithm.

> `Answer: 32`

---

## Task 5: Cracking Hashes — Hands On

This is the practical section — four hashes to identify and crack. No handholding on hash type here, so I had to work it out from character count and prefix the same way the previous task explained.

First step was identifying each one:

- `$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG` → `$2a$` prefix = **bcrypt**, cost factor 06
- `9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1` → 64 hex chars, no prefix = **raw SHA-256**
- `$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0` → `$6$` prefix = **sha512crypt**
- `b6b0d451bbf6fed658659a9e7e5598fe` → 32 hex chars, no prefix = **raw MD5**

Saved each into its own file and ran hashcat against rockyou:

```bash
echo '$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG' > hash1.txt
echo '9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1' > hash2.txt
echo '$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0' > hash3.txt
echo 'b6b0d451bbf6fed658659a9e7e5598fe' > hash4.txt

hashcat -m 3200 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt    # bcrypt
hashcat -m 1400 -a 0 hash2.txt /usr/share/wordlists/rockyou.txt    # sha256
hashcat -m 1800 -a 0 hash3.txt /usr/share/wordlists/rockyou.txt    # sha512crypt
hashcat -m 0    -a 0 hash4.txt /usr/share/wordlists/rockyou.txt    # md5
```

Three of the four cracked cleanly:

```
$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG:85208520
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Speed.#01........:     2104 H/s (12.75ms)
Recovered........: 1/1 (100.00%)
```

```
9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1:halloween
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Speed.#01........:  2171.9 kH/s (0.41ms)
```

```
$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0:spaceman
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Speed.#01........:     2788 H/s (14.16ms)
```

Worth noticing the massive speed gap here — the raw MD5 attempt below hit **4.29 MH/s**, while bcrypt and sha512crypt limped along at ~2,000-2,800 H/s. That's not a fluke, it's the entire point of those algorithms — they're deliberately slow (bcrypt's cost factor, sha512crypt's 5000 rounds) specifically to make brute-forcing painful even on decent hardware.

The fourth one didn't crack:

```
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: b6b0d451bbf6fed658659a9e7e5598fe
Speed.#01........:  4290.1 kH/s (0.23ms)
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
```

100% of rockyou.txt run through, zero cracked. This is a genuinely important lesson and not just a fail state — rockyou is huge but it isn't infinite, and plenty of real passwords simply won't be in it. In a real scenario the next moves would be trying a bigger/different wordlist, applying mutation rules (`best64.rule` etc.) on top of rockyou, or falling back to an online cracker that might draw from a different database. I threw it at an online MD5 cracker and it resolved from there — a good reminder that no single tool or wordlist is the whole answer.

> `Answers:`
> `85208520`
> `halloween`
> `spaceman`
> `(cracked via online tool, not in rockyou)`

---

## Task 6: Checking / HMACs

The final task covers hashing for file integrity checking and introduces HMACs (keyed hashes for authenticity + integrity verification).

**What's the SHA1 sum for the amd64 Kali 2019.4 ISO?**

Pulled from Kali's official checksums page for that release.

> `Answer: 186c5227e24ceb60deb711f1bdc34ad9f4718ff9`

**What's the hashcat mode number for HMAC-SHA512 (key = $pass)?**

Confirmed with `hashcat --help | grep -i "hmac-sha512"`.

> `Answer: 1750`

---

## Wrap-up

This room is deceptively "medium" — it's mostly reading, but the practical section forces you to actually apply the hash-identification logic (prefix + character count) rather than just trusting an automated tool, which is exactly the habit you want going into OSCP. The MD5-exhausting-rockyou moment was probably the most useful part of the whole room for me — it's easy to assume rockyou is a magic bullet, and it's good to hit a wall with it early in a safe environment instead of during an actual exam.

**Key takeaways:**
- Encoding ≠ encryption ≠ hashing — three different things, three different reversibility properties
- Hash type identification: prefix first (`$1$`, `$2a$`, `$6$` etc.), then character count if no prefix (32=MD5/NTLM, 40=SHA1, 64=SHA256, 128=SHA512/Whirlpool)
- Slow algorithms (bcrypt, sha512crypt) resist cracking by design — the speed difference is dramatic and intentional
- rockyou.txt is big, not complete — plan for wordlist failures
