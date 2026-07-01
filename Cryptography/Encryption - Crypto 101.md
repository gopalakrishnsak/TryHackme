
# Encryption - Crypto 101

**Room:** [Encryption - Crypto 101](https://tryhackme.com/room/encryptioncrypto101)
**Difficulty:** Medium
**Category:** Cryptography / Fundamentals


## Overview

This room covers the theoretical foundations of cryptography: symmetric vs.
asymmetric encryption, RSA maths, SSH key authentication, key exchange
(Diffie-Hellman), digital signatures/certificates, and PGP/GPG. It also
includes two hands-on practicals — cracking a passphrase-protected SSH
private key with John the Ripper, and decrypting a GPG-encrypted message
with a supplied private key.

This writeup documents the answers along with the methodology and tooling
used for the practical tasks (rather than just the raw answers), since
those are the more reusable/portable skills for OSCP-style work.

---

## Task 2 — Key Terms

Basic definitions (ciphertext, cipher, plaintext, encryption vs. encoding,
key vs. passphrase, symmetric vs. asymmetric, brute force vs.
cryptanalysis, Alice & Bob). No tooling required — pure recall.

**Q: Are SSH keys protected with a passphrase or a password?**
**A:** Passphrase

---

## Task 3 — Practical Applications of Cryptography

**Q: What does SSH stand for?**
**A:** Secure Shell

**Q: How do webservers prove their identity?**
**A:** Certificates

**Q: What is the main set of standards you need to comply with if you
store or process payment card details?**
**A:** PCI-DSS

---

## Task 4 — Modulo Arithmetic

Standard `%` operator refresher — foundational for understanding RSA key
generation later in the room.

| Expression | Result |
|---|---|
| `30 % 5` | `0` |
| `25 % 7` | `4` |
| `118613842 % 9091` | `3565` |

```python
>>> 30 % 5
0
>>> 25 % 7
4
>>> 118613842 % 9091
3565
```

---

## Task 5 — Symmetric vs. Asymmetric Encryption

**Q: Should you trust DES? Yea/Nay**
**A:** Nay — DES has a fatally short 56-bit key and is trivially
brute-forceable with modern hardware.

**Q: What was the result of the attempt to make DES more secure so that
it could be used for longer?**
**A:** 3DES (Triple DES) — applying DES three times with (up to) three
different keys to extend the effective key length. Still deprecated today
due to meet-in-the-middle attacks and small block size (64-bit).

**Q: Is it ok to share your public key? Yea/Nay**
**A:** Yea — that's the entire point of asymmetric cryptography; the
public key is meant to be distributed freely, only the private key must
stay secret.

---

## Task 6 — RSA Maths

RSA key generation relies on two large primes, `p` and `q`:

- `n = p × q` — the modulus, part of both the public and private key
- `φ(n) = (p-1)(q-1)` — Euler's totient, used to derive `e` and `d`
- `e` — public exponent (commonly `65537`)
- `d` — private exponent, the modular multiplicative inverse of `e mod φ(n)`

### Given: `p = 4391`, `q = 6659`

**Q: What is n?**

```python
>>> p, q = 4391, 6659
>>> n = p * q
>>> n
29239669
```

**A: n = 29,239,669**

Verified independently using
[`rsatool.py`](https://github.com/ius/rsatool), which derives the full
RSA parameter set (`n`, `e`, `d`, CRT components) from `p` and `q`:

```bash
$ python3 rsatool.py -p 4391 -q 6659
Using (p, q) to calculate RSA paramaters

n = 29239669 (0x1be2975)
e = 65537 (0x10001)
d = 17928213 (0x1119015)
p = 4391 (0x1127)
q = 6659 (0x1a03)
```

**φ(n)** (for reference, used internally to derive `d`):

```python
>>> phi = (p - 1) * (q - 1)
>>> phi
29228620
```

---

## Task 7 — Key Exchange (conceptual)

Covers the "lock box" analogy for how asymmetric crypto solves the
symmetric key-exchange problem without ever transmitting the actual
shared secret. No answerable question, just a comprehension checkpoint.

---

## Task 8 — Digital Signatures & Certificates

**Q: What can you use to verify that a file has not been modified and is
the authentic file as the author intended?**
**A:** Digital signature

Certificates extend this idea to identity verification (e.g., HTTPS),
relying on a chain of trust rooted in trusted Certificate Authorities
(CAs).

---

## Task 9 — SSH Keys (Practical: Cracking a Passphrase)

### Files provided
- `id_rsa_1593558668558.id_rsa` — an SSH private key, passphrase-protected

### Step 1 — Identify the key algorithm

```bash
$ cat id_rsa_1593558668558.id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0B5AB4FEB69AFB92B2100435B42B7949
...
-----END RSA PRIVATE KEY-----
```

**Q: What algorithm does the key use?**
**A:** RSA

The `DEK-Info` line also tells us the key itself is encrypted with
**AES-128-CBC**, and gives us the IV used to derive the encryption key
from the passphrase (OpenSSL legacy PEM encryption uses an MD5-based KDF
seeded with the first 8 bytes of the IV as salt).

### Step 2 — Convert to a crackable hash format

```bash
$ ssh2john id_rsa_1593558668558.id_rsa > jimmy.hash
$ cat jimmy.hash
id_rsa_1593558668558.id_rsa:$sshng$1$16$0B5AB4FEB69AFB92B2100435B42B7949$...
```

### Step 3 — Crack with John the Ripper + rockyou

```bash
$ john --wordlist=rockyou.txt jimmy.hash
```

This recovers the passphrase in a few thousand guesses since it's early
in the rockyou list.

### Verification / alternate method

I also independently verified the crack in Python without John, by
re-implementing OpenSSL's legacy PEM key derivation (`EVP_BytesToKey`,
MD5-based) and testing candidate passwords directly against the
AES-128-CBC-encrypted key body, checking for valid PKCS padding and a
DER `SEQUENCE` tag (`0x30`) on decrypt — a lightweight way to validate a
password guess without needing the full ASN.1 parse:

```python
import base64, hashlib
from Crypto.Cipher import AES

def derive_key(password, salt, key_len=16):
    d = b""
    d_i = b""
    while len(d) < key_len:
        d_i = hashlib.md5(d_i + password.encode() + salt).digest()
        d += d_i
    return d[:key_len]

def try_password(password, der, iv):
    salt = iv[:8]
    key = derive_key(password, salt)
    decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(der)
    pad = decrypted[-1]
    if not (1 <= pad <= 16):
        return False
    if decrypted[-pad:] != bytes([pad]) * pad:
        return False
    return decrypted[0] == 0x30  # DER SEQUENCE tag
```

Running this against `rockyou.txt` found a hit in under 4,000 attempts,
confirmed against OpenSSL directly:

```bash
$ openssl rsa -in id_rsa_1593558668558.id_rsa -passin pass:delicious -check -noout
RSA key ok
```

**Q: Crack the password with John The Ripper and rockyou, what's the
passphrase for the key?**
**A:** `delicious`

### Key takeaway for OSCP/OSEP

`ssh2john` + `john --wordlist=rockyou.txt` is a bread-and-butter move
whenever you land a private key with `Proc-Type: 4,ENCRYPTED` in the
header — this pattern shows up constantly in HTB/THM boxes and real
engagements where a key was pulled from a compromised host or a git repo
but is passphrase-locked.

---

## Task 10 — Diffie-Hellman Key Exchange (conceptual)

Covers the "combine your secret with public material, exchange the
combined values, combine again to reach a shared secret" model. No
answerable question — comprehension checkpoint only.

---

## Task 11 — PGP / GPG (Practical: Decrypting a File)

### Files provided
- `tryhackme.key` — an unprotected GPG private key
- `message.gpg` — a file encrypted with the corresponding public key

### Step 1 — Import the private key

```bash
$ gpg --import tryhackme.key
gpg: key FFA4B5252BAEB2E6: public key "TryHackMe (Example Key)" imported
gpg: key FFA4B5252BAEB2E6: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

### Step 2 — Decrypt the message

```bash
$ gpg --decrypt message.gpg
gpg: encrypted with rsa1024 key, ID 2A0A5FDC5081B1C5, created 2020-06-30
      "TryHackMe (Example Key)"
You decrypted the file!
The secret word is Pineapple.
```

**Q: You have the private key, and a file encrypted with the public key.
Decrypt the file. What's the secret word?**
**A:** `Pineapple`

Note: the key uses **RSA-1024**, which is itself well below modern
recommended key sizes (NSA guidance is RSA-3072+) — a nice practical tie
-in to the room's closing section on quantum-resistant key sizing.

---

## Task 12 — Quantum Computing & the Future of Encryption (conceptual)

Summary points worth remembering for OSCP/general awareness:

- RSA and ECC are both vulnerable to Shor's algorithm on a sufficiently
  powerful quantum computer — the "hard" factoring/discrete-log problems
  they rely on become efficiently solvable.
- AES-128 is weakened (not broken) by Grover's algorithm; AES-256 remains
  considered quantum-resistant for the foreseeable future.
- 3DES is also considered vulnerable to quantum attacks.
- Current NSA guidance: RSA-3072+ for asymmetric, AES-256+ for symmetric.
- NIST is running an active post-quantum cryptography standardization
  effort ahead of quantum computers becoming a practical threat
  (estimated ~2030+).

---

## Summary — Answer Key

| # | Question | Answer |
|---|---|---|
| 1 | SSH keys protected with passphrase or password? | Passphrase |
| 2 | SSH stands for | Secure Shell |
| 3 | How do webservers prove identity? | Certificates |
| 4 | Payment card data compliance standard | PCI-DSS |
| 5 | 30 % 5 | 0 |
| 6 | 25 % 7 | 4 |
| 7 | 118613842 % 9091 | 3565 |
| 8 | Trust DES? | Nay |
| 9 | DES made secure for longer → | 3DES |
| 10 | OK to share public key? | Yea |
| 11 | n given p=4391, q=6659 | 29,239,669 |
| 12 | Verifies file authenticity/integrity | Digital signature |
| 13 | SSH key algorithm | RSA |
| 14 | SSH key passphrase (John + rockyou) | delicious |
| 15 | GPG-decrypted secret word | Pineapple |

---

## Tools Used

- [`ssh2john`](https://github.com/openwall/john) (John the Ripper suite)
- [John the Ripper](https://www.openwall.com/john/) w/ rockyou.txt
- [`rsatool.py`](https://github.com/ius/rsatool) — RSA parameter derivation
- `openssl` — legacy PEM key inspection/verification
- `gpg` — GnuPG for key import and decryption
- Python 3 (`hashlib`, `pycryptodome`) — independent verification of the
  SSH key crack via manual OpenSSL legacy KDF + AES-128-CBC implementation

