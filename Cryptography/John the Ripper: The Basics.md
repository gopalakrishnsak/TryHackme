
#  John the Ripper - The Basics

**Room difficulty:** Easy | **Category:** Cryptography / Password Cracking

This one builds directly on the Hashing - Crypto 101 room, moving from theory into actually running John the Ripper against a bunch of different hash formats — raw hashes, Windows NTLM, `/etc/shadow`, and password-protected archives/keys. It's genuinely one of the most practically useful rooms I've done so far, since half of what it covers is stuff that shows up constantly once you've got a foothold on a real box.

---

## Task 1: Key Terms & Concepts

Quick recap of hashing fundamentals, plus the P vs NP framing for why hashes are one-way (easy to compute, computationally infeasible to reverse).

**What is the most popular extended version of John the Ripper?**

Stated directly in the task text — the "core" John distribution is limited, and the extended community edition with things like `zip2john`/`rar2john` is Jumbo John.

> `Answer: John the Ripper Jumbo`

---

## Task 2: Setting Up

Confirms Jumbo John and rockyou.txt are pre-installed on the AttackBox/Kali, and gets the lab machine running via SSH:

```bash
ssh user@10.48.177.204
```
Password: `Tryhackme123!`

**Which website's breach was the rockyou.txt wordlist created from?**

Straight from the task — rockyou.com, the 2009 breach that's basically the industry-standard password wordlist to this day.

> `Answer: rockyou.com`

---

## Task 3: Basic Hash Cracking

Covers John's basic syntax, automatic hash detection, format-specific cracking with `--format=`, and the `raw-` prefix convention for standard hash types.

Four hashes to identify and crack, no hints given this time — had to go off character count alone:

```bash
cat hash1.txt   # 2e728dd31fb5949bc39cac5a9f066498                    (32 hex = MD5)
cat hash2.txt   # 1A732667F3917C0F4AA98BB13011B9090C6F8065            (40 hex = SHA1)
cat hash3.txt   # D7F4D3CCEE7ACD3DD7FAD3AC2BE2AAE9C44F4E9B7FB802D...  (64 hex = SHA256)
cat hash4.txt   # c5a60cc6bbba781c601c5402755ae1044bbf45b78d1183c...  (128 hex = SHA512/Whirlpool)
```

Cracked the first three straightforwardly:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash3.txt
```

```
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
biscuit          (?)
1g 0:00:00:00 DONE 33.33g/s 89600p/s

Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
kangeroo         (?)
1g 0:00:00:00 DONE 33.33g/s 3904Kp/s

Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
microphone       (?)
1g 0:00:00:00 DONE 25.00g/s 2457Kp/s
```

Hash 4 was the interesting one. First instinct was `--format=raw-sha512`, but that ran to completion with zero cracks:

```
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
0g 0:00:00:14 DONE 0g/s 998172p/s
```

The room's own hint pointed at the actual issue: a 128-character hex hash isn't uniquely SHA512 — **Whirlpool** produces the exact same length output, and unlike the raw- family, it has its own dedicated John format name (no prefix needed). Switching format fixed it immediately:

```bash
john --format=whirlpool --wordlist=/usr/share/wordlists/rockyou.txt hash4.txt
```

This was a good practical lesson beyond just this room — character count alone isn't always sufficient for identification once you get into the 128-char range, since both SHA512 and Whirlpool land there. Context (where the hash came from, what generated it) matters just as much as the raw stats.

> `Answers:`
> `hash1.txt — MD5 — biscuit`
> `hash2.txt — SHA1 — kangeroo`
> `hash3.txt — SHA256 — microphone`
> `hash4.txt — Whirlpool — (cracked via --format=whirlpool)`

---

## Task 4: Cracking Windows Authentication Hashes

Covers NTHash/NTLM — the format modern Windows uses for SAM/NTDS.dit password storage, and where you'd typically encounter it (Mimikatz dumps, SAM extraction, pass-the-hash scenarios).

**What do we need to set the --format flag to in order to crack this hash?**

> `Answer: nt`

```bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
john --show --format=nt ntlm.txt
```

---

## Task 5: Cracking /etc/shadow with Unshadow

This is one of the more "real engagement" feeling tasks — combining `/etc/passwd` and `/etc/shadow` via the `unshadow` tool so John can parse the format correctly.

The lab gave a small narrative twist here: the task text referenced a file `etchashes.txt`, but the actual directory only contained `etc_hashes.txt` (underscore) plus pre-made `local_passwd` and `local_shadow` files. First attempt failed on the filename typo:

```bash
cat etchashes.txt
cat: etchashes.txt: No such file or directory
```

Then I made a bigger mistake — I ran an `echo` command to build `local_passwd` fresh, not realizing it was already correctly populated, and in the process almost overwrote good data. Caught it by re-catting all three files before running anything else:

```bash
cat local_passwd
root:x:0:0::/root:/bin/bash

cat local_shadow
root:x:0:0::/root:/bin/bash          # this was actually stale/wrong at this point

cat etc_hashes.txt
This is everything I managed to recover from the target machine before my computer crashed...
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::
```

The actual shadow hash was buried in `etc_hashes.txt` (behind a bit of in-room flavor text). Rebuilt `local_shadow` correctly with the real hash line, then ran unshadow:

```bash
echo 'root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::' > local_shadow

unshadow local_passwd local_shadow > unshadowed.txt
cat unshadowed.txt
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:0:0::/root:/bin/bash
```

Cracked immediately given the `$6$` prefix identified it as sha512crypt:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

```
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
1234             (root)
1g 0:00:00:02 DONE 0.4149g/s 531.1p/s
root:1234:0:0::/root:/bin/bash
1 password hash cracked, 0 left
```

Weak root password — `1234` cracked in about 2 seconds against 5000-round sha512crypt. Good reminder that even a deliberately slow hashing algorithm doesn't help if the underlying password is trivially guessable.

> `Answer: 1234`

---

## Task 6: Single Crack Mode & Word Mangling

Introduces John's Single Crack mode — instead of brute-forcing against a huge external wordlist, John builds a small candidate list directly out of the *username* itself (plus GECOS field data like full name/home dir if available), then mutates it with mangling rules (capitalization swaps, leetspeak substitutions, appended digits/symbols).

The file format requirement here is important — you have to prepend the username to the hash with a colon:

```bash
cat hash07.txt
7bf6d9bb82bed1302f331fc6b816aada          # 32 hex = MD5

echo "joker:$(cat hash07.txt)" > joker_hash.txt
cat joker_hash.txt
joker:7bf6d9bb82bed1302f331fc6b816aada
```

```bash
john --single --format=raw-md5 joker_hash.txt
```

```
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: Only 18 candidates buffered for the current salt, minimum 24 needed for performance.
Jok3r            (joker)
1g 0:00:00:00 DONE 50.00g/s 9800p/s
```

Cracked in under a second — John mutated "joker" with a leetspeak swap (3 for e) and landed on it almost immediately, without ever touching rockyou.txt. This is the exact scenario single crack mode is built for: usernames that hint directly at the password.

> `Answer: Jok3r`

---

## Task 7: Custom Rules

Covers writing your own mangling rules in `john.conf` (`/opt/john/john.conf` on the AttackBox) to exploit predictable password-complexity patterns — e.g. capital first letter, number + symbol appended at the end (`Polopassword1!`-style).

Rule syntax basics: `Az` appends, `A0` prepends, `c` capitalizes, and character sets go in square brackets (`[0-9]`, `[A-Z]`, custom symbol sets, etc.), all inside a named `[List.Rules:Name]` block.

**What do custom rules allow us to exploit?**

> `Answer: Password complexity predictability`

**What rule would we use to add all capital letters to the end of the word?**

Following the exact pattern from the `PoloPassword` example (`cAz"[0-9] [!£$%@]"`), swapping in only the "append uppercase" piece:

> `Answer: Az"[A-Z]"`

**What flag would we use to call a custom rule called THMRules?**

> `Answer: --rule=THMRules`

---

## Task 8: Cracking Zip File Passwords

`zip2john` converts a password-protected zip into a John-readable hash format — same conversion-tool pattern that shows up repeatedly throughout this room.

```bash
zip2john secure.zip > zip_hash.txt
cat zip_hash.txt
secure.zip/zippy/flag.txt PKZIP Encr: 2b chk...
secure.zip/zippy/flag.txt:$pkzip$1*2*2*0*26*1a*849ab5a6*0*48*0*26*b689*964fa5a31f8cefe8e6b3456b578d66a08489def78128450ccf07c28dfa6c197fd148f696e3a2*$/pkzip$:zippy/flag.txt:secure.zip::secure.zip

john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

```
Loaded 1 password hash (PKZIP [32/64])
pass123          (secure.zip/zippy/flag.txt)
1g 0:00:00:00 DONE 50.00g/s 409600p/s
```

Extracting hit a small speed bump — fat-fingered the password entry twice before getting it right (`unzip` doesn't echo the password back, easy to mistype blind):

```bash
unzip secure.zip
[secure.zip] zippy/flag.txt password:
password incorrect--reenter:
password incorrect--reenter:
 extracting: zippy/flag.txt          OK
```

Then hit a classic path mistake reading the flag — tried the absolute path first instead of relative:

```bash
cat /zippy/flag.txt
cat: /zippy/flag.txt: No such file or directory

cat zippy/flag.txt
THM{w3ll_d0n3_h4sh_r0y4l}
```

Small thing, but a good habit to reinforce: `/zippy/flag.txt` (absolute, from filesystem root) and `zippy/flag.txt` (relative, from current directory) are completely different paths. Worth running `pwd` when in doubt.

> `Answer: pass123`
> `Flag: THM{w3ll_d0n3_h4sh_r0y4l}`

---

## Task 9: Cracking RAR File Passwords

Same pattern again, this time with `rar2john`:

```bash
/opt/john/rar2john secure.rar > rar_hash.txt
cat rar_hash.txt
secure.rar:$rar5$16$b7b0ffc959b2bc55ffb712fc0293159b$15$4f7de6eb8d17078f4b3c0ce650de32ff$8$ebd10bb79dbfb9f8

john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```

```
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
password         (secure.rar)
1g 0:00:00:00 DONE 1.667g/s 106.7p/s
```

Extraction went smoothly this time (`unrar x secure.rar`, password entered once correctly):

```bash
unrar x secure.rar
Extracting  flag.txt   OK

cat flag.txt
THM{r4r_4rch1ve5_th15_t1m3}
```

> `Answer: password`
> `Flag: THM{r4r_4rch1ve5_th15_t1m3}`

---

## Task 10: Cracking SSH Private Key Passwords

The last practical task — `ssh2john` converts an `id_rsa` private key's password protection into a crackable hash. This one comes up a fair bit in CTFs where you find a private key during enumeration but it's passphrase-protected.

```bash
python3 /opt/john/ssh2john.py id_rsa > id_rsa_hash.txt
cat id_rsa_hash.txt
id_rsa:$sshng$1$16$3A98F468854BB3836BF689310D864CE9$1200$08ca19b68bc606b07875701174131b9220d23ef968befc1230eeff0d7c0f904e...

john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```

```
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
mango            (id_rsa)
1g 0:00:00:00 DONE 50.00g/s 214400p/s
```

Cracked instantly.

> `Answer: mango`

---

## Wrap-up

This room is a genuinely solid, practical tour of everything John the Ripper is used for beyond just "run it against a wordlist." The conversion-tool pattern (`zip2john`, `rar2john`, `ssh2john`, `unshadow`) repeats constantly and is worth internalizing — same logic applies to tools not covered here like `pdf2john`.

**Key takeaways:**
- Character count alone can be ambiguous once you hit 128 hex chars (SHA512 vs Whirlpool) — always sanity-check with `john --list=formats | grep`
- Single crack mode + word mangling is *fast* and should be tried first whenever you have a username tied to a hash — don't default straight to a full wordlist attack
- Custom rules exist because humans are predictable about where they put capitals/numbers/symbols to satisfy complexity requirements
- The `*2john` family (zip2john, rar2john, ssh2john, unshadow) all follow the same conversion → crack pattern
- Watch absolute vs relative paths when reading extracted files — easy mistake under pressure
- Double-check pre-supplied files before overwriting them with your own commands — lost a few minutes here rebuilding `local_shadow` after a premature `echo`
