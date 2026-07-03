# Breaking Crypto the Simple Way

**Difficulty:** Easy | **Category:** Cryptography | **Time taken:** ~1 hour

This room is a tour through the classic ways developers screw up crypto — weak RSA key generation, weak HMAC keys, hardcoded encryption keys in client-side JS, and unauthenticated encryption leading to bit-flipping attacks. Four tasks, four flags. Here's how I got each one, mistakes included.

---

## Task 1: Broadcast RSA — Factoring a Weak Modulus

The room hands you a public key and a ciphertext:

```
n = 43941819371451617899582143885098799360907134939870946637129466519309346255747
e = 65537
c = 9002431156311360251224219512084136121048022631163334079215596223698721862766
```

The premise is that `n` is a product of two *weakly generated* primes, so instead of it being computationally infeasible to factor (like it should be for real RSA), we're supposed to be able to pull `p` and `q` apart relatively easily.

### First attempt: just factor it locally

The room's own script suggests this:

```python
from sympy import factorint
n = 43941819371451617899582143885098799360907134939870946637129466519309346255747
factors = factorint(n)
```

I let this run and it just... sat there. `factorint()` uses Pollard's rho by default, and for a ~77-digit number that isn't trivially smooth, that's not guaranteed to finish quickly. I also tried a manual Fermat factorization (works great when p and q are close together) — no luck within a reasonable number of iterations, so the primes clearly aren't close to each other. That ruled out one specific "weakness" and pointed me toward a different one: maybe this modulus is just a *known* weak key that's already sitting in a public database.

### Second attempt: FactorDB

[FactorDB](http://factordb.com) keeps a crowd-sourced database of integer factorizations, and CTF/training moduli show up there constantly because someone always ends up trying to factor them. I pasted `n` into the search box and got a hit:

```
4394181937...47<77> = 205237461320000835821812139013267110933<39> · 214102333408513040694153189550512987959<39>
```

Small hiccup here — when I first transcribed the numbers off the screenshot, I miscounted a digit in `p` (missed one `3` near the end) and my `p * q` didn't reproduce `n`. Zoomed in on the image at higher resolution, recounted carefully, and confirmed:

```
p = 205237461320000835821812139013267110933
q = 214102333408513040694153189550512987959
```

`p * q == n` ✅ — factoring done, no brute-force compute required.

### Deriving the private key and decrypting

Standard RSA textbook math from here:

```python
from Crypto.Util.number import inverse, long_to_bytes

p = 205237461320000835821812139013267110933
q = 214102333408513040694153189550512987959
e = 65537
c = 9002431156311360251224219512084136121048022631163334079215596223698721862766
n = p * q

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

plaintext = pow(c, d, n)
flag = long_to_bytes(plaintext)
print(flag.decode())
```

Running this on my actual box took a couple of tries — I initially had a `NameError: name 'd' is not defined` because I'd pasted the phi calculation and the decryption step into the file separately without the intermediate `d = inverse(...)` line, then hit `ModuleNotFoundError: No module named 'Crypto'` because pycryptodome wasn't installed yet (`pip install pycryptodome --break-system-packages` sorted that — my first attempt at fixing it was `pipx install pycryptodome`, which was the wrong tool entirely; pipx is for CLI apps, not importable libraries).

Once the script actually ran end to end:

```
Phi(n) = 43941819371451617899582143885098799360487795145142432760613501190745566156856
Private key (d): 42863673506531127160266519316271436658935017712647978759376543290403486562425
THM{Psssss_4nd_Qsssssss}
```

**Flag:** `THM{Psssss_4nd_Qsssssss}`

The flag name is a nod to the paper this task is based on — "P's and Q's" by Ross Anderson and Serge Vaudenay, about weak RSA prime generation.

---

## Task 2: HMAC-SHA1 with a Weak Key

Given:

```
Message: CanYouGuessMySecret
SHA1-Digest: 1484c3a5d65a55d70984b4d10b1884bda8876c1d
```

This is HMAC-SHA1, so the "digest" isn't just a hash of the message — it's `HMAC(key, message)`, and the key is deliberately weak (probably straight out of a common password list). Hashcat mode `150` targets exactly this.

```bash
echo -n "1484c3a5d65a55d70984b4d10b1884bda8876c1d:CanYouGuessMySecret" > digest.txt
hashcat -a 0 -m 150 digest.txt /usr/share/wordlists/rockyou.txt
```

Cracked instantly:

```
1484c3a5d65a55d70984b4d10b1884bda8876c1d:CanYouGuessMySecret:sunshine
...
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Time taken: ~2 seconds
```

**Answer:** the secret key is `sunshine` — a top-100 entry in rockyou.txt, which is exactly the point: HMAC is only as strong as its key, and a dictionary-word key falls in milliseconds against a GPU/CPU cracker.

---

## Task 3: Hardcoded AES Key in Client-Side JavaScript

Lab 3 (`http://bcts.thm/labs/lab3/`) is a "Guess the message!" form. Opening dev tools and poking at the request shows the client is AES-encrypting whatever you type before sending it to `process.php`:

```json
{
  "data": "bARZY9n1bapaIKkmm4rvTg==",
  "iv": "rLS5AwaeUEO26hVAEh6qJw=="
}
```

Viewing the page source confirms *why* this is exploitable — the AES key is sitting right there in plaintext JS:

```js
const encryptionKey = CryptoJS.enc.Utf8.parse("1234567890123456"); // 16-byte key
```

Since we know the key, we can encrypt candidate guesses ourselves and just brute-force the server by POSTing encrypted versions of every word in the room's `wordlist.txt` until one comes back "Access granted!" instead of "invalid."

```python
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

url = "http://bcts.thm/labs/lab3/process.php"
encryption_key = b"1234567890123456"

def encrypt_message(message, iv):
    padded = pad(message.encode(), AES.block_size)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(padded)
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

def send_payload(ciphertext, iv):
    payload = {"data": ciphertext, "iv": iv}
    r = requests.post(url, json=payload)
    return r.text

def bruteforce():
    with open("wordlist.txt") as f:
        words = [w.strip() for w in f if w.strip()]
    for word in words:
        iv = get_random_bytes(16)
        ct, iv_b64 = encrypt_message(word, iv)
        resp = send_payload(ct, iv_b64)
        if "Access granted!" in resp:
            print(f"[+] Found: {word}")
            print(resp)
            return

bruteforce()
```

Small annoyance getting to this point: I had a leftover `exploit.py` on disk from something unrelated (`from pymodbus.client import ModbusTcpClient` — not even close to this task), which threw a confusing `ModuleNotFoundError` that had nothing to do with the actual script I meant to run. Rewrote the file cleanly with `cat > exploit.py << 'EOF' ... EOF` instead of trusting whatever was already there, and it ran fine.

```
[+] Found: ankhzljjgu
Access granted! Here's your flag: THM{3nD_2_3nd_is_n0t_c0mpl1c4ted}
```

**Flag:** `THM{3nD_2_3nd_is_n0t_c0mpl1c4ted}`

Fitting flag — "end-to-end encryption" means nothing if the key is exposed to the client.

---

## Task 4: Bit-Flipping Attack on Unauthenticated AES-CBC

Lab 4 (`http://bcts.thm/labs/lab4/`) is a login form that accepts literally any username/password. Looking at the backend logic (given in the task):

```php
$message = "username={$username}";
$role = "0";
$token = encrypt_data($message, $key, $iv);
$token2 = encrypt_data($role, $key, $iv);

setcookie("auth_token", $token, time() + 3600, "/");
setcookie("role", $token2, time() + 3600, "/");
```

So after logging in, the server sets a `role` cookie that's just AES-CBC-encrypted `"0"` — no authentication tag, no integrity check. That's the whole vulnerability: **AES-CBC without a MAC lets an attacker flip bits in the ciphertext and get predictable bit flips in the decrypted plaintext**, because CBC decryption XORs the first block of decrypted plaintext with the IV. Flip a bit in the IV, and the exact same bit flips in the decrypted first block.

`'0'` is `0x30` in ASCII, `'1'` is `0x31` — they differ by exactly one bit (`0x01`). So XOR-ing the first byte of the IV with `0x01` should flip the decrypted role from `0` to `1`.

Logged in with junk creds, grabbed the resulting `role` cookie from Firefox dev tools → Storage → Cookies:

```
b7bdaa5e2a466522e66bc750a7a31cf3d7ba9232d68ed773854055ef01e6f783989943fc60df7f186a899f68ae7a5bed
```

Ran the bit-flip script:

```python
import sys
from binascii import unhexlify, hexlify

original_token = sys.argv[1]
cipher_bytes = bytearray(unhexlify(original_token))

block_size = 16
guest_offset = 0
xor_diff = [0x01]  # '0' -> '1'

for i, diff in enumerate(xor_diff):
    cipher_bytes[guest_offset + i] ^= diff

modified_token = hexlify(cipher_bytes).decode()
print(modified_token)
```

```
[DEBUG] Original IV (First 16 Bytes): b7bdaa5e2a466522e66bc750a7a31cf3
[DEBUG] Modifying byte at offset 0: 0xb7 XOR 0x1
[DEBUG] Modified IV (First 16 Bytes): b6bdaa5e2a466522e66bc750a7a31cf3

Modified Token:
b6bdaa5e2a466522e66bc750a7a31cf3d7ba9232d68ed773854055ef01e6f783989943fc60df7f186a899f68ae7a5bed
```

Pasted that back in as the new value of the `role` cookie in dev tools (double-click the Value cell, overwrite, hit Enter), refreshed the dashboard, and:

```
Welcome, Admin!
Here is your flag: THM{flip_n_flip}
```

**Flag:** `THM{flip_n_flip}`

Note the one subtlety that tripped me up along the way: because this script only manipulates the token locally, running it *doesn't* hit the server or print a flag by itself — I initially confused its debug output with an actual server response and grabbed the wrong flag from an earlier terminal scrollback (the lab3 one) before realizing lab4's flag only shows up after you manually swap the cookie in the browser and reload the page.

---

## Summary of Flags

| Task | Vulnerability | Flag |
|---|---|---|
| 1 | Weak RSA prime generation (factorable via FactorDB) | `THM{Psssss_4nd_Qsssssss}` |
| 2 | Weak HMAC key (dictionary word) | Key: `sunshine` |
| 3 | Hardcoded AES key in client-side JavaScript | `THM{3nD_2_3nd_is_n0t_c0mpl1c4ted}` |
| 4 | Unauthenticated AES-CBC → bit-flipping attack | `THM{flip_n_flip}` |

## Takeaways

- **Randomness matters more than key length.** A "strong" 39-digit RSA prime is worthless if it's predictable or already indexed in a public factorization database.
- **HMAC security = key strength.** A cryptographically sound algorithm (SHA-1 HMAC construction) is trivially broken by a weak, guessable key.
- **Never trust client-side secrets.** Anything shipped in JS to the browser is public, full stop — including "encryption" keys.
- **Encryption ≠ integrity.** AES-CBC without a MAC (or better: an AEAD mode like AES-GCM) lets attackers tamper with ciphertext in predictable, exploitable ways. Always authenticate your ciphertexts.
