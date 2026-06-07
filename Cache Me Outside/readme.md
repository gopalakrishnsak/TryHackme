# TryHackMe — Cache Me Outside
### OSINT Writeup | Difficulty: Medium | Category: OSINT

---

## 🔗 Room Info

| Field | Details |
|---|---|
| **Room Name** | Cache Me Outside |
| **Platform** | TryHackMe |
| **URL** | https://tryhackme.com/room/cachemeoutside |
| **Category** | OSINT |
| **Description** | "Can you find this ex hacker turned outdoorsman?" |

---

## 📖 Background

> *"Years after walking away from the scene, a retired hacker has left pieces of his identity scattered across the open internet. At first glance, it looks like nothing more than a leaked conversation screenshot. But buried in that image is the first thread of a much larger trail. Public profiles, forgotten details, and small mistakes begin to connect into something more deliberate. Someone wanted this person found."*

We are given a single screenshot of a chat conversation and tasked with answering 5 questions about the person involved.

---

## 🗺️ Investigation Map (Summary)

```
Chat Screenshot
    └─► Komoot Profile URL found in chat
            └─► Full Name: "Jim Lee"
            └─► Linked GitHub: github.com/jiml33t
                    └─► Commit Patch → Exposed Email: jimleepro1@gmail.com
                    └─► Email Auto-Reply → Phone: +40 743 321 239
            └─► Linked Instagram/Threads: @jiml33t
                    └─► Post with "irigatii.ro" billboard photo
                    └─► Google Lens → Calea Buziașului, Timișoara, Romania
                            └─► City: Timișoara
                            └─► Komoot Tour (May 7, 2026) → Tram Station: Piața Gheorghe Domășneanu
```

---

## 📋 Challenge Questions & Answers

| # | Question | Answer |
|---|---|---|
| 1 | What is the retired hacker's full name? | `Jim Lee` |
| 2 | What email address did he accidentally expose? | `jimleepro1@gmail.com` |
| 3 | What is his phone number? | `+40 743 321 239` |
| 4 | In which city is he located? | `Timișoara` |
| 5 | Submit the name of the tram station where he got off on the 7th of May, 2026. | `Piața Gheorghe Domășneanu` |

---

## 🔍 Step-by-Step Investigation

---

### Step 1 — Analyzing the Leaked Chat Screenshot

**Starting point:** A Discord-style chat screenshot is provided.

In the conversation, user **"JJ ^_^"** (our target, the retired hacker) shares their Komoot profile with another user (**WKM1337?**):

```
JJ ^_^: i use komoot, it's sick for logging routes and plannew new ones.
         here's my profile if you wanna see my trails or follow me
         https://www.komoot.com/user/5667624959835
```

**Key clue extracted:**
- Komoot profile URL: `https://www.komoot.com/user/5667624959835`
- The target is into hiking and cycling (ex-hacker turned outdoorsman)
- Chat handle: `JJ ^_^`

---

### Step 2 — Investigating the Komoot Profile

**Tool used:** Browser / Komoot.com

Navigate to: `https://www.komoot.com/user/5667624959835`

The Komoot profile reveals:

- **Display Name:** `Jim Lee`
- **Bio:** *"I'm an ex-hacker trying to turn my life around. Lately, I've been focusing on becoming more active, spending more time outdoors, and getting into running. I've also started my own company as part of building a better path for myself."*
- **Website linked in profile:** `github.com/jiml33t`
- **Followers:** 55 | **Following:** 0

> 🎯 **FLAG 1 FOUND → Full Name: `Jim Lee`**

The initials `JJ` from the chat handle likely stand for **Jim (J)** as first name — though the profile confirmed the full real name.

The Komoot profile also links directly to a GitHub account.

---

### Step 3 — GitHub Profile Investigation

**Tool used:** Browser / GitHub / GitHub API

Navigate to: `https://github.com/jiml33t`

**GitHub profile reveals:**
- **Username:** `jiml33t`
- **Status:** 🏃 *"Probably practicing for my upcoming marathon!"*
- **Bio:** *"Currently starting my security consulting firm | Ex-Hacker | Avid Runner"*
- **Company:** `Jim Lee Security Consulting`
- **Public Repos:** 1 (named `jiml33t` — the special profile README repo)

The profile README repo is at: `https://github.com/jiml33t/jiml33t`

It only contains a `README.md` file with minimal visible content.

---

### Step 4 — Finding the Exposed Email via Git Commit Patch

**Tool used:** GitHub Commit API / raw.githubusercontent.com / curl

The profile README repo has only 1 commit. The commit API endpoint reveals:

```
https://api.github.com/repos/jiml33t/jiml33t/commits
```

**API Response (relevant section):**
```json
{
  "commit": {
    "author": {
      "name": "jimleepro1-cell",
      "email": "jimleepro1@gmail.com",
      "date": "2026-04-16T07:27:19Z"
    }
  }
}
```

Alternatively, the commit patch file also exposes this:
```
https://github.com/jiml33t/jiml33t/commit/7b2c8e0a540c36f2e09da5945066020621d6a059.patch
```

The patch file contains in its headers:
```
From: jimleepro1-cell <jimleepro1@gmail.com>
```

This is the classic **Git commit metadata email leak** — when a user commits directly on a device (phone/tablet), the device's Git configuration name (`jimleepro1-cell` suggests a mobile phone) and email are stored in the commit history permanently, even if the GitHub profile hides the email publicly.

> 🎯 **FLAG 2 FOUND → Email: `jimleepro1@gmail.com`**

**Why this works:** Git commit author metadata is immutable and always publicly visible in any public repository's history.

---

### Step 5 — Finding the Phone Number via Email Auto-Reply

**Tool used:** Any email client

**Method:** Send an email to `jimleepro1@gmail.com`

The challenge is set up with a **Gmail auto-reply** (vacation responder) on this account. When you email Jim Lee at `jimleepro1@gmail.com`, you receive an automated response that includes his phone number as part of his contact information — simulating the kind of accidental exposure that happens when someone leaves an OOO/auto-reply with their phone number publicly exposed.

The auto-reply contains:
```
Phone: +40 743 321 239
```

The `+40` country code is **Romania** 🇷🇴 — this already hints at the city being in Romania, which is confirmed in Step 6.

> 🎯 **FLAG 3 FOUND → Phone Number: `+40 743 321 239`**

**OSINT Lesson:** Email auto-replies are often overlooked as a source of leaked PII (Personally Identifiable Information). Many people include their mobile number in vacation responders without considering who might email them.

---

### Step 6 — Finding the City via Instagram/Threads

**Tool used:** Browser / Instagram / Threads / Google Lens

The username `jiml33t` is consistent across platforms. Search for `jiml33t` on:
- **Instagram:** `instagram.com/jiml33t`
- **Threads:** `threads.net/@jiml33t`

Browsing the profile's posts, there is an outdoor/running photo that includes a building in the background. On the building, a **sign reads: `irigatii.ro`** (a Romanian irrigation company).

**Reverse image search with Google Lens** on that post image identifies the exact location:
- **Street:** Calea Buziașului
- **City:** Timișoara, Romania

> 🎯 **FLAG 4 FOUND → City: `Timișoara`**

**OSINT Lesson:** Background details in photos (signs, landmarks, logos) are goldmines for geolocation. Tools like Google Lens, Yandex Reverse Image Search, and GeoGuessr-style analysis can pinpoint locations from seemingly innocuous photos.

---

### Step 7 — Finding the Tram Station from Komoot Activity (May 7, 2026)

**Tool used:** Browser / Komoot.com / Google Maps

Return to Jim Lee's Komoot profile:
`https://www.komoot.com/user/5667624959835`

In his **activity feed**, find the recorded tour from **May 7, 2026**. Komoot shows the GPS-tracked route on a map. The route ends (or a key waypoint is) near:
- **Calea Buziașului, Timișoara**
- Near the `irigatii.ro` billboard location

Cross-reference the end point on **Google Maps** to find the nearest tram stop.

**Alternative method (for verification):**
```
Search: "tram station near the IRIGATII.RO billboard on Calea Buziașului in Timișoara, Romania"
```

The tram stop at this location on Calea Buziașului in Timișoara is:

**`Piața Gheorghe Domășneanu`**

> 🎯 **FLAG 5 FOUND → Tram Station: `Piața Gheorghe Domășneanu`**

**OSINT Lesson:** Fitness apps like Komoot and Strava record GPS-precise routes with timestamps. These are incredibly powerful for reconstructing a person's movements on any given date — a significant privacy risk for anyone who makes their activities public.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| Browser | Profile viewing (Komoot, GitHub, Instagram) |
| GitHub API | `api.github.com/repos/jiml33t/jiml33t/commits` — extract email from commit |
| Git commit patch | `*.patch` URL format to see raw commit headers |
| Email client | Send email to `jimleepro1@gmail.com` to trigger auto-reply |
| Google Lens | Reverse image search to geolocate the Instagram post |
| Google Maps | Identify tram stop near the billboard location |
| Komoot | View GPS-tracked tour history for May 7, 2026 |

---

## 🧠 Key OSINT Techniques Demonstrated

### 1. Username Pivoting (OSINT Pivot)
The same username `jiml33t` was used across:
- Komoot
- GitHub
- Instagram
- Threads

Starting from one platform and pivoting to others using the same handle is a fundamental OSINT technique.

### 2. Git Commit Email Exposure
Every Git commit stores the author's email in its metadata. This is accessible via:
- `GET /repos/{owner}/{repo}/commits` (GitHub API)
- `https://github.com/{owner}/{repo}/commit/{sha}.patch`
- `git log --pretty=format:"%an <%ae>"` locally

This email is **permanently stored** in the commit history and cannot be redacted without rewriting history.

### 3. Email Auto-Reply as PII Leak
Sending a test email to a target's known email address can trigger auto-replies that contain:
- Phone numbers
- Alternative contact methods
- Location/office info
- Working hours (giving timezone/location clues)

### 4. Image GEOINT (Geospatial Intelligence)
Background elements in social media photos reveal location:
- **Signage** (company names, street names)
- **Architecture** (distinctive buildings)
- **Vegetation** (local plant species)
- **Vehicles** (license plates, unique models)

Tools: Google Lens, Yandex Images, TinEye, What3Words.

### 5. Fitness App GPS Data as Surveillance
Public fitness activities on Komoot, Strava, etc. expose:
- **Exact GPS routes** with timestamps
- **Home/work locations** (start/end points of regular runs)
- **Daily/weekly patterns** (when and where someone moves)
- **Specific dates** (e.g., exactly where someone was on May 7, 2026)

## 📁 Flag Summary

```
Q1 — Full Name:      Jim Lee
Q2 — Email:          jimleepro1@gmail.com
Q3 — Phone:          +40 743 321 239
Q4 — City:           Timișoara
Q5 — Tram Station:   Piața Gheorghe Domășneanu
```
