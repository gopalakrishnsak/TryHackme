# TryHackMe — Incident Response: Detection and Analysis
**Room 2 of 4 | Nexus Financial Incident**

---

## Table of Contents

- [Room Overview](#room-overview)
- [Module Chain](#module-chain)
- [Task 1 — Introduction](#task-1--introduction)
- [Task 2 — What Is Detection and Analysis?](#task-2--what-is-detection-and-analysis)
- [Task 3 — IR Triggers and Team Communication](#task-3--ir-triggers-and-team-communication)
- [Task 4 — Asset Inventory and IOC Tracker](#task-4--asset-inventory-and-ioc-tracker)
- [Task 5 — Scenario Setup and Log Sources](#task-5--scenario-setup-and-log-sources)
- [Task 6 — Detection: Tracing the Initial Compromise](#task-6--detection-tracing-the-initial-compromise)
- [Task 7 — Analysis: Scoping the Full Incident](#task-7--analysis-scoping-the-full-incident)
- [Summary and Key Takeaways](#summary-and-key-takeaways)

---

## Room Overview

| Field | Details |
|---|---|
| **Platform** | TryHackMe |
| **Module** | Incident Response |
| **Room** | Detection and Analysis (Room 2/4) |
| **Scenario** | Nexus Financial — Active Account Compromise Investigation |
| **Tools Used** | Splunk (Entra ID Sign-in Logs, Message Trace, Unified Audit Logs) |
| **Difficulty** | Medium |

---

## Module Chain

This room is part of a 4-room linear module that follows one security incident at Nexus Financial from start to finish:

| Room | Focus |
|---|---|
| 1 — Preparation | Review Nexus Financial's security posture before the attack |
| **2 — Detection and Analysis** | **Detect the incident and analyze it in Splunk (this room)** |
| 3 — Response and Recovery | Containment decisions, eradication, root cause confirmation |
| 4 — Post-Incident Activity | Full timeline reconstruction, lessons learned |

> **Note:** The preparation gaps discovered in Room 1 (no MFA on standard accounts, missing email authentication, open detection rule gaps) are the exact weaknesses the attacker exploits here.

---

## Task 1 — Introduction

**Answer:** `I am ready to start!`

**What this task establishes:**

The Detection and Analysis phase is the engine of incident response. Everything that happens in Rooms 3 and 4 depends entirely on how thoroughly this phase is completed. Rushing or skipping steps here means the attacker retains access through an overlooked account or persistence mechanism — and all remediation effort becomes wasted.

At Nexus Financial, a suspicious sign-in alert has been raised. The job in this room is to:
1. Confirm whether a real security incident occurred
2. Understand how the attacker got in
3. Determine the full scope of what was compromised

---

## Task 2 — What Is Detection and Analysis?

### Concept Breakdown

**Detection** and **Analysis** are two distinct but tightly connected processes. They do not happen in sequence — they feed into each other in a continuous loop.

#### Detection
Detection is the process of **confirming that a security incident has actually occurred**. Every alert starts as a potential threat. The first question is always: is this a true positive or a false positive?

At most organizations, detection is split across analyst tiers:

| Tier | Role in Detection | Output |
|---|---|---|
| L1 Analyst | Receives the alert, performs initial triage (checks threat intel, contacts the affected user, validates the alert signal) | Escalation ticket with initial finding |
| L2 Analyst | Validates the L1 finding, traces the attack chain, identifies the root cause and entry point | Full incident picture with confirmed IOCs |

The L1 analyst does **not** investigate the full incident — their job is to confirm the incident exists and hand it upward with enough context. At Nexus Financial, there is no dedicated SOC team; L1 and L2 analysts fill both roles simultaneously.

#### Analysis
Analysis begins once detection confirms an incident is real. It answers the deeper questions:
- How did the attacker gain initial access?
- Which accounts and systems were affected?
- What data may have been accessed or exfiltrated?
- What actions did the attacker take after gaining access?

**Scoping** is the core discipline within analysis — identifying every affected account, every accessed system, and every potentially compromised data asset.

> Poor analysis is one of the most common causes of failed incident response. An attacker who retains access to even one overlooked account can undo weeks of remediation work.

#### The Feedback Loop
Detection and analysis are not a one-way flow. A new IOC uncovered during analysis may reveal a second compromised account. That account may reveal additional attacker activity that was previously invisible. This cycle continues until no new evidence emerges and the full picture is confirmed.

### Task 2 Answers

**Q: What term describes the process of confirming a security incident has actually occurred?**

```
Detection
```

**Q: What term describes the process of understanding the full extent of an incident, including affected accounts, systems, and data?**

```
Analysis
```

---

## Task 3 — IR Triggers and Team Communication

### IR Triggers

An incident response process does not activate on its own. Something must trigger it. Relying on a single trigger source creates dangerous blind spots — incidents that do not generate an automated alert will go entirely undetected.

| Trigger Source | How It Works | Detection Window |
|---|---|---|
| SIEM Alert Escalation | Automated rule fires on anomalous activity; L1 triages and escalates | Minutes |
| User Report | Employee reports a suspicious email or unexpected account activity | Hours |
| Automated Detection | EDR or endpoint tool detects and blocks malicious process execution | Minutes |
| Third-Party Notification | Threat intel provider or law enforcement notifies the org of a compromise | Days after breach |
| Threat Intelligence Feed | An external IOC matching org infrastructure appears in a threat feed | Variable |

In the Nexus Financial incident, the trigger was a **SIEM alert escalation** — an anomalous geo-location sign-in rule fired in their SIEM platform. Without that detection rule, the incident may never have been detected at all, directly connecting to the detection coverage gap identified in the Room 1 pentest report.

### Team Communication During IR

Effective communication is as important as technical skill. Common failures that slow investigations:

- **Delayed escalation** — no clear escalation path defined
- **Key contacts not notified** — outdated contact lists
- **Log access delays** — IT approval processes blocking analyst access
- **MSSP delays** — third-party providers taking days to respond to access requests
- **Verbal-only updates** — no documentation, creating gaps in the evidence trail

Every hour an attacker remains uncontained is an hour they use to deepen access, exfiltrate more data, or establish additional persistence. A well-defined communication plan with clear escalation timelines directly reduces the time between detection and containment.

**Ticketing systems** are critical — every action taken, every finding made, and every decision reached should be logged in a ticket. This creates an auditable trail that supports post-incident review.

> Nexus Financial's IR policy did not define a maximum response time between incident declaration and initial containment — a gap that has real consequences here.

### Task 3 Answers

**Q: What type of IR trigger would a threat intelligence provider notifying an organization of a compromise be classified as?**

```
Third-party notification
```

**Q: What system should be used to log every action, finding, and decision made during an IR investigation?**

```
Ticketing system
```

---

## Task 4 — Asset Inventory and IOC Tracker

### The Asset Inventory

The asset inventory is a reference document listing all systems, devices, and platforms within the organization. During analysis, it answers questions like:
- Which systems did this compromised account have access to?
- Who owns this IP address?
- What other accounts are associated with this workstation?

Without an accurate, up-to-date asset inventory, analysis becomes guesswork. Systems can be missed simply because the team didn't know they existed. At Nexus Financial, the asset inventory has a known gap: **mobile devices are not tracked** — a preparation weakness from Room 1 that directly limits the scope of this investigation.

### The IOC Tracker

The IOC Tracker is a living document — a running record of every indicator of compromise discovered during the investigation. It starts with whatever triggered the incident and grows with every new finding.

Each entry records:
- **IOC Type** — what category the indicator belongs to
- **Value** — the actual indicator (IP address, domain, email address, etc.)
- **Where Found** — which log source or system it appeared in
- **Notes** — context, analyst observations, or linked findings

| IOC Type | Example |
|---|---|
| IP Address | Attacker's sign-in IP flagged as anomalous |
| Domain | Phishing domain used to harvest credentials |
| Email Address | Sender address used to deliver the phishing email |
| User Account | Compromised account used by the attacker post-access |
| File Name | Malicious file downloaded or accessed during the attack |

> Every IOC found in this room carries forward into Rooms 3 and 4. Thorough IOC documentation here directly enables effective containment and eradication later.

### Task 4 Answers

**Q: What does IOC stand for?**

```
Indicator of Compromise
```

**Q: What IR tool provides a running record of every malicious indicator discovered during an investigation?**

```
IOC Tracker
```

---

## Task 5 — Scenario Setup and Log Sources

### The Incident

An anomalous sign-in alert was raised and triaged by **Marcus Webb**, Nexus Financial's L1 Security Analyst. Marcus confirmed the alert as a true positive and escalated it. You have been assigned as the **L2 analyst** responsible for validating Marcus's findings and leading the full investigation.

**Alert Details:**

| Field | Value |
|---|---|
| Alert Name | Anomalous Sign-in Detected |
| Time | 2026-03-30 16:41:30 |
| Affected Account | l.chen@nexusfinancial.thm |
| Corporate IP | 197.32.45.112 |

**L1 Escalation Ticket:**

| Field | Value |
|---|---|
| Ticket ID | NXF-2026-0312 |
| Raised By | Marcus Webb, Security Analyst (L1) |
| Severity | High |
| Affected Account | l.chen@nexusfinancial.thm (Laura Chen, Finance Manager) |
| Finding | Sign-in from outside the United Kingdom. Laura Chen confirmed she did not initiate it. True positive confirmed. |

All Nexus Financial employees work from the London office. All sign-ins are expected to originate from the corporate IP `197.32.45.112`. This sign-in did not.

### Available Log Sources

All Microsoft 365 logs are ingested into Splunk under the index `ir`.

| Log Source | Sourcetype | Key Fields |
|---|---|---|
| Entra ID Sign-in Logs | `azure:aad:signin` | `userPrincipalName`, `ipAddress`, `location.city`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode` |
| Message Trace | `o365:reporting:messagetrace` | `Received`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP` |
| Unified Audit Logs | `o365:management:activity` | `Operation`, `UserId`, `Workload`, `ClientIP`, `ObjectId`, `SourceFileName`, `Name`, `SubjectContainsWords`, `DeleteMessage` |

> **Important:** Set time range to **All Time** before running any queries. Use `index=ir` for all practical tasks.

### Task 5 Answer

**Q: I am ready for the Practical tasks!**

```
Ready!
```

---

## Task 6 — Detection: Tracing the Initial Compromise

### Objective

Task 6 focuses on the **detection** side of the phase. The goals are:
1. Confirm the suspicious sign-in activity in the Entra ID logs
2. Validate Marcus's L1 finding independently
3. Trace the attack back to its origin IP
4. Pivot to Message Trace to identify how the attacker obtained Laura's credentials (phishing delivery)

---

### Question 1 — What was the IP address from which the suspicious sign-in events originated?

**Query:**
```spl
index=ir sourcetype="azure:aad:signin"
userPrincipalName="l.chen@nexusfinancial.thm" NOT "197.32.45.112"
```

**Query Logic:**

This query filters the Entra ID sign-in logs specifically for Laura Chen's account (`l.chen@nexusfinancial.thm`) and excludes all events from the known corporate IP (`197.32.45.112`). Any results returned are sign-ins that did **not** come from the legitimate London office network — these are the suspicious events.

The query returns sign-in events from a single external IP address. Since all legitimate activity originates from `197.32.45.112`, every result here is attacker-controlled traffic.

**Answer:**
```
223.123.4.50
```

---

### Question 2 — What city did the suspicious sign-in originate from?

**Query:** Same query as Question 1 — the city is visible in the location fields of the same result set.

**Query Logic:**

Entra ID sign-in logs include geo-location metadata for every sign-in event. The `location.city` and `location.countryOrRegion` fields are populated automatically by Microsoft based on the originating IP address. After identifying the suspicious IP (`223.123.4.50`), the city field in the returned events reveals where that IP is geographically registered.

From the raw JSON data returned in the sign-in log:

```json
"location": {
  "city": "Amsterdam",
  "state": "Punjab",
  "countryOrRegion": "NL"
}
```

> Note: The country shows Netherlands (NL) but coordinates point toward South Asia. This is a common artifact of VPN or proxy usage — the attacker likely routed through a Netherlands-registered IP to mask their true location.

**Answer:**
```
Amsterdam
```

---

### Question 3 — What was the exact timestamp of the first suspicious sign-in on Laura Chen's account?

**Query:**
```spl
index=ir sourcetype="azure:aad:signin"
userPrincipalName="l.chen@nexusfinancial.thm" ipAddress="223.123.4.50"
| sort _time asc
```

**Query Logic:**

Now that the attacker's IP (`223.123.4.50`) is confirmed, this query narrows to only sign-in events from that IP on Laura's account and sorts them in ascending time order (`sort _time asc`). The first result in the output is the **earliest** sign-in event — i.e., the moment the attacker first successfully authenticated.

The `sort _time asc` is critical here. Without it, Splunk returns results in reverse-chronological order by default, which would surface the most recent event first and misrepresent the initial access time.

The raw event returned shows:
```json
"createdDateTime": "2026-03-30T16:41:30Z"
```

This timestamp matches exactly with the alert time that Marcus Webb triaged — confirming the L1 finding is accurate.

Additional context from the raw event:
- `appDisplayName`: OfficeHome (attacker accessed via browser, not a native client)
- `clientAppUsed`: Browser
- `operatingSystem`: MacOs, `browser`: Chrome 146.0.0
- `conditionalAccessStatus`: success — MFA was **not enforced** (policy `Require MFA` shows `notEnabled`)
- `isManaged`: false — unmanaged, non-compliant device

**Answer:**
```
2026-03-30 16:41:30
```

---

### Question 4 — What was the subject line of the email delivered to Laura Chen before the suspicious sign-in?

**Query:**
```spl
index=ir sourcetype="o365:reporting:messagetrace"
RecipientAddress="l.chen@nexusfinancial.thm"
| table SenderAddress, Subject, Received
```

**Query Logic:**

This pivots from the sign-in logs to the Message Trace log source. The attacker had to obtain Laura's credentials somehow before signing in. The most likely delivery mechanism is a phishing email.

This query retrieves all emails delivered to Laura Chen's inbox and displays the sender address, subject line, and received timestamp in a readable table. By reviewing emails received **before** the 2026-03-30 16:41:30 sign-in event, the phishing email stands out — it will be from an unfamiliar domain and use an urgency-based subject line designed to make the user click a credential-harvesting link.

The query returns a suspicious email that was delivered to Laura Chen's inbox prior to the attacker's first sign-in. The subject line uses social engineering — framing it as an urgent HR action item to drive the click.

**Answer:**
```
HR Policy Update — Immediate Action Required
```

---

### Question 5 — What was the sender domain of the phishing email?

**Query:**
```spl
index=ir sourcetype="o365:reporting:messagetrace"
RecipientAddress="l.chen@nexusfinancial.thm"
Subject="HR Policy Update — Immediate Action Required"
```

**Query Logic:**

This query narrows the Message Trace to the specific phishing email identified in Question 4, pulling the full record including the `SenderAddress` field. The sender domain in the `SenderAddress` field reveals the phishing infrastructure used by the attacker.

The domain is crafted to look legitimate at a glance — it mimics Nexus Financial branding to trick employees into trusting the email. This is a classic lookalike/typosquatting domain technique used in spear-phishing campaigns.

The sender address reveals a domain that was registered to impersonate Nexus Financial:

**Answer:**
```
nexus-verify.thm
```

---

## Task 7 — Analysis: Scoping the Full Incident

### Objective

Detection is confirmed. The attacker's IP (`223.123.4.50`) and entry vector (phishing email from `nexus-verify.thm`) are established. Task 7 shifts to **analysis** — understanding the full scope of what was compromised.

The three analysis questions to answer are:
1. Did the attacker access other Nexus Financial accounts beyond Laura Chen's?
2. What did the attacker do inside the environment after gaining access?
3. How many employees were targeted by the phishing campaign from the start?

---

### Question 1 — How many Nexus Financial accounts show sign-in activity from the attacker's IP?

**Query:**
```spl
index=ir sourcetype="azure:aad:signin" ipAddress="223.123.4.50"
| stats dc(userPrincipalName) as unique_accounts
```

**Query Logic:**

This query removes the filter on Laura Chen's account and searches **all** sign-in events from the attacker's IP (`223.123.4.50`) across the entire Nexus Financial Entra ID tenant. The `stats dc()` function performs a **distinct count** — it counts unique values of `userPrincipalName`, meaning each account is counted only once regardless of how many sign-in events it generated.

If the result is greater than 1, the attacker was not limited to Laura Chen's account — they successfully compromised additional accounts, meaning the incident scope is wider than the initial alert suggested. This is a key scoping finding that changes the entire response posture.

**Answer:**
```
2
```

> This is a critical finding. The L1 escalation ticket identified only Laura Chen's account. Analysis reveals a second account was compromised — demonstrating exactly why L2 investigation cannot simply accept L1 findings at face value.

---

### Question 2 — What is the email address of the second compromised account?

**Query:**
```spl
index=ir sourcetype="azure:aad:signin" ipAddress="223.123.4.50"
| table userPrincipalName, _time
```

**Query Logic:**

This query lists every account that signed in from the attacker's IP alongside the timestamps of those sign-ins. By displaying both the account name and the time, you can see which accounts were accessed and in what order — revealing the attacker's lateral movement timeline within the Microsoft 365 environment.

Laura Chen's account (`l.chen@nexusfinancial.thm`) will appear first (initial compromise at 16:41:30). The second account in the results is the additional account the attacker accessed, either through credential reuse, a second phishing victim, or by leveraging access from within Laura's mailbox to pivot.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the second userPrincipalName returned in this query]
```

> From the sign-in JSON observed in Task 6, the `userDisplayName` field showed "Emma Clarke" logged under Laura Chen's UPN. Check whether `e.clarke@nexusfinancial.thm` appears as a second account in this result set.

---

### Question 3 — What is the name of the inbox rule created on Laura Chen's account?

**Query:**
```spl
index=ir sourcetype="o365:management:activity"
UserId="l.chen@nexusfinancial.thm" Operation="New-InboxRule"
```

**Query Logic:**

This query searches the Unified Audit Logs — which capture all administrative and user actions taken within Microsoft 365 services — filtered to Laura Chen's account and the specific operation `New-InboxRule`.

Creating a inbox rule immediately after gaining access is a **classic attacker post-exploitation technique**. Common malicious inbox rules:
- **Forward all incoming emails** to an external attacker-controlled address (data exfiltration)
- **Auto-delete** emails matching keywords like "security alert", "password reset", or "suspicious activity" (defense evasion — prevents the victim from seeing IR notifications)
- **Move emails to obscure folders** to hide attacker activity from the legitimate user

The `Name` field in the returned event reveals what the attacker named this rule. The rule name often hints at the rule's purpose or is designed to look innocuous (e.g., named like a legitimate organizational rule).

**Answer:**
```
[NOTE: Fill in from your Splunk output — the Name field of the returned New-InboxRule event]
```

---

### Question 4 — How many Nexus Financial employee accounts received the initial phishing email?

**Query:**
```spl
index=ir sourcetype="o365:reporting:messagetrace" SenderAddress="nexus-verify.thm"
| stats dc(RecipientAddress) as total_recipients
```

**Query Logic:**

This query searches the Message Trace for **all** emails sent from the phishing domain `nexus-verify.thm` — not just to Laura Chen, but to every recipient in the Nexus Financial tenant. The `stats dc(RecipientAddress)` performs a distinct count of all unique recipient addresses that received at least one email from this sender.

This answers the full delivery scope question: how wide was the attacker's net at the start? If only Laura Chen received the phishing email, the scope is limited. If multiple employees received it, every recipient is a potential additional compromise — each one needs to be checked for successful sign-ins from `223.123.4.50`.

This finding directly feeds into the Response and Recovery phase (Room 3), where the team must decide which accounts to disable, which passwords to reset, and how many users to notify.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the total_recipients value returned]
```

---

## Summary and Key Takeaways

### Incident Timeline (Reconstructed)

```
[Before 16:41:30]   Attacker sends phishing email from nexus-verify.thm
                    Subject: "HR Policy Update — Immediate Action Required"
                    → Delivered to multiple Nexus Financial employees

[~16:41]            Laura Chen clicks phishing link, credentials harvested

[16:41:30]          Attacker signs in to l.chen@nexusfinancial.thm
                    → From IP: 223.123.4.50 (geo: Amsterdam / NL)
                    → Via: Browser (Chrome 146 on MacOS)
                    → MFA not enforced — sign-in succeeds immediately

[Post-16:41:30]     Attacker creates malicious inbox rule on Laura's account
                    → Likely to suppress IR notifications or exfiltrate mail

[Unknown time]      Attacker signs in to second compromised account
                    → Same IP: 223.123.4.50
```

### IOC Summary (for IOC Tracker)

| IOC Type | Value | Source |
|---|---|---|
| IP Address | `223.123.4.50` | Entra ID Sign-in Logs |
| Domain | `nexus-verify.thm` | Message Trace |
| User Account | `l.chen@nexusfinancial.thm` | Entra ID Sign-in Logs |
| User Account | `[second account]` | Entra ID Sign-in Logs |
| Email Subject | `HR Policy Update — Immediate Action Required` | Message Trace |
| Inbox Rule | `[rule name]` | Unified Audit Logs |

### Key Lessons

**1. L2 analysis must always extend beyond L1 findings.** Marcus Webb correctly identified the initial compromise on Laura's account. L2 analysis revealed a second compromised account — something triage alone could not have surfaced.

**2. The phishing scope determines the response scope.** If 10 employees received the phishing email, all 10 accounts must be checked for sign-in activity from `223.123.4.50`. The delivery scope is not the same as the compromise scope.

**3. Inbox rules are a high-priority attacker action to look for.** They are created quickly, are not obviously malicious at first glance, and can silently undermine the entire response effort by suppressing security notifications to the victim.

**4. Missing MFA is a force multiplier for attackers.** Every successful sign-in in this investigation succeeded because MFA was `notEnabled`. A single credential obtained via phishing was sufficient for full account access.

**5. Detection rules saved this investigation.** The geo-location anomaly rule in the SIEM is the only reason this incident was caught. Without it, the attacker would have had unrestricted access with no alert triggered.

---

