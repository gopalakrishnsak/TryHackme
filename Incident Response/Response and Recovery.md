# TryHackMe — Incident Response: Response and Recovery
**Room 3 of 4 | Nexus Financial Incident**

---

## Table of Contents

- [Room Overview](#room-overview)
- [Module Chain](#module-chain)
- [Task 1 — Introduction](#task-1--introduction)
- [Task 2 — The Response Framework](#task-2--the-response-framework)
- [Task 3 — Containment](#task-3--containment)
- [Task 4 — Eradication and Recovery](#task-4--eradication-and-recovery)
- [Task 5 — Scenario Setup and Log Sources](#task-5--scenario-setup-and-log-sources)
- [Task 6 — Post-Compromise Activity and Containment Decisions](#task-6--post-compromise-activity-and-containment-decisions)
- [Task 7 — Eradication Findings and Recovery Planning](#task-7--eradication-findings-and-recovery-planning)
- [Summary and Key Takeaways](#summary-and-key-takeaways)

---

## Room Overview

| Field | Details |
|---|---|
| **Platform** | TryHackMe |
| **Module** | Incident Response |
| **Room** | Response and Recovery (Room 3/4) |
| **Scenario** | Nexus Financial — Active Account Compromise, Post-Compromise Investigation |
| **Framework** | NIST SP 800-61r2 |
| **Tools Used** | Splunk (Entra ID Sign-in Logs, Message Trace, Unified Audit Logs) |
| **Difficulty** | Medium |

---

## Module Chain

| Room | Focus |
|---|---|
| 1 — Preparation | Review Nexus Financial's security posture before the attack |
| 2 — Detection and Analysis | Detect the incident and analyze it in Splunk |
| **3 — Response and Recovery** | **Make containment decisions, confirm the attacker is gone, identify root causes (this room)** |
| 4 — Post-Incident Activity | Reconstruct the full attack timeline and revisit what went wrong |

> **Where we are:** Two accounts were confirmed compromised in Room 2. The attacker's IP (`223.123.4.50`), phishing domain (`nexus-verify.thm`), and initial inbox rule on Laura Chen's account were identified. This room picks up exactly there — the IR team is preparing containment actions and needs the full post-compromise picture before executing them.

---

## Task 1 — Introduction

**Answer:** `I am ready to start!`

**Context:**

The attacker is still active inside the Nexus Financial Microsoft 365 environment. Everything discovered in Room 2 (Detection and Analysis) was observation. This room is where the IR team transitions from understanding the incident to **actively resolving it**.

This maps to the Containment, Eradication, and Recovery phase in NIST SP 800-61r2. The learning objectives for this room:
- Understand the correct order of Containment → Eradication → Recovery and why order matters
- Learn the two containment strategies and when to apply each
- Understand how MITRE ATT&CK maps to containment decisions
- Use Splunk to analyze post-compromise activity and determine what needs to be contained and eradicated

---

## Task 2 — The Response Framework

### NIST SP 800-61r2: Three Tightly Coupled Activities

Once an incident is confirmed, the IR team stops observing and starts acting. According to NIST SP 800-61r2, the response happens through three activities that must be executed in a **strict sequence**:

| Activity | Goal | Key Question |
|---|---|---|
| **Containment** | Stop the damage from spreading any further | What do we need to cut off right now? |
| **Eradication** | Remove all attacker presence from the environment | Is the attacker completely gone? |
| **Recovery** | Restore normal operations safely | Can we bring things back online without risk? |

**Order is not optional.** You cannot eradicate without first containing. You cannot recover without first eradicating. Rushing any step undermines all subsequent steps and risks giving the attacker a path back in.

### The Whack-a-Mole Problem

The most common IR failure pattern: the team starts eradication before containment is fully complete, or begins recovery before eradication is confirmed. The attacker still has a foothold, regains access, and the team is back to square one.

This cycle repeats because:
- Scope was not fully established before clean-up began
- A secondary compromised account was missed during detection
- A persistence mechanism was overlooked during eradication

Proper, thorough analysis in Room 2 exists precisely to prevent this. The quality of the scope confirmed in Room 2 directly determines how complete and permanent the clean-up can be in this room.

### Environment Matters

The specific actions taken during each activity depend entirely on the environment in question:

| Environment | Containment Approach |
|---|---|
| On-premises Active Directory | Disable AD accounts, isolate systems at the network layer, segment VLANs |
| Endpoint compromise | Isolate the machine from the network, kill malicious processes, pull forensic image |
| Cloud identity (Microsoft 365) | Disable Entra ID accounts, revoke active sessions, enforce MFA |

This incident is a **pure cloud identity compromise** — the attacker operated entirely within Microsoft 365. No physical machines need to be unplugged. No network segments need to be isolated. All containment, eradication, and recovery actions target the identity and access layer within Microsoft 365 and Entra ID.

**Playbooks** encode this environment-specific knowledge. Rather than rebuilding the response logic from scratch during a live incident, the team follows a pre-defined, tested playbook built for exactly this scenario. Well-maintained playbooks mean faster, more consistent responses that are not dependent on any single analyst's memory under pressure.

### Task 2 Answer

**Q: According to NIST SP 800-61r2, what is the first activity that must happen before eradication can begin?**

```
Containment
```

---

## Task 3 — Containment

### What Containment Actually Means

Containment does **not** mean the attacker is gone. It means their ability to cause further harm has been **limited** while the team works on removing them completely.

Think of it as closing the doors before a fire spreads. The fire is still burning — but it is no longer spreading to adjacent rooms. In IR terms, the attacker may still have a foothold, but their lateral movement and damage radius has been stopped.

Every minute an attacker remains uncontained is a minute they can:
- Access more data and expand exfiltration
- Compromise additional accounts via lateral movement
- Establish additional persistence mechanisms that will survive the eventual clean-up

### Containment Strategies

| | Full Isolation | Controlled Isolation |
|---|---|---|
| **What it is** | Immediately disable accounts, terminate all active sessions, revoke access completely | Monitor the attacker's activity closely while restricting what they can reach — do not cut them off yet |
| **Speed** | Immediate | Delayed while monitoring |
| **Risk of tipping off attacker** | High — a sophisticated attacker who suddenly loses access knows they have been detected and may activate backup persistence before the team finds it | Low — attacker believes they are still operating freely |
| **Intelligence gathered** | Limited — you lose visibility the moment you cut them off | High — you observe exactly what they are targeting and what other footholds they may have |
| **Best used when** | Full scope is well understood; the attacker must be stopped immediately | Scope is still being determined; more intelligence is needed before acting |

> In the Nexus Financial incident, the team chose to gather more intelligence first (this room's investigation) before executing containment. This is consistent with controlled isolation — understand the full picture, then cut the attacker off cleanly.

### ATT&CK Mapping to Containment Decisions

MITRE ATT&CK maps real attacker behaviors to named techniques and procedures. In the Nexus Financial incident, the following techniques were identified during Room 2 and each carries a specific containment response:

| Technique ID | Technique Name | What the Attacker Did | Containment Response |
|---|---|---|---|
| T1566 | Phishing | Sent phishing emails from `nexus-verify.thm` to harvest credentials | Block the phishing domain at the email gateway |
| T1078 | Valid Accounts | Used stolen credentials to sign in as Laura Chen and a second account | Disable accounts, revoke all active sessions, reset passwords |
| T1564.008 | Email Hiding Rules | Created inbox rules on compromised accounts to suppress security alert emails | Remove the malicious inbox rules immediately |
| T1213 | Data from Information Repositories | Accessed SharePoint to download sensitive files | Review and restrict SharePoint permissions; revoke any external sharing links |

This table is the decision framework for Task 6. Every artifact found in the logs maps to one of these techniques and requires the corresponding containment action.

### Task 3 Answer

**Q: What containment strategy involves monitoring the attacker's activity rather than cutting off their access immediately?**

```
Controlled isolation
```

---

## Task 4 — Eradication and Recovery

### Eradication

Eradication is the process of removing **every trace** of the attacker from the environment. Containment stopped them from causing more damage — eradication makes them completely gone.

The attacker may have left behind:
- Malicious inbox rules on compromised mailboxes (suppress security alerts, auto-forward emails)
- OAuth application permissions granted during the compromise (persistent access path that survives a password reset)
- Forwarding rules or delegates added to affected mailboxes
- External sharing links on SharePoint documents (data remains accessible even after accounts are disabled)
- Additional accounts accessed from the attacker's IP that were not yet identified

**The most important eradication principle:** Do not start eradication until the full scope is confirmed. Cleaning up a known compromise while missing a secondary one gives the attacker a path back in. This directly links back to Room 2 — thorough scoping during Detection and Analysis is what makes complete eradication possible here.

Eradication checklist for a Microsoft 365 identity compromise:

- [ ] Enforce MFA on all compromised accounts before re-enabling them
- [ ] Remove all malicious inbox rules from affected mailboxes
- [ ] Review and revoke any OAuth application permissions granted during the compromise
- [ ] Confirm no additional accounts were accessed from the attacker's IP
- [ ] Revoke all external SharePoint sharing links created by the attacker
- [ ] Confirm no forwarding rules or delegates were added to affected mailboxes

### Recovery

Recovery is the process of safely returning to normal operations. It is not simply re-enabling accounts and declaring the incident closed. Before any affected account is brought back online, the team must confirm:
1. Eradication is fully complete
2. The controls that failed during the incident have been addressed

Recovery also means fixing the root causes. In a Microsoft 365 identity incident, root causes typically fall into:
- **Identity controls** that were missing or misconfigured (no MFA enforcement, no Conditional Access)
- **Email security controls** that allowed the phishing email to be delivered (no SPF/DKIM/DMARC, no phishing domain blocking)

Recovery actions are planned across three timeframes:

| Timeframe | Focus | Example Actions |
|---|---|---|
| **Near term** | Immediate actions before accounts can be re-enabled | Enforce MFA, reset passwords, remove malicious inbox rules, revoke external SharePoint shares |
| **Mid term** | Controls that address the root causes of the incident | Configure SPF, DKIM, DMARC; implement Conditional Access policies; review SharePoint permissions |
| **Long term** | Improvements to the overall security posture | Expand detection rule coverage, run phishing simulations, update IR policy with escalation timelines |

### Task 4 Answer

**Q: What timeframe should the most critical recovery actions fall under?**

```
Near term
```

---

## Task 5 — Scenario Setup and Log Sources

### Incident Summary (Carried Forward from Room 2)

| Field | Value |
|---|---|
| Alert Name | Anomalous Sign-in Detected |
| Time | 2026-03-30 16:41:30 |
| Affected Account | l.chen@nexusfinancial.thm (Laura Chen, Finance Manager) |
| Corporate IP | 197.32.45.112 |

### IOC Tracker (Confirmed in Room 2)

| Type | Value |
|---|---|
| Attacker IP Address | `223.123.4.50` |
| Phishing Sender Domain | `nexus-verify.thm` |
| Compromised Account 1 | `l.chen@nexusfinancial.thm` |
| Compromised Account 2 | `[confirmed in Room 2 — second account from Entra ID sign-in logs]` |
| Malicious Inbox Rule | `[confirmed in Room 2 — from Unified Audit Logs]` |

### Available Log Sources

All Microsoft 365 logs are ingested into Splunk under `index=ir`. Set the time range to **All Time** before running any queries.

| Log Source | Sourcetype | Key Fields |
|---|---|---|
| Entra ID Sign-in Logs | `azure:aad:signin` | `userPrincipalName`, `ipAddress`, `location.city`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode`, `riskLevelDuringSignIn` |
| Message Trace | `o365:reporting:messagetrace` | `Received`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP` |
| Unified Audit Logs | `o365:management:activity` | `Operation`, `UserId`, `Workload`, `ClientIP`, `ObjectId`, `SourceFileName`, `Name`, `SubjectContainsWords`, `DeleteMessage` |

### Task 5 Answer

**Q: I am ready for the Practical tasks!**

```
Ready!
```

---

## Task 6 — Post-Compromise Activity and Containment Decisions

### Objective

Before executing any containment action, the IR team needs a complete picture of **what the attacker did inside the environment after gaining access**. This prevents containment from destroying evidence and ensures nothing is missed during eradication.

The investigation focuses on the Unified Audit Logs — this is where all post-authentication activity in Microsoft 365 is recorded. The targets are:
- Persistence mechanisms on both compromised mailboxes (inbox rules)
- Internal lateral movement (emails sent from compromised accounts to other employees)
- Any other post-compromise operations recorded in the audit trail

---

### Question 1 — What keywords does the malicious inbox rule on Laura Chen's account filter for?

**Query:**
```spl
index=ir sourcetype=o365:management:activity
Operation=New-InboxRule UserId="l.chen@nexusfinancial.thm"
| table _time UserId Name SubjectContainsWords DeleteMessage ClientIP
```

**Query Logic:**

This targets the Unified Audit Logs and filters for `New-InboxRule` operations specifically on Laura Chen's account. The `New-InboxRule` operation is logged every time a user or session creates an inbox rule within Microsoft 365. The `SubjectContainsWords` field reveals the keyword filter — these are the email subject keywords the rule is configured to act on.

Malicious inbox rules typically filter for keywords that would appear in security or IT alert emails — terms like "security alert", "password reset", "suspicious", "breach", "verify", or the organization's name. This allows the rule to silently delete or move security notifications before the legitimate user sees them, effectively blinding the victim to the ongoing compromise and any IR notifications sent to their mailbox.

The `ClientIP` field in the returned event will show `223.123.4.50` — confirming this rule was created by the attacker's session, not a legitimate user action.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the value in the SubjectContainsWords field of the returned event]
```

---

### Question 2 — What is the value of the DeleteMessage field in the malicious inbox rule on Laura Chen's account?

**Query:** Same query as Question 1 — `DeleteMessage` is a field in the same returned event.

**Query Logic:**

The `DeleteMessage` field is a boolean-style field that indicates whether the inbox rule is configured to **automatically delete** matched emails rather than just move them to a folder. A value of `True` here means emails matching the `SubjectContainsWords` keywords are permanently deleted from the mailbox as soon as they arrive.

This is the most aggressive form of inbox-based defense evasion. If the rule is set to delete matching emails:
- Laura Chen cannot see IR notifications sent to her account
- Security alert emails are silently destroyed
- Password reset emails from IT may be suppressed if they contain matching keywords
- The attacker buys significantly more time before the legitimate user notices anything unusual

The combination of `SubjectContainsWords` (what to catch) and `DeleteMessage: True` (what to do with it) forms a complete detection suppression mechanism mapped to **T1564.008 — Email Hiding Rules**.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the value in the DeleteMessage field, typically True or False]
```

---

### Question 3 — What is the name of the inbox rule created on the second compromised account?

**Query:**
```spl
index=ir sourcetype=o365:management:activity
Operation=New-InboxRule
| table _time UserId Name SubjectContainsWords DeleteMessage ClientIP
```

**Query Logic:**

This broadens the previous query by removing the `UserId` filter — instead of looking only at Laura Chen's account, it returns all `New-InboxRule` events across the entire tenant. This reveals whether the attacker created persistence mechanisms on the second compromised account as well.

The `Name` field for the malicious rule on the second account reveals the rule name. Attacker-created rules are often given innocuous-looking names designed to blend in with legitimate organizational rules — names like "Newsletters", "Updates", or "Notifications" that a user might not question if they happened to check their inbox rules. The `ClientIP` field will again show `223.123.4.50` for any rules created by the attacker.

This finding also confirms that the second account was not just passively signed into — the attacker took active persistence steps on it, classifying it as a fully compromised account requiring the same scope of containment and eradication as Laura Chen's account.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the Name field value for the rule on the second compromised account]
```

---

### Question 4 — Based on Task 3, what containment action should be taken against these inbox rules?

**Logic:**

From the ATT&CK mapping table in Task 3, inbox rules created by the attacker are mapped to **T1564.008 — Email Hiding Rules**. The corresponding containment response defined in that table is:

**Answer:**
```
Remove the malicious inbox rules immediately
```

---

### Question 5 — How many internal Nexus Financial employees received the internal phishing email?

**Query:**
```spl
index=ir sourcetype=o365:reporting:messagetrace
SenderAddress="l.chen@nexusfinancial.thm"
| table RecipientAddress Subject
```

**Query Logic:**

This pivots to the Message Trace log source and queries for all emails **sent from Laura Chen's account** — not emails received by her. After gaining access to Laura's mailbox at 16:41:30, the attacker used her account to send internal phishing emails to other Nexus Financial employees.

This is a significant escalation of the attack:
- Emails from `l.chen@nexusfinancial.thm` originate from a legitimate internal domain
- Internal email has no external phishing filters applied
- Recipients recognize Laura's name and are far more likely to trust and click
- The attacker can expand their credential harvest from one compromised account to many

The number of rows returned by this query is the number of internal employees targeted in the second wave. Each of these recipients is a potential additional compromise and must be checked against the Entra ID sign-in logs for activity from `223.123.4.50`.

**Answer:**
```
[NOTE: Fill in from your Splunk output — count the number of RecipientAddress rows returned]
```

---

### Question 6 — Based on Task 3, what containment action should be taken against the phishing domain?

**Logic:**

From the ATT&CK mapping table in Task 3, the phishing domain `nexus-verify.thm` used to deliver the initial credential-harvesting email maps to **T1566 — Phishing**. The corresponding containment response is:

**Answer:**
```
Block domain at the email gateway
```

---

## Task 7 — Eradication Findings and Recovery Planning

### Objective

Containment has stopped the attacker from causing further damage. The focus now shifts to two final questions:
1. What data did the attacker access or exfiltrate?
2. What security controls were missing that allowed this incident to happen?

Both must be fully understood before any recovery action is taken. The investigation uses SharePoint activity logs to determine data exposure and Entra ID sign-in logs to identify the missing security controls.

---

### Question 1 — How many files were downloaded from SharePoint across both compromised accounts?

**Query:**
```spl
index=ir sourcetype=o365:management:activity Workload=SharePoint
(Operation=FileDownloaded OR Operation=FileAccessed)
| stats count
```

**Query Logic:**

This query targets Unified Audit Log events where the `Workload` field is `SharePoint` and the `Operation` is either `FileDownloaded` or `FileAccessed`. Both operations indicate the attacker interacted with SharePoint documents — `FileDownloaded` is an explicit download action while `FileAccessed` captures views and reads that may not result in a local file.

The `stats count` function returns the total number of such events across all accounts in the tenant. Since the attacker operated from `223.123.4.50`, filtering by `ClientIP="223.123.4.50"` would narrow this to attacker-only activity. Without that filter, the count reflects all SharePoint file activity in the time window but the attacker's events will dominate given the timeframe.

This number quantifies the data exposure from the SharePoint side of the incident — how many file interactions the attacker performed across both compromised accounts combined.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the count value returned]
```

---

### Question 2 — What is the name of the first file downloaded by the attacker from Laura Chen's account?

**Query:**
```spl
index=ir sourcetype=o365:management:activity Workload=SharePoint
UserId="l.chen@nexusfinancial.thm"
(Operation=FileDownloaded OR Operation=FileAccessed)
| sort 0 _time
| table _time SourceFileName
```

**Query Logic:**

This narrows the SharePoint activity query to Laura Chen's account specifically and sorts results in ascending time order (`sort 0 _time` — the `0` removes Splunk's default result limit). The first row in the output is the earliest SharePoint file the attacker accessed after signing in at 16:41:30.

The `SourceFileName` field contains the actual filename of the accessed document. This is a critical finding for data exposure assessment — the filename often reveals the sensitivity of the accessed data (e.g., files named "Payroll", "Contracts", "Client Data", "Financial Report" immediately signal what type of data was potentially exfiltrated).

This finding maps directly to **T1213 — Data from Information Repositories** in the ATT&CK table from Task 3. The targeted eradication and recovery action is reviewing and restricting SharePoint permissions and revoking external sharing links.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the SourceFileName value of the first row returned]
```

---

### Question 3 — Based on Task 4, what eradication action should be taken against the external sharing links created by the attacker?

**Logic:**

From the eradication checklist defined in Task 4 for a Microsoft 365 identity compromise, the action targeting external SharePoint sharing links created during the compromise is:

**Answer:**
```
Revoking all external sharing links created by the attacker from SharePoint
```

---

### Question 4 — What risk level was assigned to the attacker's sign-ins by Microsoft's risk engine?

**Query:**
```spl
index=ir sourcetype=azure:aad:signin
| stats values(riskLevelDuringSignIn) by userPrincipalName ipAddress
```

**Query Logic:**

This query extracts the `riskLevelDuringSignIn` field from all Entra ID sign-in events and groups them by account and IP address. The `riskLevelDuringSignIn` field reflects Microsoft's **Entra ID Identity Protection** risk engine — an automated system that evaluates each sign-in event against signals like:
- Sign-in from an unfamiliar IP or location
- Impossible travel (sign-in from two geographically distant locations in a short time)
- IP address associated with known malicious infrastructure
- Atypical sign-in patterns for the user

The risk levels are: `none`, `low`, `medium`, `high`. A high risk level should have triggered an automated Conditional Access response — requiring step-up authentication or blocking the sign-in entirely. The fact that the attacker successfully signed in regardless of the assigned risk level reveals a critical gap: **the risk signals were present but no Conditional Access policy was in place to act on them**.

**Answer:**
```
[NOTE: Fill in from your Splunk output — the riskLevelDuringSignIn value returned for the attacker's IP 223.123.4.50]
```

---

### Question 5 — What authentication control was absent that allowed the attacker to sign in without additional verification?

**Logic:**

From the raw sign-in event JSON observed during Room 2, the `conditionalAccessStatus` field showed `notEnabled` and the MFA requirement policy displayed as `notEnabled`. This means Microsoft's risk engine may have flagged the sign-in as suspicious, but **no policy was in place to enforce additional verification** before allowing access.

A single stolen password was all the attacker needed. With MFA enforced, the stolen credentials would have been insufficient — the attacker would also need the second factor (authenticator app, SMS code, FIDO key) that they could not have obtained from a phishing page alone.

**Answer:**
```
MFA
```

---

### Question 6 — According to the recovery timeframes in Task 4, what timeframe should MFA enforcement fall under?

**Logic:**

From the recovery timeframe table in Task 4:
- **Near term**: Immediate actions before accounts can be re-enabled — enforce MFA, reset passwords, remove malicious rules, revoke external shares

MFA enforcement is a prerequisite before any compromised account can be brought back online. It cannot wait for mid-term or long-term planning — without it, re-enabling the account reintroduces the exact same vulnerability that allowed the initial compromise.

**Answer:**
```
Near term
```

---

## Summary and Key Takeaways

### Full Post-Compromise Activity Map

```
[16:41:30]         Attacker signs in to l.chen@nexusfinancial.thm
                   → IP: 223.123.4.50

[Post-16:41:30]    Attacker creates malicious inbox rule on l.chen
                   → SubjectContainsWords: [fill from Splunk]
                   → DeleteMessage: True
                   → Purpose: Suppress security alert emails (T1564.008)

[Post-16:41:30]    Attacker signs in to second compromised account
                   → IP: 223.123.4.50 (same session)

[Post-sign-in]     Attacker creates malicious inbox rule on second account
                   → Rule name: [fill from Splunk]
                   → Same defense evasion objective (T1564.008)

[Post-sign-in]     Attacker sends internal phishing emails from l.chen
                   → To: [X] internal employees
                   → Lateral movement attempt (T1566 — internal phishing)

[Post-sign-in]     Attacker accesses SharePoint via both accounts
                   → [X] total files accessed/downloaded
                   → First file: [fill from Splunk]
                   → Data from Information Repositories (T1213)
```

### Containment Actions Required

| Finding | ATT&CK Technique | Containment Action |
|---|---|---|
| Attacker IP sign-ins on 2 accounts | T1078 — Valid Accounts | Disable both accounts, revoke all sessions, reset passwords |
| Inbox rules on both mailboxes | T1564.008 — Email Hiding Rules | Remove malicious inbox rules immediately |
| Internal phishing emails sent via l.chen | T1566 — Phishing | Block `nexus-verify.thm` at email gateway |
| SharePoint files accessed/downloaded | T1213 — Data from Information Repositories | Review and restrict SharePoint permissions |

### Eradication and Recovery Actions

**Near term (before any account is re-enabled):**
- Enforce MFA on both compromised accounts
- Remove all malicious inbox rules on both mailboxes
- Revoke all external SharePoint sharing links created by the attacker
- Confirm no forwarding rules or delegates were added to either mailbox
- Confirm no OAuth application permissions were granted during the compromise

**Mid term (address root causes):**
- Configure Conditional Access policies to enforce MFA on all sign-ins
- Configure Conditional Access policies to block sign-ins flagged as high risk
- Implement SPF, DKIM, and DMARC on the Nexus Financial domain
- Deploy external phishing protection and email gateway domain blocklisting
- Review and restrict SharePoint external sharing permissions globally

**Long term (security posture improvements):**
- Expand SIEM detection rule coverage (anomalous sign-in, inbox rule creation, bulk file access)
- Run phishing simulation campaigns to train employees
- Update the IR policy with defined escalation timelines and maximum response times
- Implement a mobile device management solution (gap identified in Room 1)

### Root Cause Summary

| Root Cause | Evidence | Fix |
|---|---|---|
| No MFA enforcement | `conditionalAccessStatus: notEnabled` in sign-in logs | Enforce MFA via Conditional Access — Near term |
| No Conditional Access risk-based policy | High-risk sign-in succeeded without challenge | Create Conditional Access policy: block or step-up auth on high-risk sign-ins — Mid term |
| Email gateway allowed phishing domain through | `nexus-verify.thm` delivered successfully | SPF/DKIM/DMARC + phishing domain blocklist — Mid term |
| No internal email scanning | Attacker used l.chen's account to send internal phishing with no detection | Enable internal mail scanning in Microsoft Defender for Office 365 — Mid term |

---

*Writeup by [your GitHub handle] | TryHackMe Incident Response Module | Room 3 of 4*
