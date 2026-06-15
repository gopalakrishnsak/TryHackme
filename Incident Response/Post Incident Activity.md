# TryHackMe — Post-Incident Activity
## Incident Response Module | Room 4 of 4 | Nexus Financial

> **Platform:** TryHackMe  
> **Room:** [Post-Incident Activity](https://tryhackme.com/room/postincidentactivity)  
> **Difficulty:** Medium  
> **Category:** Incident Response / DFIR / Blue Team  
> **Environment:** Microsoft 365 (Splunk SIEM — `index=ir`)  
> **Framework:** NIST SP 800-61r2  
> **Author:** [gopalakrishnsak](https://github.com/gopalakrishnsak)  
> **TryHackMe:** [gopalakrishnavarma](https://tryhackme.com/p/gopalakrishnavarma) | GRANDMASTER

---

## Table of Contents

1. [Room Overview](#room-overview)
2. [Module Context](#module-context)
3. [Incident Background](#incident-background)
4. [Theoretical Concepts Covered](#theoretical-concepts-covered)
   - [The Lessons Learned Meeting](#the-lessons-learned-meeting)
   - [Executive Summary vs Technical Summary](#executive-summary-vs-technical-summary)
   - [From TTPs to Detection Rules](#from-ttps-to-detection-rules)
   - [Alert Fatigue](#alert-fatigue)
   - [Post-Incident M365 Tools](#post-incident-m365-tools)
5. [Practical Investigation](#practical-investigation)
   - [Lab Environment](#lab-environment)
   - [IOC Tracker](#ioc-tracker)
   - [Splunk Queries & Results](#splunk-queries--results)
6. [Full Attack Timeline (Reconstructed)](#full-attack-timeline-reconstructed)
7. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
8. [Detection Rules Built From This Incident](#detection-rules-built-from-this-incident)
9. [Task Answers](#task-answers)
10. [Key Takeaways](#key-takeaways)

---

## Room Overview

This is the **final room** of the four-part Incident Response module at TryHackMe, based on a simulated security incident at **Nexus Financial**. This room focuses on the **Post-Incident Activity** phase of the NIST SP 800-61r2 IR lifecycle. The attacker has already been contained and eradicated (covered in Room 3). This room is where the team steps back, reflects, documents findings, and converts investigation intelligence into detection capability.

**Learning Objectives:**
- Understand the purpose of the Post-Incident Activity phase
- Learn what a Lessons Learned process involves and why it often gets skipped
- Differentiate between executive and technical summary documents
- Understand how IOCs become detection rules
- Use Splunk to reconstruct the full attack timeline and calculate dwell time
- Build detection rules from confirmed IOCs across the Nexus Financial investigation

---

## Module Context

| Room | Focus |
|------|-------|
| Room 1 — Preparation | Reviewing Nexus Financial's security posture pre-attack |
| Room 2 — Detection & Analysis | Detecting the incident and analyzing it in Splunk |
| Room 3 — Response & Recovery | Containment decisions, attacker eradication, root cause identification |
| **Room 4 — Post-Incident Activity** | **Timeline reconstruction, documentation, detection engineering** |

---

## Incident Background

**Initial Alert:**
```
Alert Name  : Anomalous Sign-in Detected
Time        : 2026-03-30 16:41:30
Account     : l.chen@nexusfinancial.thm
Corporate IP: 197.32.45.112
```

**Escalation Ticket:**
```
Ticket ID   : NXF-INC-2026-0312
Raised by   : Marcus Webb, Security Analyst (L1)
Assigned to : L2 Analyst
Severity    : High
```

A SIEM alert fired on a successful sign-in to Laura Chen's account (Finance Manager) from an IP address **never seen in the environment**, originating from **outside the United Kingdom**. Laura confirmed she did not initiate the sign-in. Investigation confirmed a true positive.

**Confirmed Attack Chain (from Rooms 2 & 3):**
1. Credential-harvesting phishing emails delivered to multiple Nexus Financial employees
2. Laura Chen (l.chen) clicked the link and submitted credentials on a phishing page
3. Attacker signed in from an external IP using harvested credentials
4. Attacker created a malicious inbox rule on l.chen's mailbox to suppress security alerts
5. Attacker accessed and downloaded sensitive SharePoint files via l.chen's session
6. Attacker moved laterally by sending internal phishing from l.chen's compromised mailbox
7. Second account (k.patel) was compromised via internal phishing
8. Attacker accessed HR SharePoint site through k.patel's account and exfiltrated data via external sharing

---

## Theoretical Concepts Covered

### The Lessons Learned Meeting

A **structured discussion** held after the incident is resolved. Brings together the SOC team, stakeholders, IT, and management to review what happened and what can be improved.

**Key questions addressed:**
- What exactly happened and what was the root cause?
- How did the attacker gain initial access?
- When was the incident detected, and what triggered detection?
- Could it have been detected earlier?
- What went well / what didn't?
- What changes (people, process, technology) would prevent recurrence?

> **Why it gets skipped:** After an incident, the team is tired, stakeholders want to move on, and there's always another alert to triage. But skipping this phase means the same vulnerabilities remain open, the same detection gaps persist, and the next attacker using the same technique will succeed just as easily.

**NIST SP 800-61r2** connects Post-Incident Activity back to **Preparation**, making IR a continuous improvement loop rather than a one-time event.

---

### Executive Summary vs Technical Summary

| Attribute | Executive Summary | Technical Summary |
|-----------|-------------------|-------------------|
| **Audience** | Leadership, legal, stakeholders (CIO, CEO, board) | SOC team, security engineers, IT staff |
| **Language** | Plain business language | Technical and precise |
| **IOCs included** | ❌ No | ✅ Yes — all of them |
| **Timeline detail** | High level only | Full with exact timestamps |
| **MITRE ATT&CK** | ❌ No | ✅ Yes, with contextual detail |
| **Purpose** | Inform and reassure leadership | Record findings, improve defenses |

**Executive Summary covers:**
- What happened (in plain language)
- Business impact (data loss, operational disruption, regulatory exposure)
- How it was discovered and resolved (no technical indicators)
- Prevention and remediation steps (plain language)

**Technical Summary covers:**
- Full attack timeline with exact log timestamps
- Complete IOC list (IPs, domains, emails, filenames, account names)
- ATT&CK technique mappings with contextual specifics
- Log evidence — queries, sourcetypes, raw entries
- Root causes and remediation steps taken
- Detection gaps and new rules added

> **Important:** Listing a MITRE technique ID alone (e.g., `T1564.008`) is not useful. The technical summary should include the exact inbox rule name, keywords filtered, action performed, account it was created on, and the precise timestamp. That specificity is what allows detection rules to be written from the report.

---

### From TTPs to Detection Rules

Every TTP identified during the investigation corresponds to a specific attacker behavior captured in the logs. Post-incident, the SOC has a clear picture of exactly what the attacker did and can create targeted detection rules so the next use of the same technique is caught in minutes rather than hours.

**The False Positive Problem:**

Writing good detection rules is hard. Many attacker behaviors resemble normal user activity:
- Creating inbox rules — employees do this legitimately
- Downloading SharePoint files — completely normal
- Signing in from a new location — could be travel

Rules that alert on every instance of these behaviors generate **alert fatigue** — so many alerts that real threats go unnoticed.

**Good detection rules look for:**
- Combinations of events (correlation) rather than single actions
- Context-sensitive anomalies

**Examples of effective correlated rules:**
```
Inbox rule created by account that signed in from a new country in the last hour
Large number of SharePoint file downloads from a single account within a short timeframe
Successful sign-in from an IP never seen in the environment + no MFA challenge
External sharing event on a sensitive file immediately following an anomalous sign-in
```

---

### Alert Fatigue

**Alert fatigue** is the situation where too many alerts are generated, causing analysts to become desensitised and miss real threats. It is one of the most common problems in security operations and is caused by poorly tuned detection rules that do not account for normal user behaviour patterns.

---

### Post-Incident M365 Tools

| Tool | Description |
|------|-------------|
| **Hawk** | Open-source PowerShell tool for gathering forensic data from M365 — mailbox activity, admin actions, sign-in logs |
| **Sparrow** | Checks for IOCs specific to M365 and Azure; developed after high-profile cloud incidents |
| **Microsoft Secure Score** | Measures the organisation's security posture across M365 services; useful for identifying remaining gaps post-incident |

---

## Practical Investigation

### Lab Environment

```
Target IP     : 10.49.190.21
Splunk URL    : https://10-49-190-21.reverse-proxy.cell-prod-ap-south-1b.vm.tryhackme.com
Index         : ir
Time Range    : All Time
```

**Available Log Sources:**

| Log Source | Sourcetype | Key Fields |
|------------|------------|------------|
| Entra ID Sign-in Logs | `azure:aad:signin` | `userPrincipalName`, `ipAddress`, `location.city`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode` |
| Message Trace | `o365:reporting:messagetrace` | `Received`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP` |
| Unified Audit Logs | `o365:management:activity` | `Operation`, `UserId`, `Workload`, `ClientIP`, `ObjectId`, `SourceFileName`, `Name`, `SubjectContainsWords`, `DeleteMessage` |

---

### IOC Tracker

| Type | Value |
|------|-------|
| Attacker IP Address | *(Confirmed in Room 2 — Entra ID sign-in logs)* |
| Phishing Sender Address | *(Confirmed in Room 2 — Message Trace)* |
| Compromised Account 1 | `l.chen@nexusfinancial.thm` |
| Compromised Account 2 | `k.patel@nexusfinancial.thm` |
| Malicious Inbox Rule | *(Confirmed in Room 2 — Unified Audit Logs, `New-InboxRule` operation)* |
| SharePoint Files Exfiltrated | `Board_Meeting_Notes_July.docx`, `Employee_Salary_Data.xlsx`, `Q3_Financial_Report.xlsx`, `Full_Employee_PII_Data.xlsx`, `Payroll_Q3_2024.xlsx` |
| External Email (Exfil target) | *(Confirmed in Room 3 — `SharingInvitationCreated`)* |

---

### Splunk Queries & Results

#### Q1 — Internal Phishing Recipients (How many employees were put at risk?)

```splunk
index=ir sourcetype="o365:reporting:messagetrace"
SenderAddress="l.chen@nexusfinancial.thm"
RecipientAddress="*@nexusfinancial.thm"
| stats count by RecipientAddress
```

**Result: 3 internal recipients**

| RecipientAddress |
|-----------------|
| allan.senna@nexusfinancial.thm |
| k.patel@nexusfinancial.thm |
| m.harris@nexusfinancial.thm |

*The attacker used l.chen's compromised account to send lateral phishing to three other Nexus Financial employees. k.patel subsequently clicked and became Compromised Account 2.*

---

#### Q2 — SharePoint Files Downloaded (Which file contains employee PII?)

```splunk
index=ir sourcetype="o365:management:activity" Operation="FileDownloaded"
| table _time, UserId, SourceFileName, ObjectId
```

**Result: 5 files downloaded across two compromised accounts**

| Timestamp | UserId | SourceFileName | SharePoint Path |
|-----------|--------|----------------|-----------------|
| 2026-03-30 16:55:24 | l.chen@nexusfinancial.thm | Board_Meeting_Notes_July.docx | /Finance-department/Shared Documents/ |
| 2026-03-30 16:55:33 | l.chen@nexusfinancial.thm | Employee_Salary_Data.xlsx | /Finance-department/Shared Documents/ |
| 2026-03-30 16:55:37 | l.chen@nexusfinancial.thm | Q3_Financial_Report.xlsx | /Finance-department/Shared Documents/ |
| 2026-03-30 17:03:38 | k.patel@nexusfinancial.thm | **Full_Employee_PII_Data.xlsx** | /HR-department/Shared Documents/ |
| 2026-03-30 17:03:45 | k.patel@nexusfinancial.thm | Payroll_Q3_2024.xlsx | /HR-department/Shared Documents/ |

**PII File: `Full_Employee_PII_Data.xlsx`** — downloaded by k.patel (Compromised Account 2) from the HR department SharePoint at 17:03:38.

---

#### Q3 — Inbox Rule Detection (What operation to monitor?)

```splunk
index=ir sourcetype="o365:management:activity" Operation="New-InboxRule"
UserId="l.chen@nexusfinancial.thm"
| table _time, ClientIP, UserId, Name, SubjectContainsWords, DeleteMessage
```

Relevant `Operation` field value: **`New-InboxRule`**

---

#### Q4 — Entra ID Field for Unusual Country Detection

Field: **`location.countryOrRegion`**

```splunk
index=ir sourcetype="azure:aad:signin"
userPrincipalName="l.chen@nexusfinancial.thm"
| where ipAddress != "197.32.45.112"
| table _time, ipAddress, location.city, location.countryOrRegion
```

---

## Full Attack Timeline (Reconstructed)

```
2026-03-30 (Pre 16:41)  INITIAL ACCESS
  └─ Phishing email with credential-harvesting link delivered to l.chen@nexusfinancial.thm
  └─ l.chen clicks link → submits credentials on phishing page
  └─ Attacker captures l.chen's username and password

2026-03-30 16:41:30     ALERT TRIGGERED
  └─ SIEM fires "Anomalous Sign-in Detected" on l.chen's account
  └─ Source: Entra ID Sign-in Logs (azure:aad:signin)
  └─ Sign-in from external IP (non-UK) — never seen in environment

2026-03-30 (Post 16:41) DEFENSE EVASION
  └─ Attacker creates malicious inbox rule on l.chen's mailbox
  └─ Rule configured to suppress/delete incoming security alert emails
  └─ Operation: New-InboxRule | Source: Unified Audit Logs

2026-03-30 16:55:24–37  COLLECTION — ACCOUNT 1 (l.chen)
  └─ Attacker downloads 3 files from Finance SharePoint:
      ├─ Board_Meeting_Notes_July.docx
      ├─ Employee_Salary_Data.xlsx
      └─ Q3_Financial_Report.xlsx

2026-03-30 (Mid-session) LATERAL MOVEMENT
  └─ Attacker sends internal phishing email from l.chen to 3 employees:
      ├─ allan.senna@nexusfinancial.thm
      ├─ k.patel@nexusfinancial.thm
      └─ m.harris@nexusfinancial.thm
  └─ k.patel clicks link → submits credentials → Account 2 compromised

2026-03-30 17:03:38–45  COLLECTION — ACCOUNT 2 (k.patel)
  └─ Attacker downloads 2 files from HR SharePoint:
      ├─ Full_Employee_PII_Data.xlsx  ← contains employee PII
      └─ Payroll_Q3_2024.xlsx

2026-03-30 (Post 17:03) EXFILTRATION
  └─ Attacker uses SharingInvitationCreated to share files externally
  └─ Data sent to attacker-controlled external email address
  └─ Source: Unified Audit Logs (o365:management:activity)
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Nexus Financial Specifics |
|--------|-----------|-----|--------------------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Credential-harvesting email sent to l.chen; contained a malicious link to a phishing page mimicking a legitimate login portal |
| Credential Access | Steal Web Session Cookie / Credentials from Web Browser | T1539 / T1555 | l.chen submitted credentials directly on phishing page; attacker used harvested plaintext credentials |
| Defense Evasion | Email Hiding Rules | T1564.008 | Malicious inbox rule created on l.chen's mailbox via `New-InboxRule`; rule configured to delete incoming emails matching security alert keywords |
| Collection | Data from Cloud Storage | T1530 | Attacker downloaded sensitive files from SharePoint: Finance and HR department document libraries |
| Lateral Movement | Internal Spearphishing | T1534 | Attacker sent phishing email from l.chen's compromised account to three internal employees; k.patel subsequently compromised |
| Exfiltration | Exfiltration to Cloud Storage / Transfer Data to Cloud Account | T1567 | Attacker used `SharingInvitationCreated` in SharePoint to share HR files with an external email address |

---

## Detection Rules Built From This Incident

### Rule 1 — Anomalous Sign-in From New Country

```splunk
index=ir sourcetype="azure:aad:signin"
| where location.countryOrRegion != "United Kingdom"
| where status.errorCode = 0
| stats count by userPrincipalName, ipAddress, location.countryOrRegion
| where count >= 1
```

**Rationale:** All Nexus Financial employees work from a London office. Any successful authentication from outside the UK with a previously unseen IP should be investigated immediately.

**Improvement:** Correlate with MFA bypass events (no MFA challenge registered) to reduce false positives for traveling employees.

---

### Rule 2 — Malicious Inbox Rule Creation Following Anomalous Sign-in

```splunk
index=ir sourcetype="o365:management:activity" Operation="New-InboxRule"
| join UserId [
    search index=ir sourcetype="azure:aad:signin"
    | where location.countryOrRegion != "United Kingdom"
    | rename userPrincipalName as UserId
]
| table _time, UserId, ClientIP, Name, SubjectContainsWords, DeleteMessage
```

**Rationale:** Attackers commonly suppress security alert emails immediately after gaining access. An inbox rule created shortly after an anomalous sign-in is a high-confidence indicator of compromise. Standalone inbox rule creation is too noisy; the correlation with the anomalous sign-in drastically reduces false positives.

---

### Rule 3 — Bulk SharePoint File Download

```splunk
index=ir sourcetype="o365:management:activity" Operation="FileDownloaded"
| bin _time span=10m
| stats count by _time, UserId
| where count >= 3
```

**Rationale:** Downloading multiple sensitive files within a short timeframe is unusual for typical user behavior at Nexus Financial. Three or more downloads within a 10-minute window should trigger investigation. Threshold should be tuned based on baseline behavior.

---

### Rule 4 — External SharePoint Sharing Following Anomalous Activity

```splunk
index=ir sourcetype="o365:management:activity" Operation="SharingInvitationCreated"
| where match(ObjectId, "HR-department|Finance-department")
| table _time, UserId, ObjectId, ClientIP
```

**Rationale:** Sharing of files from sensitive document libraries (Finance, HR) to external email addresses is a high-risk action. Combined with prior anomalous sign-in activity, this pattern indicates active exfiltration.

---

### Rule 5 — Internal Phishing From Compromised Account

```splunk
index=ir sourcetype="o365:reporting:messagetrace"
| where SenderAddress like "%@nexusfinancial.thm"
| where FromIP != "197.32.45.112"
| stats values(RecipientAddress) as Recipients count by SenderAddress, FromIP
```

**Rationale:** Legitimate internal emails originate from the corporate mail relay (197.32.45.112). Internal emails sent from an external IP indicate the account is compromised and is being used for lateral phishing.

---

## Task Answers

| # | Question | Answer |
|---|----------|--------|
| T1-Q1 | Name of the structured discussion held post-incident | `Lessons Learned Meeting` |
| T1-Q2 | Phase that Post-Incident Activity feeds back into (NIST SP 800-61r2) | `Preparation` |
| T2-Q1 | Report type written for non-technical audience | `Executive Summary` |
| T2-Q2 | Report type containing IOCs, MITRE IDs, and exact timestamps | `Technical Summary` |
| T3-Q1 | Term for too many alerts causing analysts to miss real threats | `Alert Fatigue` |
| T3-Q2 | Microsoft tool that measures M365 security posture | `Microsoft Secure Score` |
| T6-Q1 | Initial attack vector used to compromise Laura Chen | `Phishing` |
| T6-Q2 | Security control that would have prevented access post-credential theft (abbreviation) | `MFA` |
| T6-Q3 | Number of employees put at risk by internal phishing email | `3` |
| T6-Q4 | First log source that identified suspicious activity | `Entra ID Sign-in Logs` |
| T6-Q5 | File containing employee PII downloaded by attacker | `Full_Employee_PII_Data.xlsx` |
| T6-Q6 | Operation relevant for detecting suspicious inbox rule creation | `New-InboxRule` |
| T6-Q7 | Entra ID field for detecting auth from unusual countries | `location.countryOrRegion` |

---

## Key Takeaways

1. **Post-Incident Activity is not optional.** Skipping it leaves the same vulnerabilities open and ensures the next attacker using the same technique will succeed just as easily.

2. **The Lessons Learned meeting closes the IR loop.** Outputs feed directly back into the Preparation phase: new detection rules, updated policies, additional training, and improved tooling.

3. **MFA would have stopped this entire attack.** The attacker harvested valid credentials through phishing but had no MFA token to bypass. This is the single highest-impact control gap in this incident.

4. **Detection is built incrementally.** No organisation has perfect coverage before an incident. Every investigation teaches the security team something new about attacker behavior and provides an opportunity to close detection gaps.

5. **Alert fatigue kills SOCs.** A detection rule that fires on every inbox rule creation is useless. Good rules look for anomalies, combinations of events, and context — not individual actions in isolation.

6. **The IOC Tracker is the foundation of the technical summary.** Every entry in the tracker captures a specific attacker action with enough detail (timestamp, account, operation, indicator) to write both a detection rule and an ATT&CK technique entry from it.

7. **Lateral movement through internal phishing is hard to detect without context.** The email looked like it came from a trusted internal sender. Only by correlating the sending IP with the known corporate relay IP (`197.32.45.112`) was it possible to flag this activity as malicious.

---

## References

- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1564.008 — Hide Artifacts: Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)
- [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [T1534 — Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)
- [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [TryHackMe — Incident Response Module](https://tryhackme.com/module/incident-response)

---

*Writeup by [gopalakrishnsak](https://github.com/gopalakrishnsak) | TryHackMe GRANDMASTER*
