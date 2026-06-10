# TryHackMe — Defender for Cloud: CSPM

**Room:** Defender for Cloud: CSPM  
**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Cloud Security / Microsoft Azure  
**Tags:** `Azure` `Microsoft Defender` `CSPM` `Cloud Security` `Secure Score`

---

## Table of Contents

- [Task 1 — What is Microsoft Defender for Cloud?](#task-1--what-is-microsoft-defender-for-cloud)
- [Task 2 — Main Features of Microsoft Defender for Cloud](#task-2--main-features-of-microsoft-defender-for-cloud)
- [Task 3 — What is CSPM?](#task-3--what-is-cspm)
- [Task 4 — Key CSPM Features](#task-4--key-cspm-features)
- [Task 5 — Secure Score](#task-5--secure-score)
- [Task 6 — Lab Setup](#task-6--lab-setup)
- [Task 7 — Practical Lab Walkthrough](#task-7--practical-lab-walkthrough)
- [Answers Summary](#answers-summary)

---

## Task 1 — What is Microsoft Defender for Cloud?

Microsoft Defender for Cloud is a comprehensive cloud security solution designed to protect cloud and hybrid environments across **Microsoft Azure**, **AWS**, **GCP**, and on-premises datacenters.

It continuously analyzes environments for:
- Misconfigurations
- Outdated software
- Weak access controls

Its core suite includes:

| Tool | Purpose |
|------|---------|
| **CSPM** (Cloud Security Posture Management) | Proactively identifies and recommends actions to strengthen cloud environments |
| **CWP** (Cloud Workload Protection) | Advanced protection for servers, containers, storage, databases |
| **DevSecOps Integration** | Embeds protection at the code level across multicloud/multi-pipeline environments |

> This room focuses specifically on **Defender for Cloud's CSPM capabilities**.

### Answer

> **Let's get started!** ✅

---

## Task 2 — Main Features of Microsoft Defender for Cloud

![Defender for Cloud CSPM Dashboard](images/5efbaebdaaea011c857b438d-1749206379272.png)
*Microsoft Defender for Cloud CSPM dashboard showing resource configuration and security score*

### Feature Overview

**Cloud Security Posture Management (CSPM)**
Identifies and mitigates misconfigurations in cloud resources. Provides a security posture score based on how well resources are configured against best practices.

**Threat Protection**
Uses advanced analytics and machine learning to detect and respond to threats — monitors for suspicious behavior, intrusions, and abnormal activities.

**Vulnerability Assessment**
Scans VMs, containers, and other resources for known vulnerabilities, providing actionable remediation recommendations.

**Compliance Management**

![Compliance Management](images/5efbaebdaaea011c857b438d-1749825915778.png)
*Compliance status against standards like GDPR, PCI DSS, and HIPAA*

Provides compliance insights against standards: **GDPR**, **HIPAA**, **PCI-DSS**, and more.

**Secure Score**

![Secure Score Overview](images/5efbaebdaaea011c857b438d-1749206601893.png)
*Secure Score overview showing overall security posture rating*

A numerical value (0–100%) representing overall security posture. Provides action items to improve the score.

**Multi-Cloud Support**

![Multi-Cloud Support](images/5efbaebdaaea011c857b438d-1749209435770.png)
*Connected Azure, AWS, and Google Cloud environments*

Supports Azure, AWS, and GCP — manage security across your entire cloud ecosystem from one pane.

**Security Alerts and Recommendations**

![Security Alerts](images/5efbaebdaaea011c857b438d-1749210055158.png)
*Security alerts and recommendations panel showing severity levels and remediation steps*

Provides alerts about potential threats and vulnerabilities with actionable, prioritized remediation steps.

### Who Should Use Microsoft Defender for Cloud?

- Enterprises with complex cloud environments needing strong governance
- SMBs looking for affordable cloud security
- Compliance-driven organizations (GDPR, HIPAA, PCI-DSS)
- DevSecOps teams integrating security into CI/CD pipelines

### Answers

> **Q: Which feature helps to identify and mitigate misconfigurations in cloud resources to reduce the risk of vulnerabilities?**
> **A: `Cloud Security Posture Management`**

> **Q: What does Secure Score represent?**
> **A: `Overall security posture`** (a numerical value reflecting how well your environment follows security best practices)

---

## Task 3 — What is CSPM?

**Cloud Security Posture Management (CSPM)** is a category of security tools and practices that continuously monitor and improve the security configuration of cloud environments.

CSPM tools automatically scan cloud infrastructure — virtual networks, storage accounts, databases, identity configurations — against:
- Industry best practices
- Regulatory standards (ISO, NIST, PCI-DSS, GDPR)
- Organization-specific policies

When a misconfiguration is detected (e.g., publicly accessible storage bucket, overly permissive IAM role), CSPM:
1. Alerts security teams
2. Provides recommendations
3. Offers automated remediation options

> **Key distinction:** CSPM is **preventative** — it generates security recommendations to prevent attacks before they occur, rather than responding after the fact.

### Key Benefits of Defender for Cloud CSPM

| Capability | Description |
|-----------|-------------|
| Continuous Posture Monitoring | Evaluates resources against best practices and regulatory standards continuously |
| Security & Compliance Insights | Highlights non-compliant areas; supports GDPR, HIPAA, PCI-DSS reporting |
| Threat Protection & Detection | Integrates Microsoft threat intelligence; detects ransomware, DDoS, APTs |
| Automated Remediation | Automated workflows to fix issues before they escalate |
| Multi-Cloud Management | Single pane of glass for Azure, AWS, and GCP |
| DevSecOps Integration | Security checks embedded in CI/CD pipeline |
| Security Recommendations | Actionable items covering network security, identity management, data protection |
| Advanced Threat Protection | Protection for VMs, containers, databases, storage |
| Microsoft Sentinel Integration | SIEM integration for extended threat detection and response |

### Answers

> **Q: Is Cloud Security Posture Management (CSPM) preventative or reactive?**
> **A: `Preventative`**

> **Q: Which capability of CSPM provides actionable items aimed to improve your cloud security posture?**
> **A: `Security Recommendations`**

---

## Task 4 — Key CSPM Features

This task focuses on three core CSPM features:
1. **Security Posture**
2. **Recommendations**
3. **Attack Path**

### Security Posture

![Security Posture](images/5efbaebdaaea011c857b438d-1749827231221.png)
*Security posture shield illustration*

Cloud security posture refers to the overall security status and configuration of an organization's cloud environment — ensuring infrastructure, applications, and data are protected from cyber threats.

The Defender for Cloud **Overview page** shows a summary tile for security posture, with:
- Critical recommendations
- Attack paths
- Recommendations by risk
- Secure score

![Security Posture Details](images/5efbaebdaaea011c857b438d-1749827988055.png)
*Security posture details broken down by cloud environment (Azure, AWS, GCP)*

### Recommendations

To populate recommendations, environments must first be connected to Defender for Cloud and protection plans enabled. After connection, Defender for Cloud scans environments and starts generating recommendations (may take some time initially).

![Recommendations List](images/5efbaebdaaea011c857b438d-1749828838651.png)
*Recommendations list organized by risk level with affected resources and attack path counts*

Recommendations are organized by **risk levels**, also showing:
- Affected resources
- Risk factors
- Possible attack path counts

On the **recommendation details page**, you'll find:
- Recommendation description
- Risk factors
- How to remediate: **Quick fix** or **manual**
- Tactics (MITRE ATT&CK mapping)
- Recommendation owner

![Recommendation Details](images/5efbaebdaaea011c857b438d-1749832070820.png)
*Recommendation details showing description, risk factors, remediation steps, tactics, and owner*

### Attack Path

![Attack Path](images/5efbaebdaaea011c857b438d-1749833085953.png)
*Attack path analysis visualization*

Defender for Cloud uses a **unique algorithm** to identify potential attack paths. Rather than relying on predefined static paths, it detects paths dynamically based on the specific **multi-cloud security graph**. This analysis highlights the most critical vulnerabilities that could lead to a breach.

The **Graph tab** visually displays attack path details with entity nodes and how they are linked within the path.

### Answers

> **Q: What are the recommendations organized by?**
> **A: `Risk levels`**

> **Q: Which other remediation option is available other than the manual one?**
> **A: `Quick fix`**

---

## Task 5 — Secure Score

Secure Score is a feature that helps organizations measure and improve their cloud security posture, providing a single numerical score (0–100%) based on security recommendations and assessments.

> **Higher score = More secure environment = Lower identified risk level**

### Why Secure Score Is Used

**Measuring Security Posture**
Aggregates all security findings into one simple score for a quick at-a-glance assessment.

**Risk Assessment**
Highlights security gaps and assigns severity values — helps teams prioritize efforts on the highest-impact areas.

**Continuous Monitoring**

![Continuous Monitoring](images/5efbaebdaaea011c857b438d-1750091298739.png)
*Secure score continuously updating as new vulnerabilities and recommendations are detected*

The score is not a one-time measurement — it updates continuously as new vulnerabilities or recommendations are found.

### How Secure Score Helps Security Posture

**Clear Visibility**
Aggregates multiple security assessments into one score for quick team-wide understanding.

**Actionable Recommendations**

![Actionable Recommendations](images/5efbaebdaaea011c857b438d-1750091632357.png)
*Actionable recommendations list alongside the secure score*

Provides a prioritized list of recommendations. Following them systematically improves the score over time.

**Benchmarking**

![Benchmarking](images/5efbaebdaaea011c857b438d-1750091869830.png)
*Secure score benchmarked against the Microsoft Cloud Security Benchmark (MCSB)*

The score is based on the **Microsoft Cloud Security Benchmark (MCSB)**, aligning security practices with globally recognized cloud security standards.

**Progress Tracking**

![Progress Tracking](images/5efbaebdaaea011c857b438d-1750091517896.png)
*Secure score progress tracking view showing improvement over time*

Tracks security improvements over time, demonstrating effectiveness to stakeholders and external auditors.

**Compliance and Reporting**

![Compliance Reporting](images/5efbaebdaaea011c857b438d-1750092454259.png)
*Compliance dashboard showing adherence to ISO 27001, SOC 2, and GDPR*

Higher scores indicate better adherence to frameworks like **ISO 27001**, **SOC 2**, and **GDPR**.

### Answers

> **Q: What does secure score aggregate into one simple score?**
> **A: `Security findings`**

> **Q: What aligns your security practices with best practices for cloud security?**
> **A: `Microsoft Cloud Security Benchmark (MCSB)`**

---

## Task 6 — Lab Setup

Access the lab via the **Cloud Details** button and log in to the Azure portal with the provided credentials.

**Scenario context:**
- You are the **CISO/CIO** of a company
- Responsible for overall cloud security posture awareness
- Decision-maker role — not operational/hands-on
- You will NOT be making changes; you will be reviewing/observing
- Assigned: **Subscription-level Security Reader** role

---

## Task 7 — Practical Lab Walkthrough

### Step 1: Review Onboarded Environments and Enabled Plans

**1.1 — Search for Defender for Cloud**

![Search Defender for Cloud](images/5efbaebdaaea011c857b438d-1750278084340.png)
*Azure portal search bar with "Defender for Cloud" entered*

Navigate to the Azure portal and search for **Defender for Cloud**.

On the Overview page, notice the four summary tiles:
- Security posture
- Regulatory compliance
- Workload protections
- Inventory

**1.2 — View Environment Settings**

To check which environments are onboarded, navigate to:
`Management` → `Environment settings`

![Environment Settings Nav](images/5efbaebdaaea011c857b438d-1750278396860.png)
*Left navigation menu with Environment settings highlighted*

**1.3 — Expand Tenant Root Group**

Expand **Tenant Root Group** → click on the **Az-Subs-DefenderForCloud** subscription.

![Tenant Root Group](images/5efbaebdaaea011c857b438d-1750278854274.png)
*Environment settings showing Tenant Root Group expanded with the subscription listed*

**1.4 — Review Defender Plans**

On the **Defender plans** page, review the enabled plans organized by:
- **CSPM** (Cloud Security Posture Management)
- **CWP** (Cloud Workload Protection)

![Defender Plans](images/5efbaebdaaea011c857b438d-1750279523025.png)
*Plans page showing enabled plans organized by CSPM and CWP categories*

> As CISO, understanding plan coverage is critical — pricing is based on number of instances.

Click **Details** to review the monitoring capabilities provided by each plan.

![CSPM Plan Details](images/5efbaebdaaea011c857b438d-1750280390437.png)
*CSPM plan details showing monitoring capabilities and feature coverage*

---

### Step 2: Review Cloud Security Posture and Recommendations

**2.1 — Navigate to Security Posture**

![Overview Security Posture Tile](images/5efbaebdaaea011c857b438d-1776698333062.png)
*Defender for Cloud Overview page*

On the Overview page, click the **Security posture** tile.

![Security Posture Tile Highlighted](images/5efbaebdaaea011c857b438d-1750341793341.png)
*Security posture summary tile highlighted on the Overview page*

**2.2 — Review Posture Per Environment**

Note that security posture details are displayed **per each onboarded environment**.

![Posture Per Environment](images/5efbaebdaaea011c857b438d-1776698333123.png)
*Posture details broken down by onboarded cloud environment*

> **Important:** The overall Secure Score is a **combined score across all environments**, not per individual environment.

**2.3 — View Recommendations**

Under the Environment section, click **view recommendations**.

![View Recommendations](images/5efbaebdaaea011c857b438d-1776698633688.png)
*Environment section with "view recommendations" link highlighted*

On the **Recommendations page**, you can see all recommendations by:
- Risk level
- Risk factors
- Discovered attack paths

**2.4 — Review a Specific Recommendation**

Navigate to: **"Management ports should be closed on your virtual machines"**

![Recommendation Detail](images/5efbaebdaaea011c857b438d-1776698633717.png)
*Recommendation detail page showing description and remediation options*

Review the description and remediation details. As CISO, you're not expected to act on these directly, but should understand:
- The **Quick fix** option (automated remediation)
- The **Manual** fix option (manual steps provided)

**2.5 — Explore the Attack Path Graph**

Click the **Graph tab** to view the attack path details.

![Attack Path Graph](images/5efbaebdaaea011c857b438d-1750345500610.png)
*Graph tab showing attack path with connected entity nodes illustrating the potential breach route*

> **Note:** As environments get continuously scanned, risk levels, insights, attack paths, and vulnerability details may differ from screenshots. If no attack path appears during your lab, review the provided reference screenshots.

**2.6 — Investigate LinuxVM1 Node**

The attack path description mentions high severity vulnerabilities. Click the **LinuxVM1 node**, then open the **Insights tab**.

![LinuxVM1 Attack Path Node](images/5efbaebdaaea011c857b438d-1750345499880.png)
*Attack path graph with LinuxVM1 node selected and the Insights tab open*

Review the vulnerabilities and their descriptions.

![Vulnerability Insights](images/5efbaebdaaea011c857b438d-1750345777792.png)
*Insights panel listing high severity vulnerabilities on LinuxVM1 with CVE references*

> **Note:** **AI-generated descriptions** are provided for vulnerabilities, including attack vectors and contextual remediation guidance — extremely useful for security analysts working on remediation.

---

### Answers

> **Q: Which CSPM plan is free with Defender for Cloud?**
> **A: `Foundational CSPM`**

> **Q: What type of VM access is recommended as part of the manual fix to lock down inbound traffic to Azure VMs by demand?**
> **A: `Just-in-Time (JIT) VM access`**

---

## Answers Summary

| Task | Question | Answer |
|------|----------|--------|
| Task 1 | Let's get started! | ✅ (No answer required) |
| Task 2 | Which feature helps identify and mitigate misconfigurations? | `Cloud Security Posture Management` |
| Task 2 | What does Secure Score represent? | `Overall security posture` |
| Task 3 | Is CSPM preventative or reactive? | `Preventative` |
| Task 3 | Which capability provides actionable items to improve security posture? | `Security Recommendations` |
| Task 4 | What are the recommendations organized by? | `Risk levels` |
| Task 4 | Which other remediation option is available other than manual? | `Quick fix` |
| Task 5 | What does secure score aggregate into one simple score? | `Security findings` |
| Task 5 | What aligns your security practices with best practices for cloud security? | `Microsoft Cloud Security Benchmark (MCSB)` |
| Task 7 | Which CSPM plan is free with Defender for Cloud? | `Foundational CSPM` |
| Task 7 | What type of VM access is recommended for the manual fix? | `Just-in-Time (JIT) VM access` |

---

## Key Takeaways

- **Microsoft Defender for Cloud** is a multi-cloud security platform covering Azure, AWS, and GCP.
- **CSPM** = preventative security — identifies misconfigurations before attackers can exploit them.
- **Foundational CSPM** is free and automatically enabled; **Defender CSPM** (paid) adds attack path analysis, cloud security explorer, and governance features.
- **Secure Score** is a continuous, aggregated 0–100% metric benchmarked against **MCSB**.
- **Recommendations** are risk-level organized with both **Quick fix** and **manual** remediation options.
- **Attack Path Analysis** uses a dynamic graph algorithm to identify the most critical breach paths.
- **JIT VM Access** limits exposure by only opening management ports on-demand.
- As CISO, the **Security Reader** role provides full visibility without operational change permissions.

---

* TryHackMe | Room: Defender for Cloud: CSPM*
