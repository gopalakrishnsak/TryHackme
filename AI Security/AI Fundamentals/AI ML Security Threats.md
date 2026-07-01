
# AI/ML Security Threats

**Room:** [AI/ML Security Threats](https://tryhackme.com/room/aimlsecuritythreats)

**Category:** AI Fundamentals / AI Security

## Intro

I went into this room expecting a dry "here's what AI is" lecture, but it turned out to be a genuinely solid primer — the kind of room I'd point a junior analyst to if they wanted to understand *why* everyone in security suddenly won't shut up about AI. It walks through the basics of AI/ML/DL, how LLMs actually work under the hood, how attackers are already abusing this stuff, and — my favorite part — how defenders can turn the same technology back around and use it offensively (in the good way). There's also a hands-on practical at the end where you get your own AI assistant to play with, which is a nice way to close things out instead of just reading task after task.

Here's my walkthrough, task by task.

---

## Task 1 — Introduction

No questions here, just context-setting. The room's goal is laid out clearly:

- What is AI/ML?
- How is it used in the industry?
- How does it affect our roles as security folks?
- How are attackers leveraging it?

Nothing to answer, just click through.

---

## Task 2 — AI & ML Fundamentals

This task lays the groundwork, and it's worth actually reading rather than skimming, because the terminology comes back constantly later in the room.

**Artificial Intelligence (AI)** is the umbrella term — any system that performs tasks normally requiring human reasoning, comprehension, or creativity. It's been around conceptually since the 1950s.

**Machine Learning (ML)** is a subfield of AI where a system learns patterns from data instead of being explicitly programmed. The room breaks down the ML lifecycle nicely:

1. Define the problem (e.g. "is this email spam?")
2. Collect and clean the data
3. Feature engineering (extract meaningful patterns, avoid overfitting)
4. Train the model
5. Evaluate and tune
6. Deploy
7. Monitor and retrain over time

ML algorithms themselves have three moving parts: a **decision process** (makes the prediction), an **error function** (grades how wrong it was), and a **model optimisation process** (adjusts things to reduce that error). Rinse and repeat until performance is good enough.

There are four categories of ML:

- **Supervised learning** — trained on labelled data (e.g. spam/not spam)
- **Unsupervised learning** — works on unlabelled data, finds hidden structure (clustering, etc.)
- **Semi-supervised learning** — a mix of both; a small labelled subset guides learning on a much larger unlabelled dataset
- **Reinforcement learning** — learns via rewards/penalties, like training a dog with treats, except the dog is a neural net

Then it moves into **neural networks**, which are modeled loosely on how neurons and synapses work in the brain. You've got an **input layer** (raw data goes in here), **hidden layers** (where the actual pattern extraction happens — early layers pick up simple features like edges, deeper layers combine those into more complex concepts), and an **output layer** (the final prediction). The connections between nodes are **weighted**, and those weights are the neural network's version of synapse strength — how much influence one node has over the next.

Once a network has more than three layers, congratulations, you've got **Deep Learning (DL)**. The key advantage of DL over standard ML is that it doesn't need labelled data — it can chew through raw, unstructured input and figure out the relevant features itself. That's also why DL only really took off in the last decade or so: it needed the explosion of digitised data (and the compute to process it) that we didn't really have before.

### Answers

| Question | Answer |
|---|---|
| What category of machine learning combines both labelled and unlabelled data? | **Semi-supervised learning** |
| What is the first layer in a neural network that handles incoming raw data? | **Input layer** |
| Which learning method does not require human-labeled data and can extract features from raw, unstructured input? | **Deep Learning (DL)** |
| What are the weighted connections between nodes in a neural network meant to simulate in the human brain? | **Synapses** |

---

## Task 3 — LLMs

This is where things get more current and interesting — how do tools like ChatGPT, LLaMA, and DeepSeek actually work?

**LLMs (Large Language Models)** are deep-learning models that generate text by predicting the next word in a sequence, one token at a time. Feed it "Ever have that feeling where you're not sure if you're awake or ___" and it's going to spit out probabilities for the next word based on everything it learned during training (spoiler: the room's example lands on "egg," which is a fun, weirdly specific choice).

The training process breaks down like this:

1. **Pretraining** — the model chews through absolutely massive amounts of text data (GPT-3's training set alone would take a human roughly 2,600 years to read). It's during this phase the model builds up its general sense of language, grammar, and world knowledge.
2. **Backpropagation** — the model's guesses get compared against the actual correct next word, and its internal parameters get nudged to make it more likely to guess right next time. Do this trillions of times and you start getting something coherent.
3. **RLHF (Reinforcement Learning from Human Feedback)** — humans step back in and review the model's outputs, flagging bad or unhelpful ones so the model can be fine-tuned further.

None of this would be feasible without two hardware/architecture breakthroughs:

- **GPUs**, which allow the kind of massive parallel processing this all needs
- **Transformer neural networks**, introduced in Google's 2017 paper *Attention Is All You Need*. Transformers were the real unlock because they allowed parallel text processing instead of the old sequential, word-by-word approach, and introduced the concept of "attention" — letting the model weigh which words in a sentence matter most for understanding context (e.g. figuring out whether "it" refers to "the bank" or "the loan" in an ambiguous sentence).

### Answers

| Question | Answer |
|---|---|
| What type of AI model enabled major advancements in ChatGPT and similar tools? | **Transformer** |
| What is the first training stage where an LLM processes massive amounts of data? | **Pretraining** |
| What type of neural network introduced by Google in 2017 powers modern LLMs? | **Transformer** |

---

## Task 4 — AI/ML Security Threats

This is the meat of the room from a security perspective, and it's split into two buckets: **vulnerabilities baked into the models themselves**, and **existing attacks that AI has supercharged**.

MITRE (yes, the same people behind ATT&CK) has built a parallel framework specifically for AI threats called **ATLAS**, which is worth bookmarking if you're going to be doing any actual AI security work.

### Model Vulnerabilities

- **Prompt Injection** — overriding a model's original system instructions to make it do something it wasn't supposed to (leak internal info, generate content it should refuse, etc.)
- **Data Poisoning** — tampering with the training data so the model learns the wrong thing. Classic example: poisoning a spam filter's training data so it stops correctly flagging spam, letting an attacker's emails sail through.
- **Model Theft** — repeatedly querying a model's API, collecting the outputs, and using them to train a clone model that mimics the original's behavior. Basically stealing the IP without ever touching the actual weights.
- **Privacy Leakage** — a model trained on sensitive data (think patient records) inadvertently spits that data back out to a user who shouldn't have access to it.
- **Model Drift** — a model's real-world accuracy degrading over time as the surrounding data/environment shifts, which is why ongoing monitoring and periodic retraining matters.

### Enhanced Existing Attacks

- **Malware generation** — generative AI means attackers can produce working malicious code almost instantly, no deep coding skill required.
- **Deepfakes** — voice and video can now be convincingly faked given enough training data on the target. The room's example is a good one: a "video call" from your boss asking you to forward confidential customer data — except it's not your boss.
- **Phishing** — historically, broken English and awkward phrasing were red flags people were trained to spot. Generative AI erases that tell almost entirely, letting attackers churn out fluent, context-aware phishing emails regardless of their own writing ability. Models like GPT have guardrails against generating this kind of content directly, but those guardrails can sometimes be bypassed via — you guessed it — prompt injection.

### Answers

| Question | Answer |
|---|---|
| What framework was developed by MITRE to guide the understanding of AI-specific cyber threats? | **MITRE ATLAS** |
| What type of attack involves cloning an AI model by interacting with its API? | **Model Theft** |
| What generative AI technique can replicate a person's voice or appearance with high realism? | **Deepfakes** |
| What common social engineering attack has become harder to detect due to AI-generated fluent and convincing messages? | **Phishing** |

---

## Task 5 — Defensive AI

After a whole task about how scary AI can be in the wrong hands, this one flips the script: AI is just as much a defensive tool as it is an offensive one, and honestly, that's the more important half of the story.

The stats cited from **IBM's Cost of a Data Breach Report** back this up hard:

- Organizations that adopted AI in their security stack saved an average of **$2.2 million** per breach
- The average cost of a breach without it: **$4.88 million**
- AI-adopting orgs identified and contained breaches **108 days faster**

That's a massive gap, and it comes down to AI being genuinely good at four things:

1. **Analysis** — chewing through huge volumes of data (like network traffic) to spot anomalies far faster than a human analyst could manually.
2. **Prediction & automation** — the same way attackers use AI to write better phishing emails, defenders can train models to recognize and auto-block those emails before they hit an inbox.
3. **Summarisation** — turning long incident reports or documents into digestible summaries, saving analysts hours of reading time.
4. **Investigation** — feeding logs into a chatbot and asking it to explain what's going on in plain English, or having it brainstorm threat hunting scenarios an analyst might not have thought of on their own (human imagination has limits; a model trained on a huge dataset of attack patterns doesn't have the same blind spots).

But — and this is the important caveat — adopting AI securely matters just as much as adopting it at all. The IBM report also found that **only 24% of generative AI initiatives are actually secured**. If you bolt AI onto your stack without securing it, you're just adding a new attack surface on top of whatever benefit you gained. The room lists a few concrete ways to do this properly:

- **Access control** — RBAC (Role-Based Access Control) and MFA to restrict who can actually interact with the model
- **Privacy protection** — treat training data like any other sensitive data; encrypt it
- **Security standards** — implement recognized frameworks (e.g. ISO/IEC 27090) throughout the model's lifecycle
- **Model monitoring** — not just for performance drift, but for unexpected behavior, bias, or anomalies that might indicate an attack, using explainability tools like **SHAP** and **LIME**

### Answers

| Question | Answer |
|---|---|
| According to IBM, how many days faster does AI help identify and contain breaches? | **108 days** |
| What cybersecurity task benefits from AI helping to imagine attacker behavior we might not consider? | **Threat hunting** |
| Explainability tools such as SHAP and LIME help with what? | **Model monitoring** (spotting unexpected behavior, bias, or anomalies) |

---

## Task 6 — Practical: Your Cyber Assistant

This is the fun part. You're handed your own AI assistant chatbot and walked through a handful of realistic defensive use cases before finishing off with a flag hunt.

### Log Analysis

Prompt:
> Here's a logline: `Apr 22 11:45:09 ubuntu sshd[1245]: Failed password for invalid user admin from 203.0.113.55 port 56231 ssh2` — can you explain what's happening?

The assistant correctly broke it down: an SSH login attempt against a non-existent/invalid user `admin`, originating from `203.0.113.55`, that failed — a pretty textbook indicator of a brute-force or unauthorized access attempt.

### Phishing Detection

Fed it a fake "Microsoft 365 account verification" email with a spoofed sender domain (`m1crosoft365-security.com` — note the "1" instead of "i") and a suspicious link. The assistant flagged it correctly as phishing, pointing out both the fake domain and the urgency-based pressure tactic ("verify within 12 hours or lose access") — classic red flags.

### Threat Hunting Brainstorm

Asked it for three realistic threat hunting scenarios. It came back with:

1. Unusual outbound connections to known malicious IPs (possible C2 traffic / data exfiltration)
2. Suspicious login behavior or privilege escalation (insider threat / compromised account)
3. Lateral movement — failed logins followed by successful ones on new hosts, or unexpected use of PowerShell/PsExec/RDP

All solid, realistic starting points for an actual hunt.

### Regex Generation

Asked it to write a regex for catching failed SSH logins in a Linux auth log. It produced:

```regex
Failed password for (invalid user \w+|[^\s]+) from (\d{1,3}\.){3}\d{1,3} port \d+ ssh2
```

Clean, functional, and it even explained each component without being asked to.

### The Flag

The final challenge is a nice little demonstration of using an LLM for quick fact lookups instead of manually searching three separate things. The prompt:

> What are these values: DNS over HTTPS (DoH) Port, SYN flood timeout, and Windows ephemeral port range size?

The assistant returned:

- **DoH Port:** `443` (DoH rides over standard HTTPS)
- **SYN Flood Timeout:** `60` (a commonly cited default for half-open TCP connection timeouts)
- **Windows Ephemeral Port Range Size:** `16384` (ports 49152–65535 inclusive → that's 16,384 usable ports)

Slot those into the flag format given in the task:

```
thm{443/60/16384}
```

And that's the room complete.

---

## Final Thoughts

What I liked about this room is that it doesn't just do the usual "AI bad, here's why" doom-and-gloom thing. It's balanced — it spends real time on how the underlying tech actually works (which most "AI security" content skips straight past), gives a clear-eyed rundown of how it's being weaponized, and then just as much space to how defenders can flip it around. The IBM stats alone ($2.2M saved, 108 days faster containment) make a pretty compelling case that ignoring this space isn't really an option anymore, whichever side of the fence you're defending.

If you're brand new to AI/ML concepts and want the "why should I care" context before diving into more technical AI security rooms (prompt injection labs, adversarial ML, etc.), this is a good, low-friction place to start.

---

