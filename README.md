# 🔐 Detection Engineering Lab (Beginner Project)

This project demonstrates how I built basic detection rules using Wazuh by simulating real-world attack techniques and analyzing logs. 

The goal of this lab is to understand how attackers behave and how to detect them using endpoint telemetry, logs, and custom correlation rules.

---

## 🎯 Objectives
- Learn how specific attacks generate Windows Event Logs.
- Write custom Wazuh detection logic (XML).
- Perform basic correlation of events to reduce false positives.
- Map attacker techniques using the MITRE ATT&CK framework.

---

## 🛠️ Lab Setup
- **SIEM/XDR:** Wazuh  
- **OS:** Windows (Test Machine)  
- **Tools Used:** PowerShell, Atomic Red Team, Windows Event Logs (Sysmon)  

---

## 🔍 What I Implemented

### 1. Initial Access
- [Brute force detection (multiple failed logins)](./initial-access/brute-force.md)
- [Password spray simulation (multiple users, same password)](./initial-access/password-spray.md)
- [Detection of a successful login immediately following a brute force attempt](./initial-access/success-after-bruteforce.md)

### 2. Execution
- [PowerShell abuse: Encoded command & fileless execution detection](./execution/powershell-abuse.md)

### 3. Defense Evasion & Impact
- [Shadow copy deletion, backup destruction, and simulated ransomware behavior](./defense-evasion/ransomeware-behaviour.md)

### 4. Lateral Movement
- [SMB Lateral Movement detection](./lateral-movement/lateral-movement.md)

---

## 📊 Detection Approach

For every attack simulated in this lab, I followed a strict methodology:
1. **Emulate:** Simulated the attack using PowerShell or Atomic Red Team.
2. **Analyze:** Observed raw logs in Wazuh to identify key indicators (Event IDs, command lines).
3. **Engineer:** Wrote custom XML rules focusing on specific field names.
4. **Validate:** Triggered the alert and tuned it for accuracy.

---

## 📸 Example Detection Flow: Brute Force → Success

* **Step 1:** Attacker generates multiple failed logins **(Event ID 4625)**.
* **Step 2:** Attacker eventually guesses the password and logs in **(Event ID 4624)**.
* **Step 3:** Custom Wazuh correlation rule links the Source IP and Username across both events.
* **Result:** Triggers a High-Severity Alert for "Successful Bypass of Authentication".

---

## 🧠 Key Learnings
- **Logs > Commands:** Detection depends on understanding the underlying logs, not just the command executed.
- **Correlation is King:** Single-event rules are noisy. Correlation rules drastically improve alert accuracy.
- **Failures still leave traces:** Even if an attack (like a password spray) fails, it generates highly useful telemetry.
- **Tuning is required:** Real-world detection requires constant testing and adjustment to filter out normal administrative behavior.

---

## 🚀 Future Improvements
- Improve password spray detection using stricter IP correlation.
- Expand into more persistence techniques (e.g., Registry Run Keys, Scheduled Tasks).
- Refine alert tuning to further reduce false positives.

---

## 📌 Note
This is a beginner-level detection engineering project built primarily for my own learning. The focus is on understanding core SOC concepts, threat modeling, and log analysis rather than deploying production-ready enterprise rules.

---

## 📬 Author
**Vijith Pramod** | Security Operations Analyst
