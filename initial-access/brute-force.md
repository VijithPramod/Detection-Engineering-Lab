# 🔐 Detection Name: Brute Force Attack (Same User + Same IP)

## 1. Scenario / Objective
Brute force attacks involve repeated login attempts using different passwords against a single user account. 
Attackers use this technique to gain unauthorized access by guessing credentials.

This detection focuses on identifying multiple failed login attempts from the same IP address targeting the same user within a short time window.

---

## 2. Attack Emulation (Atomic Red Team)

To simulate brute force behavior, I executed an Atomic Red Team test:

* **Technique:** T1110 - Brute Force
* **Test Used:** Multiple failed login attempts

Additionally, manual failed login attempts were generated to ensure proper telemetry collection.

<img width="859" height="733" alt="atom" src="https://github.com/user-attachments/assets/665b60ae-1386-428f-b917-ebc7ae506c21" />

---

## 3. Telemetry & Log Analysis

After executing the attack, I analyzed Windows Security logs in Wazuh.

* **Log Source:** Windows Security Logs  
* **Event ID:** 4625 (Failed Logon)  
* **Key Indicators:**
  - Repeated failed login attempts
  - Same `TargetUserName`
  - Same `IpAddress`
  - Occurring within a short timeframe

These events indicate a potential brute force attempt against a specific account.

<img width="1600" height="754" alt="failed" src="https://github.com/user-attachments/assets/3de36124-8f0e-4fc2-b7e2-34f71b2612af" />

---

## 4. Detection Logic & Wazuh Rule

Based on the observed telemetry, I created a custom Wazuh rule to detect brute force activity:

```xml
  <rule id="100200" level="12" frequency="5" timeframe="60">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>
      Brute Force Attack Detected (Same User + Same IP)
    </description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
```
##  5. Alert Validation, Key Learning & Improvements

The rule successfully triggered when multiple failed login attempts occurred for the same user from the same IP.

* **Alert Level:** High (Level 12)
* **Behavior Detected:** Repeated authentication failures indicating a brute force attempt

<img width="1600" height="745" alt="unnamed" src="https://github.com/user-attachments/assets/a507ed73-bb25-4228-8848-95199b07fd68" />


### 6. Key Learnings
- Brute force detection requires **event correlation**, not single logs
- Matching **user + IP context** significantly reduces false positives
- Threshold tuning (frequency/timeframe) is critical for accuracy

### 7. Improvements
- Detect **low-and-slow brute force attacks**
- Correlate with **successful login (4624)** for compromise detection
- Include **account lockout (4740)** for stronger signals
