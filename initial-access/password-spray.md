# 🔐 Detection Name: Password Spray Attack (Same IP + Multiple Users)

## 1. Scenario / Objective
Password spraying is a technique where an attacker attempts a single password across multiple user accounts to avoid account lockouts.

Unlike brute force (many passwords → one user), password spray is:
👉 One password → many users

This detection focuses on identifying multiple failed login attempts from the same IP address targeting different user accounts within a short timeframe.

---

## 2. Attack Emulation (Atomic Red Team + PowerShell)

To simulate password spraying behavior, I used a combination of Atomic Red Team tests and manual PowerShell-based login attempts.

* **Technique:** T1110 - Brute Force (Password Spraying)

### 🔧 Methods Used:
- Executed Atomic Red Team tests for authentication failures
- Performed manual login attempts across multiple user accounts
- Used PowerShell commands to simulate repeated authentication attempts with the same password across different users

### 🎯 Attack Pattern:
- Same password used
- Multiple usernames targeted
- Same source machine/IP

📸 **[INSERT PICTURE 1: Screenshot showing PowerShell/Atomic execution with multiple login attempts]**

📸 **[INSERT PICTURE 1: Terminal showing multiple login attempts or Atomic execution]**

---

## 3. Telemetry & Log Analysis

After executing the attack, I analyzed Windows Security logs in Wazuh.

* **Log Source:** Windows Security Logs  
* **Event ID:** 4625 (Failed Logon)  

### 🔍 Key Indicators:
- Same `IpAddress`
- Multiple different `TargetUserName`
- Repeated failed attempts
- Occurring within a short timeframe

This pattern indicates a password spray attack originating from a single source.
<img width="1600" height="754" alt="failed 2" src="https://github.com/user-attachments/assets/cd7c8e1e-acdd-4b5d-8a35-7aa3205b553b" />

---

## 4. Detection Logic & Wazuh Rule

Based on the observed telemetry, I created a custom rule:

```xml
  <rule id="100201" level="12" frequency="5" timeframe="60">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>
      Password Spray Attack Detected (Same IP Multiple Users)
    </description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
```
## 5. Alert Validation, Key Learning & Improvements

The rule successfully triggered when multiple failed login attempts occurred from the same IP across different user accounts.

Alert Level: High (Level 12)
Behavior Detected: Password spraying attempt

<img width="1914" height="357" alt="image" src="https://github.com/user-attachments/assets/57e3d424-4a12-4240-b2f9-ee4c504bf95f" />


## 6. Key Learnings
Password spraying focuses on user diversity, not password diversity
Correlating by IP address only helps detect horizontal attacks
Requires tuning to avoid false positives in NAT environments
## 7. Improvements
Exclude trusted IP ranges (corporate NAT / VPN)
Increase threshold for large environments
Combine with successful login detection (4624) for compromise detection
    <id>T1110</id>
  </mitre>
</rule>
