# 🔗 Detection Name: Successful Login After Brute Force (Account Compromise)

## 1. Scenario / Objective
After a brute force or password spray attack, attackers often succeed in gaining access to an account.

This detection focuses on identifying a **successful login (Event ID 4624)** that occurs shortly after multiple **failed login attempts (Event ID 4625)**.

👉 This pattern strongly indicates potential **account compromise**.

---

## 2. Attack Emulation (Atomic Red Team + Manual + PowerShell)

To simulate this attack chain, I performed a multi-step attack:

### 🔧 Steps:
1. Generated multiple failed login attempts (brute force/password spray)
2. Used Atomic Red Team to simulate authentication failures
3. Performed a **successful login manually / via PowerShell** after failures

### 🎯 Attack Pattern:
- Multiple failed logins (4625)
- Followed by a successful login (4624)
- Same user and/or same IP within a short timeframe

📸 **[INSERT PICTURE 1: Screenshot showing failed attempts followed by successful login]**

---

## 3. Telemetry & Log Analysis

Analyzed Windows Security logs in Wazuh:

* **Event ID 4625:** Failed logon  
* **Event ID 4624:** Successful logon  

### 🔍 Key Indicators:
- Same `TargetUserName`
- Same `IpAddress`
- Sequence: failures → success
- Occurring within a short timeframe

This sequence indicates a likely brute force success.

📸 **[INSERT PICTURE 2: Wazuh Discover showing failed + success login sequence]**

---

## 4. Detection Logic & Wazuh Rule

This rule correlates successful login events with previous failed login activity:

```xml
<rule id="100202" level="13" timeframe="600">
  <if_sid>60106</if_sid> <!-- Successful login -->
  <if_matched_sid>100200</if_matched_sid> <!-- Brute force rule -->
  <same_field>win.eventdata.targetUserName</same_field>
  <description>
    Successful Login After Brute Force (Possible Account Compromise)
  </description>
  <mitre>
```
## 5. Alert Validation, Key Learning & Improvements

The rule successfully triggered when a successful login followed multiple failed attempts.

Alert Level: High (Level 13)
Behavior Detected: Account compromise after brute force
<img width="1600" height="750" alt="success" src="https://github.com/user-attachments/assets/d487591a-fd17-4d3a-a134-5a8082dffc50" />


## 6. Key Learnings
Correlation provides high-confidence detection
Sequence-based detection is more powerful than single-event rules
Matching user/IP context improves accuracy
## 7. Improvements
Include IP correlation along with username
Detect low-and-slow attacks over longer timeframe
Add geo-location anomaly detection
    <id>T1110</id>
  </mitre>
</rule>
