# 🔗 Detection Name: Successful Login After Brute Force (Account Compromise)

## 1. Scenario / Objective
After a brute force or password spray attack, attackers often succeed in gaining access to an account.

This detection focuses on identifying a **successful login (Event ID 4624)** that occurs shortly after multiple **failed login attempts (Event ID 4625)**.

👉 This pattern strongly indicates potential **account compromise**.

---

## 2. Attack Emulation (Brute Force → Successful Login)

To simulate a brute force attack followed by account compromise, I executed multiple failed authentication attempts and then performed a successful login using the correct credentials.

* **Technique:** T1110 - Brute Force  

### 🔧 Method Used:
- Performed repeated failed login attempts against a single user account using incorrect passwords
- Followed by a successful login using the correct password

# Brute force (failed attempts)
```powershell

for ($i=0; $i -lt 5; $i++) {
    net use \\localhost\IPC$ /user:testuser WrongPassword123
    Start-Sleep -Seconds 1
}
```
# Successful login
```powershell
net use \\localhost\IPC$ /user:testuser <correct_password>
```

### 🎯 Attack Pattern:
Multiple failed login attempts for the same user
Same source system (local machine)
Followed by a successful authentication
Indicates possible credential compromise

### 📸 Brute Force Followed by Successful Login Execution:
Repeated failed authentication attempts were generated (System error 1326), followed by a successful login (The command completed successfully). This simulates an attacker eventually guessing the correct password.

<img width="657" height="397" alt="image" src="https://github.com/user-attachments/assets/99a0f44e-0702-41d9-a760-ed6b495d6bcf" />


---

## 📊 3. Telemetry & Log Analysis

After executing the attack simulation, authentication-related logs were generated and analyzed in Wazuh.

* **Log Source:** Windows Security Logs  
* **Key Event IDs:**
  - **4625** → Failed Login Attempts  
  - **4624** → Successful Login  

---


<img width="1908" height="427" alt="image" src="https://github.com/user-attachments/assets/08a710cc-c659-4472-b494-c1b0a11a596a" />

This sequence of failed logins followed by a successful authentication strongly indicates a brute force attack leading to account compromise.


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
<id>T1110</id>
  </mitre>
</rule>
```
## 5. Alert Validation, Key Learning & Improvements

The rule successfully triggered when a successful login followed multiple failed attempts.

Alert Level: High (Level 13)
Behavior Detected: Account compromise after brute force

<img width="1901" height="264" alt="image" src="https://github.com/user-attachments/assets/949c42b8-6808-435a-9243-e9c8f637119c" />

## Key Learnings
- Correlation provides high-confidence detection
- Sequence-based detection is more powerful than single-event rules
- Matching user/IP context improves accuracy
## Improvements
- Include IP correlation along with username
- Detect low-and-slow attacks over longer timeframe
- Add geo-location anomaly detection
    
