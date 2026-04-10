# 🔐 Detection Name: Password Spray Attack (Same IP + Multiple Users)

## 1. Scenario / Objective
Password spraying is a technique where an attacker attempts a single password across multiple user accounts to avoid account lockouts.

Unlike brute force (many passwords → one user), password spray is:
👉 One password → many users

This detection focuses on identifying multiple failed login attempts from the same IP address targeting different user accounts within a short timeframe.

---

## ⚔️ 2. Attack Emulation (Password Spray using PowerShell)

To simulate a password spray attack, I manually executed PowerShell commands to attempt authentication across multiple user accounts using the same password.

* **Technique:** T1110.003 - Password Spraying  

### 🔧 Method Used:
- Created multiple user accounts (e.g., user1, user2, user3, user4, user5)
- Used a single common password across all users
- Executed repeated authentication attempts using the `net use` command

```powershell
$users = @("user1","user2","user3","user4","user5")

foreach ($user in $users) {
    net use \\localhost\IPC$ /user:$user WrongPassword123
    Start-Sleep -Seconds 1
}
```
### 🎯 Attack Pattern:
Same source system attempting authentication
Multiple different user accounts targeted
Same password used across all attempts
Rapid sequence of login failures

### 📸 Password Spray Execution:
Multiple authentication attempts were performed against different user accounts using a single password. The repeated failures (System error 1326) indicate invalid credentials and successfully generate logon failure events required for detection.


<img width="688" height="462" alt="image" src="https://github.com/user-attachments/assets/83f7dccc-bd9b-4989-8dc9-682f2d256301" />



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
<img width="1905" height="389" alt="image" src="https://github.com/user-attachments/assets/10d18890-1d5b-40a0-936f-ff41436ee80b" />


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


## Key Learnings
- Password spraying focuses on user diversity, not password diversity
- Correlating by IP address only helps detect horizontal attacks
- Requires tuning to avoid false positives in NAT environments
## Improvements
- Exclude trusted IP ranges (corporate NAT / VPN)
- Increase threshold for large environments
- Combine with successful login detection (4624) for compromise detection
  
