# 🔗 Detection Name: Possible Lateral Movement (Command Execution + net.exe Correlation)

## 1. Scenario / Objective
Lateral movement is a technique used by attackers to move across systems within a network after gaining initial access.

Attackers commonly abuse built-in Windows tools such as:
- `net.exe`
- PowerShell
- cmd.exe

These tools are used for:
- Enumerating users and shares
- Accessing remote systems
- Executing commands across machines

This detection focuses on identifying suspicious `net.exe` usage combined with command execution activity under the same user context.

---

## 2. Attack Emulation (Atomic Red Team + PowerShell)

To simulate lateral movement behavior, I executed Atomic Red Team tests targeting SMB/Windows Admin Shares.

* **Technique:** T1021.002 - SMB / Windows Admin Shares

### Methods Used:
- Executed Atomic Red Team tests:
  - Mapping admin shares
  - Executing commands remotely
  - Simulating PsExec-like behavior
- Used PowerShell to initiate the tests

### Attack Patterns:
- Execution of `net.exe`
- Command execution via PowerShell / cmd
- Multiple related actions under the same user

<img width="858" height="683" alt="lateral mv exec" src="https://github.com/user-attachments/assets/c06362da-ed60-4720-8c44-59ca59b93dd4" />

Execution of Atomic Red Team tests for SMB/Windows Admin Shares. The test attempts included mapping admin shares and executing commands remotely.

⚠️ Some Atomic tests partially failed due to the absence of a real remote target system in the lab environment. However, the execution still generated sufficient telemetry (process creation and command execution) for detection engineering.

---

## 3. Telemetry & Log Analysis

Analyzed logs using Wazuh + Sysmon:

* **Log Source:** Sysmon  
* **Event ID:** 1 (Process Creation)

### Key Indicators:
- Execution of `net.exe`
- PowerShell or cmd launching commands
- Same `user` across multiple events
- Rapid sequence of related activities

<img width="918" height="444" alt="image" src="https://github.com/user-attachments/assets/815e4576-9508-4489-a6a0-ca044ad6ba48" />
Sysmon process creation log showing execution of `net use` command targeting an administrative share (`\\Target\C$`) using domain administrator credentials. This behavior is commonly associated with lateral movement via SMB.

---

## 4. Detection Logic & Wazuh Rule

```xml
<group name="windows,lateral_movement,custom">

  <rule id="100310" level="12" frequency="3" timeframe="60">

    <!-- Base: net.exe execution -->
    <if_sid>92036</if_sid>

    <!-- Correlate multiple suspicious events -->
    <if_matched_group>sysmon</if_matched_group>

    <!-- Same user correlation -->
    <same_field>win.eventdata.user</same_field>

    <description>
      Possible Lateral Movement (PowerShell/CMD + net.exe, same user)
    </description>

    <mitre>
      <id>T1021</id>
    </mitre>

  </rule>
</group>
```
## 5. Alert Validation, Key Learning & Improvements

The rule successfully triggered when multiple suspicious events involving net.exe and command execution occurred under the same user within a short timeframe.

Alert Level: High (Level 12)
Behavior Detected: Potential lateral movement activity

<img width="1600" height="371" alt="result" src="https://github.com/user-attachments/assets/30e9850f-18e0-452f-9341-6cc874d6c741" />

Custom Wazuh rule triggered after detecting multiple suspicious command executions involving net.exe within a short time window.

## Key Learnings
Lateral movement often uses legitimate system tools
Single events are not sufficient — correlation is critical
User-based correlation helps identify suspicious activity chains
Even partial attack simulations can generate valuable telemetry
## Improvements
Add source IP correlation
Include remote logon detection (Event ID 4624 - Logon Type 3)
Detect service creation (Event ID 7045)
Expand to SMB/WMI/PsExec-based detection patterns
