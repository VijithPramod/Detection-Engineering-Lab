# 💥 Detection Name: Ransomware Behavior (Defense Evasion + Backup/Shadow Deletion)

## 1. Scenario / Objective
Ransomware attacks aim to encrypt user data and disrupt recovery mechanisms.

Before encryption, attackers typically perform **defense evasion** by:
- Deleting shadow copies
- Disabling backups and system restore
- Modifying registry settings

This detection focuses on identifying these pre-encryption behaviors to detect ransomware activity early.

---

## 2. Attack Emulation (Atomic Red Team + PowerShell)

To simulate ransomware behavior, I executed Atomic Red Team tests along with manual PowerShell and command-line activity.

* **Technique:** T1490 - Inhibit System Recovery

### 🔧 Methods Used:
- Executed Atomic Red Team tests:
  ```powershell
  Invoke-AtomicTest T1490 -TestNumbers 1,3,4
  ```
* **Simulated attacker behavior using PowerShell and cmd**
* **Triggered commands related to:**
  - Shadow copy deletion (vssadmin)
  - Backup deletion (wbadmin)
  - Recovery disable (bcdedit, schtasks)
  - System configuration changes
### 🎯 Attack Patterns Observed:
Shadow copy deletion attempts
Backup and recovery removal
Disabling system restore mechanisms
Defense evasion via system configuration changes

<img width="855" height="489" alt="rans1" src="https://github.com/user-attachments/assets/d3ecdccd-09c4-448a-a16a-59a43f4144b3" />


---

## 3. Telemetry & Log Analysis

After executing the ransomware simulation, multiple suspicious commands were observed in the endpoint telemetry, indicating defense evasion and backup destruction activity.

* **Log Source:** Sysmon (Event ID 1 – Process Creation)
* **Key Indicators:**
  - Execution of `vssadmin` for shadow copy deletion
  - Execution of `wbadmin` for backup removal
  - Execution of `bcdedit` to disable recovery mechanisms
  - Multiple suspicious `cmd.exe` executions

---

<img width="949" height="383" alt="rans2 vss" src="https://github.com/user-attachments/assets/14f6642d-a6c0-4efc-a165-dc94c1055090" />

The command `vssadmin delete shadows /all /quiet` was executed, indicating an attempt to delete volume shadow copies and prevent system recovery.

<img width="954" height="389" alt="rans3 wb" src="https://github.com/user-attachments/assets/188a9b89-7e94-48b3-a3ec-90da63f4429a" />

The command `wbadmin delete catalog -quiet` was observed, showing deletion of backup catalog data to disable restoration options.

<img width="933" height="266" alt="rans4 bd" src="https://github.com/user-attachments/assets/48c9b531-0059-4d90-8d88-24ec7bd21b05" />
The command `bcdedit /set {default} bootstatuspolicy ignoreallfailures` suppresses recovery prompts, allowing malicious activity to continue without interruption.

<img width="1906" height="343" alt="ranswazuh logs" src="https://github.com/user-attachments/assets/a2dbab5a-515e-4697-8bc8-eaa4d6782b09" />

Multiple `cmd.exe` executions triggered alerts such as "Suspicious Windows cmd shell execution" and "Command prompt started by abnormal process", supporting the ransomware activity pattern.

---

These telemetry artifacts collectively indicate a coordinated attempt to disable recovery options and prepare the system for ransomware impact.

---

## 4. Detection Logic & Wazuh Rules

### 🔹 Backup / Shadow Copy Deletion

```xml
<rule id="100500" level="13">
  <if_group>sysmon_event1</if_group>
  <match>vssadmin|wbadmin|diskshadow</match>
  <description>
    Possible Ransomware Activity (Backup Deletion / Recovery Disable)
  </description>
  <mitre>
    <id>T1490</id>
  </mitre>
</rule>
```
### 🔹 Defense Evasion (System Restore Disable / Registry)
```xml
<rule id="100600" level="12">
  <if_group>sysmon_event1</if_group>
  <match>schtasks|reg add</match>
  <description>
    Defense Evasion Activity (System Restore / Registry Modification)
  </description>
  <mitre>
    <id>T1490</id>
    <id>T1112</id>
  </mitre>
</rule>
```
### 🔹 Correlation Rule (Multi-stage Ransomware Detection)
```xml
<rule id="100800" level="15" timeframe="300">

  <if_matched_sid>100500</if_matched_sid>
  <if_matched_sid>100600</if_matched_sid>

  <description>
    Confirmed Ransomware Activity (Defense Evasion + Backup/Shadow Deletion)
  </description>

  <mitre>
    <id>T1490</id>
  </mitre>

</rule>
```

### 5. Alert Validation, Key Learning & Improvements

The rules successfully detected ransomware-like behavior during simulation.

**Alert Levels:**
  - Backup deletion → High (13)
  - Defense evasion → High (12)
  - Correlation → Critical (15)

<img width="1600" height="250" alt="ransomeware" src="https://github.com/user-attachments/assets/b3333cc6-0f63-47de-badf-0bf1d6e836d8" /> 
Multiple alerts for backup deletion and recovery disable actions were correlated to generate a critical alert (Level 15). This demonstrates detection of ransomware behavior before encryption by identifying defense evasion techniques such as shadow copy and backup removal.


### Key Learnings
* **Ransomware can be detected before encryption stage**
* **Backup deletion is a strong indicator of malicious intent**
* **Correlation across multiple behaviors gives high-confidence detection**
* **Attackers rely heavily on built-in tools**  
### Improvements
* **Add log clearing detection (Event ID 1102)**
* **Detect disabling of Windows Defender**
* **Include file encryption behavior detection**
* **Extend correlation with lateral movement activity**
