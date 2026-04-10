# Detection Name: Suspicious PowerShell Execution (Encoded & Fileless)

## 1. Scenario / Objective
PowerShell is commonly abused by attackers to execute malicious commands while evading detection.

Two major techniques observed:
- **Encoded Commands** → used to obfuscate malicious scripts
- **Fileless Execution** → executing payloads directly in memory without writing files

This detection focuses on identifying both behaviors using command-line analysis and process relationships.

---

## 2. Attack Emulation (Atomic Red Team + PowerShell)

To simulate malicious PowerShell activity, I executed Atomic Red Team tests and manual commands.

* **Technique:** T1059.001 - PowerShell

### Methods Used:
- Executed Atomic Red Team tests for:
  - Encoded command execution
  - Fileless PowerShell execution
- Observed command-line variations such as:
  - Encoded arguments
  - In-memory execution using PowerShell

### Attack Patterns:
- Encoded / obfuscated commands
- PowerShell spawning PowerShell
- Execution using in-memory techniques (fileless)

<img width="859" height="229" alt="encoding execution" src="https://github.com/user-attachments/assets/6df1fefd-cdf1-41c6-a349-031ad96361bb" />

Execution of Atomic Red Team test demonstrating PowerShell encoded command usage (`-EncodedCommand`), simulating obfuscated attacker behavior.

<img width="861" height="299" alt="fileless" src="https://github.com/user-attachments/assets/c3dd8032-6bf6-4e22-a802-3b9c3fdd35a9" />

Execution of fileless PowerShell technique using in-memory commands such as `IEX` and Base64 decoding, without writing payloads to disk.


---

## 3. Telemetry & Log Analysis

Analyzed logs using Wazuh + Sysmon:

* **Log Source:** Sysmon  
* **Event ID:** 1 (Process Creation)

### Key Indicators:
- Presence of encoding indicators:
  - `enc`, `EncodedCommand`
  - `EncodedCommandParamVariation`
- Suspicious command patterns:
  - `IEX` (Invoke-Expression)
  - `FromBase64String`
- PowerShell as parent process spawning another process

<img width="1600" height="767" alt="wazuh encoding logs" src="https://github.com/user-attachments/assets/aabc8062-9655-4aa4-be7b-05b2a112fcea" />

Multiple process creation events captured in Wazuh, showing repeated PowerShell activity and suspicious process patterns. These logs indicate potential misuse of PowerShell during attack simulation.

<img width="956" height="852" alt="encoding result" src="https://github.com/user-attachments/assets/6c238822-9403-4a9b-81f5-c686182553a4" />
Detailed event log showing PowerShell execution with encoded command indicators such as `EncodedCommandParamVariation`. This confirms the presence of obfuscated command-line arguments used during the attack.


---

## 4. Detection Logic & Wazuh Rules

### 🔹 Encoded PowerShell Detection

```xml
<group name="windows,powershell,custom">

  <rule id="100300" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">powershell.exe</field>
    <match>enc|encodedcommand|EncodedCommandParamVariation|Out-ATHPowerShellCommandLineParameter</match>
    <description>
      Suspicious PowerShell Execution (Encoded / Obfuscated Command)
    </description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```
### 🔹 Fileless PowerShell Detection
```xml
<group name="windows,powershell,fileless,custom">

  <rule id="100400" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage">powershell.exe</field>
    <match>iex|FromBase64String|Invoke-Expression</match>
    <description>
      Fileless PowerShell Execution via Registry (Base64 + IEX)
    </description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
      <id>T1112</id>
    </mitre>
  </rule>

</group>
```
## 5. Alert Validation, Key Learning & Improvements

Both rules successfully triggered during Atomic Red Team simulations.

Alert Levels:
Encoded Command → Medium (Level 10)
Fileless Execution → High (Level 13)

<img width="1600" height="426" alt="encoding" src="https://github.com/user-attachments/assets/26f0ae74-5f10-4d2c-ade2-3885db9d7dc8" />

Custom Wazuh rule successfully detected encoded PowerShell execution and generated a medium-severity alert.

<img width="1909" height="356" alt="image" src="https://github.com/user-attachments/assets/f56332b7-d0cb-4748-80ac-a245f0b7f879" />

Custom Wazuh rule successfully detected fileless PowerShell activity and triggered a high-severity alert based on suspicious execution patterns.

## Key Learnings
Encoded commands are commonly used for obfuscation
Fileless execution is harder to detect since it leaves no files on disk
Command-line visibility is critical for PowerShell detection
Parent-child process relationships improve detection accuracy

## Improvements
Add correlation between encoded + fileless execution
Reduce false positives by filtering admin scripts
Include user context (privileged vs normal users)
